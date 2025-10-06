use modql::filter::{FilterGroups, ListOptions};
use sea_query::{
    Alias, Asterisk, CommonTableExpression, Condition, Expr, Func, Iden, JoinType,
    PostgresQueryBuilder, Query, SelectStatement, SimpleExpr, Value,
};
use sea_query_binder::SqlxBinder;
use serde_json::json;
use sqlx::{postgres::PgRow, FromRow};

use crate::store::{
    ctx::StoreCtx,
    dbx::Dbx,
    error::{Result, StoreError},
    queries::{
        count::{count, count_many},
        meta::{CountManyQueryMeta, GetJoinedQueryMeta, ListJoinedMeta, ReadQueryMeta},
    },
    traits::{
        join::JoinOneToManyStore,
        meta::{HasId, StoreId, StoreRow, TableIden},
    },
    utils::{pg_type_of, ListOptionsValidator, LIST_LIMIT_MAX},
};

#[derive(Iden)]
pub struct ManyCte;

pub async fn get_joined_opt<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &GetJoinedQueryMeta<I>,
) -> Result<Option<T>> {
    // 1) Guard: count rows on the many side via its FK -> single PK
    let count_meta = CountManyQueryMeta {
        table: meta.many_table,
        fk: meta.many_fk, // FIX: use many_fk (foreign key on the many table)
    };
    let count = count_many(ctx, dbx, id, &count_meta).await?;
    if count > LIST_LIMIT_MAX {
        return Err(StoreError::ListLimitExceeded {
            max: LIST_LIMIT_MAX,
            actual: count,
        });
    }

    // Define the query for the Common Table Expression (CTE)
    let cte_query = Query::select()
        .from(meta.many_table)
        .column(Asterisk)
        .to_owned();

    // Create the CTE object
    let common_table_expr = CommonTableExpression::new()
        .table_name(ManyCte) // Name our CTE `CredentialCte`
        .query(cte_query) // Use the query defined above
        .to_owned();

    // Create custom aggregate and coalesce expression
    let cust = format!(
        r#"COALESCE(jsonb_agg("{many_cte}") FILTER (WHERE "{many_cte}".id IS NOT NULL), '[]'::jsonb)"#,
        many_cte = ManyCte.to_string()
    );
    let join_agg = Expr::cust(cust);

    // Build the main query
    let mut main_query = Query::select();
    main_query
        .from(meta.single_table)
        .column((meta.single_table, Asterisk))
        // we need to use meta.agg_alias in order to deserialize to the correct field on the type T which is `single_table_row.collection`, ie. account.credentials
        .expr_as(join_agg, meta.agg_alias)
        .join(
            JoinType::LeftJoin,
            ManyCte, // Join to the CTE, not the original table
            Expr::col((meta.single_table, meta.single_pk)).equals((ManyCte, meta.many_fk)),
        )
        .and_where(Expr::col((meta.single_table, meta.single_pk)).eq(id.clone()))
        .group_by_col((meta.single_table, meta.single_pk));

    // Attach the WithClause to the main query
    let final_query = main_query.with(common_table_expr.into());

    let (sql, vals) = final_query.build_sqlx(PostgresQueryBuilder);

    let query = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let res: Option<T> = dbx.fetch_optional(query).await?;

    Ok(res)
}

pub async fn get_joined<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &GetJoinedQueryMeta<I>,
) -> Result<T> {
    match get_joined_opt(ctx, dbx, id, meta).await? {
        Some(t) => Ok(t),
        None => Err(StoreError::EntityNotFound {
            entity: meta.single_table.to_string(),
            id: id.to_string(),
        }),
    }
}

pub async fn list_joined<T: StoreRow, F: Into<FilterGroups>, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    filter: Option<F>,
    opts: Option<ListOptions>,
    meta: &ListJoinedMeta<I>,
) -> Result<Vec<T>> {
    // Define the query for the Common Table Expression (CTE)
    let cte_query = Query::select()
        .from(meta.many_table)
        .column(Asterisk)
        .to_owned();

    // Create the CTE object
    let common_table_expr = CommonTableExpression::new()
        .table_name(ManyCte) // Name our CTE `CredentialCte`
        .query(cte_query) // Use the query defined above
        .to_owned();

    let cust = format!(
        r#"COALESCE(jsonb_agg("{many_cte}") FILTER (WHERE "{many_cte}".id IS NOT NULL), '[]'::jsonb)"#,
        many_cte = ManyCte.to_string()
    );
    let join_agg = Expr::cust(cust);

    // 4. Build the main query
    let mut main_query = Query::select();
    main_query
        .from(meta.single_table)
        .column((meta.single_table, Asterisk))
        .expr_as(join_agg, meta.agg_alias)
        .join(
            JoinType::LeftJoin,
            ManyCte, // Join to the CTE, not the original table
            Expr::col((meta.single_table, meta.single_pk)).equals((ManyCte, meta.many_fk)),
        )
        .group_by_col((meta.single_table, meta.single_pk));

    // TODO: ensure joined list row count does not exceed list limits
    // apply filter to query

    if let Some(filter) = filter {
        let filters: FilterGroups = filter.into();
        let cond: Condition = filters.try_into()?;
        main_query.cond_where(cond);
    }

    // validate list options
    let list_options = ListOptionsValidator::validate_list_opts(opts, meta.has_audit)?;
    // add list options to query, there will always at least be maximum limit
    list_options.apply_to_sea_query(&mut main_query);

    // Attach the WithClause to the main query
    let final_query = main_query.with(common_table_expr.into());

    let (sql, vals) = final_query.build_sqlx(PostgresQueryBuilder);

    let query = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let res: Vec<T> = dbx.fetch_all(query).await?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use env_logger::filter;
    use serde_json::{from_value, json};
    use serial_test::serial;

    use crate::{
        dev::init::init_test,
        store::{
            ctx::StoreCtx,
            queries::crud::create,
            schema::{
                account::{
                    AccountFilter, AccountForCreate, AccountIden, AccountRow,
                    AccountWithCredentials,
                },
                credential::{
                    CredentialFilter, CredentialForCreate, CredentialIden, CredentialKind,
                },
            },
            stores::{account::AccountStore, credential::CredentialStore},
            traits::{
                crud::{Creatable, Listable, Readable},
                meta::ReadableMeta,
            },
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_get_joined() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = CredentialStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        let filter: CredentialFilter = json!({"account_id": ctx.user_id()}).try_into()?;

        let existing_cred = store.list(&ctx, Some(filter), None).await?;

        let c = |i| {
            let mut cred = CredentialForCreate::default();
            cred.account_id = ctx.user_id();
            cred.namespace_id = ctx.namespace_id();
            cred.provider_id = Some("TEST".to_string());

            cred
        };

        let create_count = 2;

        for i in 0..create_count {
            let cred = c(i);
            store.create(&ctx, cred).await?;
        }

        let meta = GetJoinedQueryMeta {
            single_table: AccountIden::Table,
            many_table: AccountIden::Credential,
            single_pk: AccountIden::Id,
            many_pk: AccountIden::Id,
            many_fk: AccountIden::AccountId,
            agg_alias: AccountIden::Credentials,
        };

        let res: AccountWithCredentials = get_joined(&ctx, &dbx, &ctx.user_id(), &meta).await?;

        let all_cred = res.credentials;

        assert_eq!(all_cred.len(), existing_cred.len() + create_count);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_joined() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = CredentialStore::new(dbx.clone());
        let acc_store = AccountStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        let c = |i| {
            let mut acc = AccountForCreate::default();
            acc.email = format!("test{i}{i}@LIST_JOIN");
            acc.description = Some("TEST DESCRIPTION".to_string());
            acc
        };

        let mut acc = vec![];

        let acc_count = 2;

        for i in 0..acc_count {
            let n = c(i);

            acc.push(acc_store.create(&ctx, n).await?);
        }

        let c = |acc_id| {
            let mut cred = CredentialForCreate::default();
            cred.account_id = acc_id;
            cred.namespace_id = ctx.namespace_id();
            cred
        };

        let cred_count = 3;

        for ac in acc {
            for i in 0..cred_count {
                let cred = c(ac.id.into());
                store.create(&ctx, cred).await?;
            }
        }

        let meta = ListJoinedMeta {
            single_table: AccountIden::Table,
            many_table: AccountIden::Credential,
            single_pk: AccountIden::Id,
            many_pk: AccountIden::Id,
            many_fk: AccountIden::AccountId,
            agg_alias: AccountIden::Credentials,
            has_audit: true,
        };

        // let filter: AccountFilter = json!({"description":"TEST DESCRIPTION"}).try_into()?;
        let filter: AccountFilter = json!({"email": { "$contains" : "LIST_JOIN"}}).try_into()?;

        let res: Vec<AccountWithCredentials> =
            list_joined::<_, AccountFilter, _>(&ctx, &dbx, Some(filter), None, &meta).await?;

        let mut total_count = 0;
        res.iter()
            .for_each(|el| total_count += el.credentials.len());

        assert_eq!(total_count, acc_count * cred_count);

        Ok(())
    }
}
