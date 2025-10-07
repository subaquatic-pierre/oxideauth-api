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
        meta::{
            CountManyQueryMeta, ManyToManyMutateQueryMeta, ManyToManyReadQueryMeta,
            OneToManyQueryMeta, ReadQueryMeta,
        },
    },
    traits::meta::{HasId, StoreId, StoreRow, TableIden},
    utils::{pg_type_of, ListOptionsValidator, LIST_LIMIT_MAX},
};

#[derive(Iden)]
pub struct ManyCte;

pub async fn get_one_to_many_opt<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &OneToManyQueryMeta<I>,
) -> Result<Option<T>> {
    // Guard: count rows on the many side via its FK -> single PK
    let count_meta = CountManyQueryMeta {
        table: meta.many_table,
        fk: meta.many_fk,
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
        r#"COALESCE(jsonb_agg("{many_cte}") FILTER (WHERE "{many_cte}"."{many_pk}" IS NOT NULL), '[]'::jsonb)"#,
        many_cte = ManyCte.to_string(),
        many_pk = meta.many_pk.to_string()
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

pub async fn get_one_to_many<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &OneToManyQueryMeta<I>,
) -> Result<T> {
    match get_one_to_many_opt(ctx, dbx, id, meta).await? {
        Some(t) => Ok(t),
        None => Err(StoreError::EntityNotFound {
            entity: meta.single_table.to_string(),
            id: id.to_string(),
        }),
    }
}

pub async fn list_one_to_many<T: StoreRow, F: Into<FilterGroups> + Clone, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    filter: Option<F>,
    opts: Option<ListOptions>,
    meta: &OneToManyQueryMeta<I>,
) -> Result<Vec<T>> {
    // Guard: count rows on the many side via its FK -> single PK
    let count_meta = ReadQueryMeta {
        table: meta.single_table,
        pk: meta.single_pk,
        has_audit: meta.has_audit,
    };
    let count = count(ctx, dbx, filter.clone(), &count_meta).await?;
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

    let cust = format!(
        r#"COALESCE(jsonb_agg("{many_cte}") FILTER (WHERE "{many_cte}"."{many_pk}" IS NOT NULL), '[]'::jsonb)"#,
        many_cte = ManyCte.to_string(),
        many_pk = meta.many_pk.to_string()
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

// CURRENTLY WORKING ON
pub async fn get_many_to_many_opt<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &ManyToManyReadQueryMeta<I>,
) -> Result<Option<T>> {
    // Guard: count rows on the many side via its FK -> single PK
    let count_meta = CountManyQueryMeta {
        table: meta.join_table,
        fk: meta.join_fk,
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
        r#"COALESCE(jsonb_agg("{many_cte}") FILTER (WHERE "{many_cte}"."{many_pk}" IS NOT NULL), '[]'::jsonb)"#,
        many_cte = ManyCte.to_string(),
        many_pk = meta.many_pk.to_string()
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
            meta.join_table,
            // meta.many_pk: correlates to single table "primary key", ie. role_permission.role_id
            Expr::col((meta.join_table, meta.many_pk)).equals((meta.single_table, meta.single_pk)),
        )
        .join(
            JoinType::LeftJoin,
            ManyCte, // Join to the CTE, not the original table to avoid column collisions
            // meta.join_fk: correlates to CTE "primary_key", ie. role_permission.permission_id
            Expr::col((meta.join_table, meta.join_fk)).equals((ManyCte, meta.many_pk)),
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

pub async fn set_many_to_many_links<I: TableIden, ID: StoreId>(
    ctx: &StoreCtx, // Ctx might be used for auditing in the future
    dbx: &Dbx,
    self_id: &ID,
    other_ids: Vec<ID>,
    meta: &ManyToManyMutateQueryMeta<I>,
) -> Result<()> {
    // let mut tx = dbx.begin().await?;

    // // Delete all existing associations for self_id
    // let (sql, vals) = Query::delete()
    //     .from_table(meta.join_table.as_iden())
    //     .and_where(Expr::col(meta.self_fk_col.as_iden()).eq(self_id.clone()))
    //     .build_sqlx(PostgresQueryBuilder);

    // sqlx::query_with(&sql, vals).execute(&mut *tx).await?;

    // // 2. If there are new IDs to link, insert them
    // if !other_ids.is_empty() {
    //     let mut query = Query::insert();
    //     query
    //         .into_table(meta.join_table.as_iden())
    //         .columns([meta.self_fk_col.as_iden(), meta.other_fk_col.as_iden()]);

    //     // Add a row for each new association
    //     for other_id in other_ids {
    //         query.values_panic(vec![self_id.clone().into(), other_id.into()]);
    //     }

    //     let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);
    //     sqlx::query_with(&sql, vals).execute(&mut *tx).await?;
    // }

    // tx.commit().await?;

    Ok(())
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
                crud::{Create, Get, List},
                meta::ReadStoreMeta,
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

        let meta = OneToManyQueryMeta {
            single_table: AccountIden::Table,
            many_table: AccountIden::Credential,
            single_pk: AccountIden::Id,
            many_pk: AccountIden::Id,
            many_fk: AccountIden::AccountId,
            agg_alias: AccountIden::Credentials,
            has_audit: true,
        };

        let res: AccountWithCredentials =
            get_one_to_many(&ctx, &dbx, &ctx.user_id(), &meta).await?;

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

        let meta = OneToManyQueryMeta {
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
            list_one_to_many::<_, AccountFilter, _>(&ctx, &dbx, Some(filter), None, &meta).await?;

        let mut total_count = 0;
        res.iter()
            .for_each(|el| total_count += el.credentials.len());

        assert_eq!(total_count, acc_count * cred_count);

        Ok(())
    }
}
