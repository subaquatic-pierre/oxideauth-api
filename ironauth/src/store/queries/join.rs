use sea_query::{
    Alias, Asterisk, Expr, Func, Iden, JoinType, PostgresQueryBuilder, Query, SelectStatement,
    SimpleExpr,
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
        meta::{CountManyQueryMeta, GetJoinedQueryMeta, ReadQueryMeta},
    },
    traits::{
        join::JoinOneToManyStore,
        meta::{HasId, StoreId, StoreRow, TableIden},
    },
    utils::LIST_LIMIT_MAX,
};

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

    // Step 1: Define the aggregate function call itself.
    let agg_function = Func::cust(Alias::new("jsonb_agg"))
        .arg(Func::cust(Alias::new("to_jsonb")).arg(Expr::col(meta.many_table)));

    // Step 2: Define the expression for the FILTER's WHERE clause.
    let filter_condition = Expr::col((meta.many_table, meta.many_pk)).is_not_null();

    let filtered_expression = Expr::cust_with_exprs(
        "? FILTER (WHERE ?)",
        [
            // The first `?` is the aggregate function call.
            SimpleExpr::FunctionCall(agg_function),
            // The second `?` is the condition for the filter.
            filter_condition.into(),
        ],
    );

    let final_agg_expr = Func::coalesce([
        filtered_expression.into(),      // The expression to check.
        Expr::val("'[]'::jsonb").into(), // The default value if the first is NULL.
    ]);

    // --- PART C: Construct the final SELECT query ---
    let mut query = Query::select();

    query
        .column((meta.single_table, Asterisk))
        .expr_as(final_agg_expr, meta.agg_alias) // Use the final coalesce function
        .from(meta.single_table)
        .left_join(
            meta.many_table,
            Expr::col((meta.single_table, meta.single_pk)).equals((meta.many_table, meta.many_fk)),
        )
        .and_where(Expr::col((meta.single_table, meta.single_pk)).eq(id.clone()))
        .group_by_col((meta.single_table, meta.single_pk));

    let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
    let sqlx_query = sqlx::query_as_with::<_, T, _>(&sql, values);

    let result = dbx.fetch_optional(sqlx_query).await?;
    Ok(result)
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

#[cfg(test)]
mod tests {
    use anyhow::Result;
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
                credential::{CredentialForCreate, CredentialIden},
            },
            stores::{account::AccountStore, credential::CredentialStore},
            traits::{
                crud::{Creatable, Readable},
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

        let c = |i| {
            let mut cred = CredentialForCreate::default();
            cred.account_id = ctx.user_id();
            cred.namespace_id = ctx.namespace_id();
            cred
        };

        for i in 0..5 {
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

        let creds = res.credentials;

        println!("{creds:?}");

        Ok(())
    }
}
