use sea_query::{
    Alias, Asterisk, Expr, Func, Iden, JoinType, PostgresQueryBuilder, Query, SelectStatement,
    SimpleExpr, Value,
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
    utils::{pg_type_of, LIST_LIMIT_MAX},
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

    let id_val: Value = id.to_owned().into();
    let id_type = pg_type_of(&id_val);

    let raw_sql = format!(
        r#"
    WITH
      many_cte AS (
        SELECT
          *
        FROM
          "{many_table}"
      )
    SELECT
      "{single_table}".*,
      COALESCE(
        jsonb_agg(many_cte) FILTER (WHERE many_cte.id IS NOT NULL),
        '[]'::jsonb
      ) AS "{many_alias}"
    FROM
      "{single_table}"
      LEFT JOIN many_cte ON "{single_table}"."id" = many_cte."{many_fk}"
    WHERE
      "{single_table}"."{single_pk}" = $1::{id_type}
    GROUP BY
      "{single_table}"."id"
    "#,
        single_table = meta.single_table.to_string(),
        many_table = meta.many_table.to_string(),
        many_fk = meta.many_fk.to_string(),
        single_pk = meta.single_pk.to_string(),
        many_alias = meta.agg_alias.to_string(),
        id_type = id_type
    );

    // join query and expression
    print!("SQL RAW DEBUG");
    print!("{raw_sql}");

    let sqlx_query = sqlx::query_as::<_, T>(&raw_sql).bind(id.to_string());

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

        // let creds = res.credentials;

        println!("{res:?}");

        Ok(())
    }
}
