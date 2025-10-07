use modql::filter::{FilterGroups, ListOptions};
use sea_query::{Asterisk, Condition, PostgresQueryBuilder, Query};
use sea_query::{Expr, Func, Iden};
use sea_query_binder::SqlxBinder;
use sqlx::Row;
use sqlx::{postgres::PgRow, FromRow};
use sqlx::{query_as_with, query_scalar_with, query_with, Value};

use crate::store::dbx::Dbx;
use crate::store::error::{Result, StoreError};
use crate::store::queries::meta::{CountManyQueryMeta, ReadQueryMeta};
use crate::store::traits::meta::{StoreId, TableIden};
use crate::store::{ctx::StoreCtx, manager::StoreManager};
use crate::store::{traits::meta::Store, utils::ListOptionsValidator};

pub async fn count<F: Into<FilterGroups>, I: TableIden>(
    _ctx: &StoreCtx,
    dbx: &Dbx,
    filter: Option<F>,
    meta: &ReadQueryMeta<I>,
) -> Result<i64> {
    let mut query = Query::select();

    // SELECT COUNT(*)
    query
        .expr_as(Func::count(Expr::col(Asterisk)), "count")
        .from(meta.table);

    // apply filter
    if let Some(filter) = filter {
        let filters: FilterGroups = filter.into();
        let cond: Condition = filters.try_into()?;
        query.cond_where(cond);
    }

    // build SQL and values
    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);
    let q = query_with(&sql, vals);

    let row = q.fetch_one(dbx.db()).await?;

    // Extract COUNT(*) as i64
    let cnt: i64 = row.try_get("count")?;
    Ok(cnt)
}

/// Counts the number of related items for a given parent ID.
pub async fn count_many<I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &CountManyQueryMeta<I>,
) -> Result<i64> {
    let mut query = Query::select();

    // SELECT COUNT(*) FROM {many_table}
    query
        .expr(Func::count(Expr::col(Asterisk)))
        .from(meta.table)
        .and_where(Expr::col(meta.fk).eq(id.clone())); // WHERE foreign_key = ?

    let (sql, values) = query.build_sqlx(PostgresQueryBuilder);

    // Here we can't use `try_get("count")` as easily without an alias,
    // so we fetch into a tuple, which is very efficient.
    let count: (i64,) = sqlx::query_as_with(&sql, values)
        .fetch_one(dbx.db())
        .await?;

    Ok(count.0)
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
            schema::account::{AccountFilter, AccountForCreate, AccountRow},
            stores::account::AccountStore,
            traits::{
                crud::{Create, Get},
                meta::ReadStoreMeta,
            },
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_count_after_inserts_matches_number_of_rows() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        let mut ac = |i: usize| {
            let mut data = AccountForCreate::default();
            data.email = format!("user{i}{i}{i}@example.com");
            data.avatar_url = Some(format!("TEST_FILTER"));
            data
        };

        // Create N accounts
        let n = 3usize;
        let mut created: Vec<AccountRow> = Vec::with_capacity(n);
        for i in 0..n {
            let row = ac(i);
            created.push(acc_store.create(&ctx, row).await?);
        }

        // Verify via get()
        for r in &created {
            let found = acc_store.get(&ctx, &r.id).await?;
            assert_eq!(found.id, r.id);
        }

        let filter: AccountFilter =
            from_value(json!({"avatar_url":{"$contains":"TEST_FILTER"}})).unwrap();

        // Generate meta and call count with the correct arguments
        let meta = acc_store.read_meta();
        let total = count(&ctx, &dbx, Some(filter), &meta).await?;
        assert_eq!(total as usize, n);

        Ok(())
    }
}
