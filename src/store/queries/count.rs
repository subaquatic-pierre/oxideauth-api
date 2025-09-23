use crate::store::error::{Error, Result};
use crate::store::{ctx::Ctx, manager::StoreManager};
use crate::store::{opts::ListOptionsValidator, stores::base::MetaStore};
use modql::filter::{FilterGroups, ListOptions};
use sea_query::{Asterisk, Condition, PostgresQueryBuilder, Query};
use sea_query::{Expr, Func, Iden};
use sea_query_binder::SqlxBinder;
use sqlx::Row;
use sqlx::{postgres::PgRow, FromRow};
use sqlx::{query_as_with, query_scalar_with, query_with, Value};

pub async fn count<F, DB>(_ctx: &Ctx, store: &DB, filter: Option<F>) -> Result<i64>
where
    DB: MetaStore,
    F: Into<FilterGroups>,
{
    let mut query = Query::select();

    // SELECT COUNT(*)
    query
        .expr_as(Func::count(Expr::col(Asterisk)), "count")
        .from(DB::TABLE);

    // apply filter
    if let Some(filter) = filter {
        let filters: FilterGroups = filter.into();
        let cond: Condition = filters.try_into()?;
        query.cond_where(cond);
    }

    // build SQL and values
    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);
    let q = query_with(&sql, vals);

    let row = q.fetch_one(store.db().db()).await?;

    // Extract COUNT(*) as i64
    let cnt: i64 = row.try_get("count")?;
    Ok(cnt)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::{from_value, json};
    use serial_test::serial;

    use crate::{
        dev::init::init_test,
        store::{
            ctx::Ctx,
            queries::crud::create,
            schema::account::{AccountCreate, AccountFilter, AccountRow},
            stores::{
                account::AccountStore,
                base::{CreateStore, GetStore},
            },
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_count_after_inserts_matches_number_of_rows() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        let mut ac = |i: usize| {
            let mut data = AccountCreate::default();
            data.email = format!("user{}@example.com", i);
            data
        };

        // Create N accounts
        let n = 3usize;
        let mut created: Vec<AccountRow> = Vec::with_capacity(n);
        for i in 0..3 {
            let row = ac(i);
            created.push(acc_store.create(&ctx, row).await?);
        }

        // Verify via get()
        for r in &created {
            let found = acc_store.get(&ctx, r.id).await?;
            assert_eq!(found.id, r.id);
        }

        let filter: AccountFilter =
            from_value(json!({"provider":{"$contains":"TEST_FILTER"}})).unwrap();

        // Count should equal n
        let total = count(&ctx, &acc_store, Some(filter)).await?;
        assert_eq!(total as usize, n);

        Ok(())
    }
}
