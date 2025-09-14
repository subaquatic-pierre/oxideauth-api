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
