use modql::filter::{FilterGroups, ListOptions};
use sea_query::Iden;
use sea_query::{Asterisk, Condition, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow};
use sqlx::{query_as_with, Value};

use crate::store::dbx::Dbx;
use crate::store::error::{Result, StoreError};
use crate::store::queries::meta::{FirstQueryMeta, ReadQueryMeta};
use crate::store::traits::meta::{StoreRow, TableIden};
use crate::store::{ctx::StoreCtx, manager::StoreManager};
use crate::store::{traits::meta::Store, utils::ListOptionsValidator};

pub async fn first_opt<T: StoreRow, F: Into<FilterGroups>, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    filter: Option<F>,
    opts: Option<ListOptions>,
    meta: &ReadQueryMeta<I>,
) -> Result<Option<T>> {
    let mut query = Query::select();

    // FROM {DB::TABLE_NAME} SELECT *
    query.from(meta.table).column(Asterisk);

    // apply filter
    if let Some(filter) = filter {
        let filters: FilterGroups = filter.into();
        let cond: Condition = filters.try_into()?;
        query.cond_where(cond);
    }

    // validate list options
    let mut list_opts = ListOptionsValidator::validate_list_opts(opts, meta.has_audit)?;
    // ensure deterministic first if caller didn’t provide order
    if list_opts.order_bys.is_none() {
        // choose your house default:
        // most recent created first
        list_opts.order_bys = Some(vec!["!created_at".to_string()].into());
    }
    list_opts.limit = Some(1);
    list_opts.apply_to_sea_query(&mut query);

    // build sql
    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    // run query, expecting at most one row
    let sqlx = query_as_with::<_, T, _>(&sql, vals);

    let ret = dbx.fetch_optional(sqlx).await?;

    Ok(ret)
}
pub async fn first<T: StoreRow, F: Into<FilterGroups>, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    filter: Option<F>,
    opts: Option<ListOptions>,
    meta: &ReadQueryMeta<I>,
) -> Result<T> {
    match first_opt(ctx, dbx, filter, opts, meta).await? {
        Some(t) => Ok(t),
        None => Err(StoreError::EntityNotFound {
            entity: meta.table.to_string(),
            id: "first".to_string(),
        }),
    }
}
