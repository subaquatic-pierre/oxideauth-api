use crate::store::error::{Error, Result};
use crate::store::{ctx::Ctx, manager::StoreManager};
use crate::store::{opts::ListOptionsValidator, stores::base::MetaStore};
use modql::filter::{FilterGroups, ListOptions};
use sea_query::Iden;
use sea_query::{Asterisk, Condition, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow};
use sqlx::{query_as_with, Value};

pub async fn first<T, F, DB>(
    ctx: &Ctx,
    store: &DB,
    filter: Option<F>,
    opts: Option<ListOptions>,
) -> Result<T>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    F: Into<FilterGroups>,
{
    let mut query = Query::select();

    // FROM {DB::TABLE} SELECT *
    query.from(DB::TABLE).column(Asterisk);

    // apply filter
    if let Some(filter) = filter {
        let filters: FilterGroups = filter.into();
        let cond: Condition = filters.try_into()?;
        query.cond_where(cond);
    }

    // validate list options
    let mut list_opts = ListOptionsValidator::validate_list_opts(opts, DB::HAS_AUDIT_FIELDS)?;
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

    let ret = store
        .db()
        .fetch_optional(sqlx)
        .await?
        .ok_or(Error::EntityNotFound {
            entity: DB::TABLE.to_string(),
            id: "first".to_string(),
        })?;

    Ok(ret)
}

pub async fn first_opt<T, F, DB>(
    ctx: &Ctx,
    store: &DB,
    filter: Option<F>,
    opts: Option<ListOptions>,
) -> Result<Option<T>>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    F: Into<FilterGroups>,
{
    match first(ctx, store, filter, opts).await {
        Err(e) => match e {
            Error::EntityNotFound { .. } => Ok(None),
            _ => Err(e),
        },
        Ok(t) => Ok(Some(t)),
    }
}
