use modql::field::HasSeaFields;
use modql::filter::{FilterGroups, ListOptions};
use sea_query::{
    Alias, Asterisk, Condition, Expr, IdenList, IntoValueTuple, PostgresQueryBuilder, Query,
};
use sea_query_binder::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow};
use sqlx::{query_as_with, Value};
use uuid::Uuid;

use crate::store::dbx::Dbx;
use crate::store::error::{Error, Result};
use crate::store::opts::ListOptionsValidator;
use crate::store::schema::iden::CommonIden;
use crate::store::stores::base::MetaStore;
use crate::store::utils::prepare_audit_fields;
use crate::store::{ctx::Ctx, manager::StoreManager};
use sea_query::{Iden, IntoIden, TableRef};

pub async fn create<T, C, DB>(ctx: &Ctx, store: &DB, data: C) -> Result<T>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    C: HasSeaFields,
{
    let user_id = ctx.user_id();
    let mut fields = data.not_none_sea_fields();

    if DB::HAS_AUDIT_FIELDS {
        prepare_audit_fields(&mut fields, user_id, true);
    }

    let (cols, vals) = fields.for_sea_insert();
    let mut query = Query::insert();
    query
        .into_table(DB::TABLE)
        .columns(cols)
        .values(vals)?
        .returning_all();

    let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
    let sqlx_query = query_as_with::<_, T, _>(&sql, values);

    let ret = store.db().fetch_one(sqlx_query).await?;

    Ok(ret)
}

pub async fn get<T, DB, ID>(ctx: &Ctx, store: &DB, id: ID) -> Result<T>
where
    ID: ToString + Into<sea_query::Value>,
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
{
    let mut query = Query::select();
    let id_for_error = id.to_string();

    query
        .from(DB::TABLE)
        .column(Asterisk)
        .and_where(Expr::col(CommonIden::Id).eq(id));

    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);
    let sqlx_query = query_as_with::<_, T, _>(&sql, vals);

    let ret = store
        .db()
        .fetch_optional(sqlx_query)
        .await?
        .ok_or(Error::EntityNotFound {
            entity: DB::TABLE.to_string(),
            id: id_for_error,
        })?;

    Ok(ret)
}

pub async fn list<T, F, DB>(
    ctx: &Ctx,
    store: &DB,
    filter: Option<F>,
    opts: Option<ListOptions>,
) -> Result<Vec<T>>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    F: Into<FilterGroups>,
{
    let mut query = Query::select();

    // FROM {DB::TABLE} SELECT *
    query.from(DB::TABLE).column(Asterisk);

    // apply filter to query
    if let Some(filter) = filter {
        let filters: FilterGroups = filter.into();
        let cond: Condition = filters.try_into()?;
        query.cond_where(cond);
    }

    // validate list options
    let list_options = ListOptionsValidator::validate_list_opts(opts, DB::HAS_AUDIT_FIELDS)?;
    // add list options to query, there will always at least be maximum limit
    list_options.apply_to_sea_query(&mut query);

    // build sql
    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    // build sqlx query
    let sqlx = query_as_with::<_, T, _>(&sql, vals);

    // execute query against dbx
    let ret = store.db().fetch_all(sqlx).await?;

    Ok(ret)
}

pub async fn update<T, DB, U>(ctx: &Ctx, store: &DB, id: DB::Id, data: U) -> Result<T>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    U: HasSeaFields,
{
    let mut query = Query::update();
    // let mut where_query = Query::select();
    let user_id = ctx.user_id().to_string();

    let mut fields = data.not_none_sea_fields();

    if DB::HAS_AUDIT_FIELDS {
        prepare_audit_fields(&mut fields, ctx.user_id(), false);
    }

    let fields = fields.for_sea_update();

    let query = query
        .table(DB::TABLE)
        .values(fields)
        .and_where(Expr::col(CommonIden::Id).eq(id))
        .returning_all();

    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    let sqlx = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let ret = store.db().fetch_one(sqlx).await?;

    Ok(ret)
}

pub async fn delete<T, DB>(ctx: &Ctx, store: &DB, id: DB::Id) -> Result<T>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
{
    let mut query = Query::delete();

    query
        .from_table(DB::TABLE)
        .and_where(Expr::col(CommonIden::Id).eq(id))
        .returning_all();

    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    let sqlx = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let ret = store.db().fetch_one(sqlx).await?;

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serial_test::serial;
    use sqlx::{query_as, Postgres};

    use crate::{
        dev::init::init_test,
        store::{
            schema::account::{AccountCreate, AccountRow},
            stores::account::AccountStore,
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_create() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();

        let acc_store = AccountStore::new(dbx);

        let ctx = Ctx::new_root();

        let data = AccountCreate::default();

        let ret: AccountRow = create(&ctx, &acc_store, data).await?;

        let query = query_as::<_, AccountRow>("SELECT * FROM accounts WHERE id = $1").bind(ret.id);

        let found: AccountRow = acc_store.db().fetch_one(query).await?;

        assert_eq!(found.id, ret.id);
        Ok(())
    }
}
