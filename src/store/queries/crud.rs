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
    let id_str = id.to_string();
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

    let ret = store.db().fetch_one(sqlx).await.map_err(|e| match e {
        Error::Sqlx(e) => match e {
            sqlx::Error::RowNotFound => Error::EntityNotFound {
                entity: DB::TABLE.to_string(),
                id: id_str,
            },
            _ => Error::Sqlx(e),
        },
        _ => e,
    })?;

    Ok(ret)
}

pub async fn delete<T, DB>(ctx: &Ctx, store: &DB, id: DB::Id) -> Result<T>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
{
    let id_str = id.to_string();
    let mut query = Query::delete();

    query
        .from_table(DB::TABLE)
        .and_where(Expr::col(CommonIden::Id).eq(id))
        .returning_all();

    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    let sqlx = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let ret = store.db().fetch_one(sqlx).await.map_err(|e| match e {
        Error::Sqlx(e) => match e {
            sqlx::Error::RowNotFound => Error::EntityNotFound {
                entity: DB::TABLE.to_string(),
                id: id_str,
            },
            _ => Error::Sqlx(e),
        },
        _ => e,
    })?;

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::{from_value, json};
    use serial_test::serial;
    use sqlx::{query_as, Postgres};
    use uuid::Uuid;

    use crate::{
        dev::init::init_test,
        services::error::Error as ServiceError,
        store::{
            error::Error,
            schema::account::{
                AccountCreate, AccountFilter, AccountMeta, AccountRow, AccountUpdate,
            },
            stores::{
                account::AccountStore,
                base::{CreateStore, GetStore, UpdateStore},
            },
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_create_and_get_pass() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();

        let acc_store = AccountStore::new(dbx);

        let ctx = Ctx::new_root();

        let data = AccountCreate::default();

        let ret: AccountRow = create(&ctx, &acc_store, data).await?;

        let found: AccountRow = acc_store.get(&ctx, ret.id).await?;

        assert_eq!(found.id, ret.id);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_get_fail() -> anyhow::Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Pick a random UUID that won't exist
        let missing_id = Uuid::new_v4();

        // Act
        let err = acc_store.get(&ctx, missing_id).await;

        matches!(err, Err(Error::EntityNotFound { .. }));

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_with_filter_and_limit_pass() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Create accounts in two groups so filter can select only one group
        for i in 0..5 {
            let mut d = AccountCreate::default();
            d.email = format!("in_{}@example.com", i);
            d.provider = "LIST_FILTER_MATCH".to_string();
            create::<AccountRow, _, _>(&ctx, &acc_store, d).await?;
        }
        for i in 0..2 {
            let mut d = AccountCreate::default();
            d.email = format!("out_{}@example.com", i);
            d.provider = "OTHER_PROVIDER".to_string();
            create::<AccountRow, _, _>(&ctx, &acc_store, d).await?;
        }

        // Filter: provider contains LIST_FILTER
        let filter: AccountFilter =
            from_value(json!({"provider":{"$contains":"LIST_FILTER"}})).unwrap();

        // Limit to 3 results
        let opts = Some(ListOptions {
            limit: Some(3),
            offset: None,
            // add other fields if your ListOptions has them (e.g., sort, order, before/after)
            ..Default::default()
        });

        // Act
        let rows: Vec<AccountRow> = list(&ctx, &acc_store, Some(filter), opts).await?;

        // Assert
        assert_eq!(rows.len(), 3, "list should respect the limit");
        // sanity: all rows must match the provider filter
        assert!(rows.iter().all(|r| r.provider.contains("LIST_FILTER")));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_pagination_pass() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Create 6 rows in the matching group to test two pages of size 3
        for i in 0..6 {
            let mut d = AccountCreate::default();
            d.email = format!("page_{}@example.com", i);
            d.provider = "LIST_PAGINATION".to_string();
            create::<AccountRow, _, _>(&ctx, &acc_store, d).await?;
        }

        let filter: AccountFilter =
            from_value(json!({"provider":{"$eq":"LIST_PAGINATION"}})).unwrap();

        // Page 1: limit 3, offset 0
        let page1_opts = Some(ListOptions {
            limit: Some(3),
            offset: Some(0),
            ..Default::default()
        });
        let p1: Vec<AccountRow> = list(&ctx, &acc_store, Some(filter), page1_opts).await?;
        assert_eq!(p1.len(), 3);

        // Page 2: limit 3, offset 3
        let page2_opts = Some(ListOptions {
            limit: Some(3),
            offset: Some(3),
            ..Default::default()
        });

        let filter: AccountFilter =
            from_value(json!({"provider":{"$eq":"LIST_PAGINATION"}})).unwrap();
        let p2: Vec<AccountRow> = list(&ctx, &acc_store, Some(filter), page2_opts).await?;
        assert_eq!(p2.len(), 3);

        // Ensure pages are disjoint by id
        let p1_ids: std::collections::HashSet<_> = p1.iter().map(|r| r.id).collect();
        let p2_ids: std::collections::HashSet<_> = p2.iter().map(|r| r.id).collect();
        assert!(p1_ids.is_disjoint(&p2_ids), "pages should be disjoint");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_with_invalid_limit_fail() -> anyhow::Result<()> {
        use serde_json::{from_value, json};

        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Optional: ensure there is at least some data (not required for this failure)
        let mut d = AccountCreate::default();
        d.email = "limit_fail@example.com".into();
        d.provider = "LIMIT_FAIL".into();
        create::<AccountRow, _, _>(&ctx, &acc_store, d).await?;

        // Any filter (or None) — doesn't matter for limit validation
        let filter: Option<AccountFilter> =
            Some(from_value(json!({"provider":{"$eq":"LIMIT_FAIL"}})).unwrap());

        // Invalid limit: zero (validator should reject)
        let opts = Some(ListOptions {
            limit: Some(0),
            offset: None,
            ..Default::default()
        });

        // Act
        let err = list::<AccountRow, _, _>(&ctx, &acc_store, filter, opts).await;

        // Assert (use your concise failure style)
        matches!(err, Err(Error::InvalidListOptions { .. }));

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_success() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Create a row to update
        let mut d = AccountCreate::default();
        d.email = "update_ok@example.com".into();
        d.provider = "UPDATE_BEFORE".into();
        let created: AccountRow = create(&ctx, &acc_store, d).await?;

        // Prepare update (change provider)
        let mut u = AccountUpdate::default();
        u.provider = Some("UPDATE_AFTER".into());

        // Act
        let updated: AccountRow = update(&ctx, &acc_store, created.id, u).await?;

        // Assert
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.provider, "UPDATE_AFTER");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_fail_not_found() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Non-existent ID
        let missing_id = Uuid::new_v4();

        // Provide at least one field to update
        let mut u = AccountUpdate::default();
        u.provider = Some("WON'T_APPLY".into());

        // Act
        let err = update::<AccountRow, _, _>(&ctx, &acc_store, missing_id, u).await;

        // Assert (concise failure style)
        matches!(err, Err(Error::EntityNotFound { .. }));

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_success() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Create a row to delete
        let mut d = AccountCreate::default();
        d.email = "delete_ok@example.com".into();
        d.provider = "DELETE_ME".into();
        let created: AccountRow = create(&ctx, &acc_store, d).await?;

        // Act
        let deleted: AccountRow = delete(&ctx, &acc_store, created.id).await?;

        // Assert
        assert_eq!(deleted.id, created.id);
        assert_eq!(deleted.provider, "DELETE_ME");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_fail_not_found() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let acc_store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Non-existent ID
        let missing_id = Uuid::new_v4();

        // Act
        let err = delete::<AccountRow, _>(&ctx, &acc_store, missing_id).await;

        // Assert (concise failure style)
        matches!(err, Err(Error::EntityNotFound { .. }));

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_tags() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Create a baseline account
        let mut create = AccountCreate::default();
        create.email = "tag-update@example.com".to_string();
        create.provider = "TEST_UPDATE_TAGS".to_string();
        let created: AccountRow = store.create(&ctx, create).await?;

        // Act: update tags
        let new_tags = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        let mut upd = AccountUpdate::default();
        upd.tags = Some(new_tags.clone());

        let updated: AccountRow = store.update(&ctx, created.id, upd).await?;

        // Assert (via returned row)
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.tags, new_tags.as_slice());

        // Assert (via get)
        let fetched = store.get(&ctx, created.id).await?;
        assert_eq!(fetched.tags, new_tags.as_slice());

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_meta() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = Ctx::new_root();

        // Create a baseline account
        let mut create = AccountCreate::default();
        create.email = "meta-update@example.com".to_string();
        create.provider = "TEST_UPDATE_META".to_string();
        // If AccountCreate allows setting meta at create-time, you can set it here; otherwise it defaults.
        let created: AccountRow = store.create(&ctx, create).await?;

        // Act: update meta
        let mut upd = AccountUpdate::default();
        upd.meta = Some(AccountMeta {
            schema_version: "v2".to_string(),
            // add any future fields here when they exist; defaults cover the rest
        });

        let updated: AccountRow = store.update(&ctx, created.id, upd).await?;

        // Assert (via returned row)
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.meta.schema_version, "v2");

        // Assert (via get)
        let fetched = store.get(&ctx, created.id).await?;
        assert_eq!(fetched.meta.schema_version, "v2");

        Ok(())
    }
}
