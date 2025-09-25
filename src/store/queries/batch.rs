use modql::field::HasSeaFields;
use modql::filter::{FilterGroups, ListOptions};
use sea_query::{
    Alias, Asterisk, CaseStatement, Condition, Expr, IdenList, IntoValueTuple,
    PostgresQueryBuilder, Query, SeaRc, SimpleExpr, WithQuery,
};
use sea_query_binder::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow};
use sqlx::{query_as_with, Postgres, QueryBuilder, Value};
use uuid::Uuid;

use crate::store::dbx::Dbx;
use crate::store::error::{Result, StoreError};
use crate::store::traits::crud::MetaStore;
use crate::store::utils::ListOptionsValidator;
use crate::store::utils::{pg_type_of, prepare_audit_fields, push_sq_value};
use crate::store::{ctx::StoreCtx, manager::StoreManager};
use sea_query::{Iden, IntoIden, TableRef};

pub async fn create_many<T, C, DB>(ctx: &StoreCtx, store: &DB, data: Vec<C>) -> Result<Vec<T>>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    C: HasSeaFields,
{
    // --- Early exit: nothing to do, return empty result.
    if data.is_empty() {
        return Ok(vec![]);
    }

    ListOptionsValidator::validate_limit(data.len() as i64)?;

    let user_id = ctx.user_id();
    let mut query = Query::insert();

    query.into_table(DB::TABLE_NAME);

    // flag to only set columns for the first item
    // do not add columns again for any more items
    let mut is_first = true;

    for el in data {
        let mut fields = el.not_none_sea_fields();

        if DB::has_audit_fields() {
            prepare_audit_fields(&mut fields, user_id, true);
        }

        let (cols, vals) = fields.for_sea_insert();

        // add columns if not already added, .ie first iteration
        if is_first {
            query.columns(cols);
            // update is_first to skip for all next iterations
            is_first = true;
        }

        query.values(vals)?;
    }

    query.returning_all();

    let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
    let sqlx_query = query_as_with::<_, T, _>(&sql, values);

    let ret = store.db().fetch_all(sqlx_query).await?;

    Ok(ret)
}

pub async fn update_many<T, DB, U>(
    ctx: &StoreCtx,
    store: &DB,
    data: Vec<(DB::IdKind, U)>,
) -> Result<Vec<T>>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    U: HasSeaFields + Clone,
{
    // exit: nothing to do, return empty result.
    if data.is_empty() {
        return Ok(vec![]);
    }

    // validate list options, ie. max limit
    ListOptionsValidator::validate_limit(data.len() as i64)?;

    let mut updated_rows = Vec::with_capacity(data.len());

    let mut txn = store.db().begin().await?;

    for (id, updates) in data {
        let mut query = Query::update();

        let mut fields = updates.not_none_sea_fields();

        if DB::has_audit_fields() {
            prepare_audit_fields(&mut fields, ctx.user_id(), false);
        }

        let fields = fields.for_sea_update();

        let query = query
            .table(DB::TABLE_NAME)
            .values(fields)
            .and_where(Expr::col(DB::TABLE_PK).eq(id.clone()))
            .returning_all();

        let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

        let res = sqlx::query_as_with::<_, T, _>(&sql, vals)
            .fetch_optional(&mut *txn)
            .await?;

        if let Some(ret) = res {
            updated_rows.push(ret);
        }
    }

    txn.commit().await?;
    Ok(updated_rows)
}

pub async fn delete_many<T, DB>(ctx: &StoreCtx, store: &DB, ids: Vec<DB::IdKind>) -> Result<Vec<T>>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
{
    // --- Early exit: nothing to do, return empty result.
    if ids.is_empty() {
        return Ok(vec![]);
    }

    ListOptionsValidator::validate_limit(ids.len() as i64)?;

    let mut query = Query::delete();

    query
        .from_table(DB::TABLE_NAME)
        .and_where(Expr::col(DB::TABLE_PK).is_in(ids))
        .returning_all();

    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    let sqlx = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let ret = store.db().fetch_all(sqlx).await?;

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;
    use serial_test::serial;
    use sqlx::{query_as, Postgres};

    use crate::{
        dev::init::init_test,
        store::{
            queries::crud::{create, list},
            schema::account::{
                AccountCreate, AccountFilter, AccountMeta, AccountRow, AccountUpdate,
            },
            stores::account::AccountStore,
            traits::crud::GetStore,
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_update_many() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();

        let acc_store = AccountStore::new(dbx);

        let ctx = StoreCtx::new_root();

        let data = AccountCreate::default();
        // println!("DATA 1: {:#?}", data);
        let ret1: AccountRow = create(&ctx, &acc_store, data).await?;

        let mut data = AccountCreate::default();
        // println!("DATA 2: {:#?}", data);
        data.email = "change".to_string();
        let ret2: AccountRow = create(&ctx, &acc_store, data).await?;

        let c1 = AccountUpdate::default();
        let mut c2 = AccountUpdate::default();
        c2.name = None;

        let data = vec![(ret1.id, c1), (ret2.id, c2)];

        let r: Vec<AccountRow> = update_many(&ctx, &acc_store, data).await?;

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_many_ignore_unknown() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();

        let acc_store = AccountStore::new(dbx);

        let ctx = StoreCtx::new_root();

        // Prepare multiple unique payloads
        let n = 3usize;
        let mut payloads: Vec<AccountCreate> = Vec::with_capacity(n);
        let desc = "TEST_CREATE_MANY_ONE_NOT_CHANGE".to_string();

        for i in 0..n {
            let mut ac = AccountCreate::default();
            ac.email = format!("bulk{:02}{i}@example.com", i);
            ac.description = Some(desc.clone());
            payloads.push(ac);
        }

        // Act
        let created: Vec<AccountRow> = create_many(&ctx, &acc_store, payloads).await?;
        let mut data = vec![];
        for (i, acc) in created.iter().enumerate() {
            let mut new_update = AccountUpdate::default();
            new_update.description = Some("UPDATED DESCRIPTION".to_string());
            data.push((acc.id.clone(), new_update));
            if (i == 1) {
                break;
            }
        }

        // push unknown ID
        data.push((Uuid::new_v4(), AccountUpdate::default()));

        let r: Vec<AccountRow> = update_many(&ctx, &acc_store, data).await?;

        let filter: AccountFilter = json!({"description":Some(desc.clone())}).try_into()?;

        let found: Vec<AccountRow> = list(&ctx, &acc_store, Some(filter), None).await?;

        assert_eq!(found.len(), 1);

        assert_eq!(r.len(), 2);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_create_many() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = StoreCtx::new_root();

        // Prepare multiple unique payloads
        let n = 3usize;
        let mut payloads: Vec<AccountCreate> = Vec::with_capacity(n);
        for i in 0..n {
            let mut ac = AccountCreate::default();
            ac.email = format!("bulk{:02}@example.com", i);
            payloads.push(ac);
        }

        // Act
        let created: Vec<AccountRow> = create_many(&ctx, &store, payloads).await?;

        // Assert: count matches
        assert_eq!(created.len(), n);

        // Assert: emails are unique and persisted
        for (i, row) in created.iter().enumerate() {
            assert_eq!(row.email, format!("bulk{:02}@example.com", i));
            // Verify via get()
            let fetched = store.get(&ctx, &row.id).await?;
            assert_eq!(fetched.id, row.id);
            assert_eq!(fetched.email, row.email);
        }

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_many_tags() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = StoreCtx::new_root();

        // Create two baseline accounts
        let mut c1 = AccountCreate::default();
        c1.email = "bulk-tags-1@example.com".to_string();
        let a1: AccountRow = create(&ctx, &store, c1).await?;

        let mut c2 = AccountCreate::default();
        c2.email = "bulk-tags-2@example.com".to_string();
        let a2: AccountRow = create(&ctx, &store, c2).await?;

        // Act
        let upd1 = {
            let mut u = AccountUpdate::default();
            u.tags = Some(vec!["alpha".into(), "beta".into()]);
            u
        };
        let upd2 = {
            let mut u = AccountUpdate::default();
            u.tags = Some(vec!["gamma".into()]);
            u
        };
        let _updated: Vec<AccountRow> =
            update_many(&ctx, &store, vec![(a1.id, upd1), (a2.id, upd2)]).await?;

        // Assert (fetch-by-id to avoid relying on RETURNING order)
        let f1 = store.get(&ctx, &a1.id).await?;
        assert_eq!(f1.tags, ["alpha", "beta"]);

        let f2 = store.get(&ctx, &a2.id).await?;
        assert_eq!(f2.tags, ["gamma"]);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_many_meta() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = StoreCtx::new_root();

        // Create two baseline accounts
        let mut c1 = AccountCreate::default();
        c1.email = "bulk-meta-1@example.com".to_string();
        let a1: AccountRow = create(&ctx, &store, c1).await?;

        let mut c2 = AccountCreate::default();
        c2.email = "bulk-meta-2@example.com".to_string();
        let a2: AccountRow = create(&ctx, &store, c2).await?;

        // Act
        let upd1 = {
            let mut u = AccountUpdate::default();
            u.meta = Some(AccountMeta {
                schema_version: "v1.2.3".into(),
                ..Default::default()
            });
            u
        };
        let upd2 = {
            let mut u = AccountUpdate::default();
            u.meta = Some(AccountMeta {
                schema_version: "v9.9.9".into(),
                ..Default::default()
            });
            u
        };
        let _updated: Vec<AccountRow> =
            update_many(&ctx, &store, vec![(a1.id, upd1), (a2.id, upd2)]).await?;

        // Assert
        let f1 = store.get(&ctx, &a1.id).await?;
        assert_eq!(f1.meta.schema_version, "v1.2.3");

        let f2 = store.get(&ctx, &a2.id).await?;
        assert_eq!(f2.meta.schema_version, "v9.9.9");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_create_many_fail() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = StoreCtx::new_root();

        // Build a payload intentionally exceeding the validator limit.
        // (We don't rely on the exact limit; 2000 should be safely over any sane cap.)
        let over_limit = 2000usize;
        let mut payloads: Vec<AccountCreate> = Vec::with_capacity(over_limit);
        for i in 0..over_limit {
            let mut ac = AccountCreate::default();
            ac.email = format!("too-many-{:04}@example.com", i);
            payloads.push(ac);
        }

        // Act
        let res: crate::store::error::Result<Vec<AccountRow>> =
            create_many(&ctx, &store, payloads).await;

        // Assert
        assert!(
            res.is_err(),
            "expected create_many to fail when exceeding the max batch size"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_many_fail() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = StoreCtx::new_root();

        // Create a single baseline account to obtain a valid id
        let mut ac = AccountCreate::default();
        ac.email = "update-many-fail@example.com".to_string();
        let row: AccountRow = create(&ctx, &store, ac).await?;

        // Build an updates vector intentionally exceeding the validator limit
        let over_limit = 2000usize;
        let mut updates: Vec<(Uuid, AccountUpdate)> = Vec::with_capacity(over_limit);
        for _ in 0..over_limit {
            let mut u = AccountUpdate::default();
            // touch a benign field so it's a real update payload
            u.name = Some("bulk-name".to_string());
            updates.push((row.id, u));
        }

        // Act
        let res: crate::store::error::Result<Vec<AccountRow>> =
            update_many(&ctx, &store, updates).await;

        // Assert
        assert!(
            res.is_err(),
            "expected update_many to fail when exceeding the max batch size"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_many() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = StoreCtx::new_root();

        // Create a few accounts
        let mut mk = |i: usize| {
            let mut c = AccountCreate::default();
            c.email = format!("del-many-{i}@example.com");
            c
        };
        let a1: AccountRow = create(&ctx, &store, mk(1)).await?;
        let a2: AccountRow = create(&ctx, &store, mk(2)).await?;
        let a3: AccountRow = create(&ctx, &store, mk(3)).await?;

        // Act
        let deleted: Vec<AccountRow> = delete_many(&ctx, &store, vec![a1.id, a2.id, a3.id]).await?;

        // Assert: all returned & gone
        assert_eq!(deleted.len(), 3);

        use crate::store::error::{Result, StoreError};
        for id in [a1.id, a2.id, a3.id] {
            let got = store.get(&ctx, &id).await;
            assert!(matches!(got, Err(StoreError::EntityNotFound { .. })));
        }

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_many_wrong_id() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = StoreCtx::new_root();

        // Create one account
        let mut c = AccountCreate::default();
        c.email = "del-many-wrong@example.com".into();
        let a: AccountRow = create(&ctx, &store, c).await?;

        // Build ids: 1 real + 1 random (non-existent)
        let wrong = Uuid::new_v4();

        // Act
        let deleted: Vec<AccountRow> = delete_many(&ctx, &store, vec![a.id, wrong]).await?;

        // Assert: only the existing one is deleted; wrong id is ignored
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].id, a.id);

        // Existing row is gone
        use crate::store::error::{Result, StoreError};
        let got = store.get(&ctx, &a.id).await;
        assert!(matches!(got, Err(StoreError::EntityNotFound { .. })));

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_many_fail() -> Result<()> {
        // Arrange
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = AccountStore::new(dbx);
        let ctx = StoreCtx::new_root();

        // Intentionally exceed the validator limit with random UUIDs
        let over_limit = 2000usize;
        let ids: Vec<Uuid> = (0..over_limit).map(|_| Uuid::new_v4()).collect();

        // Act
        let res: crate::store::error::Result<Vec<AccountRow>> =
            delete_many(&ctx, &store, ids).await;

        // Assert
        assert!(
            res.is_err(),
            "expected delete_many to fail when exceeding the max batch size"
        );

        Ok(())
    }
}
