use std::sync::Arc;

use crate::store::{
    dbx::{DbExecutor, PgDbx},
    entities::token_blacklist::{
        TokenBlacklistFilter, TokenBlacklistForCreate, TokenBlacklistForUpdate, TokenBlacklistIden,
        TokenBlacklistRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::meta::{MutateStore, ReadStore, Store},
};
use modql::field::HasSeaFields;

pub struct TokenBlacklistStore {
    dbx: Arc<PgDbx>,
}

impl TokenBlacklistStore {
    /// Creates a new `TokenBlacklistStore`.
    pub fn new(dbx: Arc<PgDbx>) -> Self {
        Self { dbx }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, TokenBlacklistStore implicitly gains
// its capabilities from the blanket implementations.

impl Store for TokenBlacklistStore {
    type Iden = TokenBlacklistIden;
    type Row = TokenBlacklistRow;

    fn dbx(&self) -> impl DbExecutor {
        self.dbx.clone()
    }
}

impl ReadStore for TokenBlacklistStore {
    type FilterStoreParams = TokenBlacklistFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: TokenBlacklistIden::Table,
            pk: TokenBlacklistIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStore for TokenBlacklistStore {
    type CreateStoreParams = TokenBlacklistForCreate;
    type UpdateStoreParams = TokenBlacklistForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: TokenBlacklistIden::Table,
            pk: TokenBlacklistIden::Id,
            has_audit: true,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations

// region:    --- Tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dev::init::init_test,
        store::{
            ctx::StoreCtx,
            entities::{hash::Sha256Hash, token_blacklist::TokenBlacklistForCreate},
            error::StoreError,
            traits::crud::*,
        },
        utils::time::now_utc,
    };
    use anyhow::Result;
    use serde_json::json;
    use serial_test::serial;
    use time::Duration;

    #[tokio::test]
    #[serial]
    async fn test_create_get_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = TokenBlacklistStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let hash = Sha256Hash::gen_rand();
        let hash_2: Sha256Hash = Sha256Hash::new(hash.bytes().clone());

        let data = TokenBlacklistForCreate {
            token_hash: hash_2,
            expires_at: now_utc() + Duration::days(1),
            ..Default::default()
        };

        // -- Execute
        let created_entry = store.create(&ctx, data).await?;
        let fetched_entry = store.get(&ctx, &created_entry.id).await?;

        // -- Assert
        assert_eq!(created_entry.token_hash, hash);
        assert_eq!(fetched_entry.id, created_entry.id);
        assert_eq!(fetched_entry.token_hash, hash);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = TokenBlacklistStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let hash = Sha256Hash::gen_rand();

        let data = TokenBlacklistForCreate {
            token_hash: hash,
            expires_at: now_utc() + Duration::days(1),
            ..Default::default()
        };
        let created_entry = store.create(&ctx, data).await?;

        // -- Execute
        let deleted_entry = store.delete(&ctx, &created_entry.id).await?;
        let get_result = store.get(&ctx, &created_entry.id).await;

        // -- Assert
        assert_eq!(deleted_entry.id, created_entry.id);
        assert!(
            matches!(get_result, Err(StoreError::EntityNotFound { .. })),
            "Getting the blacklist entry after deletion should fail"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_with_filter_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = TokenBlacklistStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let hash = Sha256Hash::gen_rand();
        let hash_2: Sha256Hash = Sha256Hash::new(hash.bytes().clone());
        let entries_to_create = vec![
            TokenBlacklistForCreate {
                token_hash: hash_2,
                expires_at: now_utc() + Duration::days(1),
                reason: Some("REASON".to_string()),
                ..Default::default()
            },
            TokenBlacklistForCreate {
                token_hash: Sha256Hash::gen_rand(),
                expires_at: now_utc() + Duration::days(1),
                ..Default::default()
            },
        ];
        store.create_many(&ctx, entries_to_create).await?;

        // -- Execute
        let filter: TokenBlacklistFilter = json!({ "reason": "REASON" }).try_into()?;
        let entries = store.list(&ctx, Some(filter), None).await?;

        // -- Assert
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].token_hash, hash);

        Ok(())
    }
}
// -----------------------------------------------------------------------------
// endregion: --- Tests
