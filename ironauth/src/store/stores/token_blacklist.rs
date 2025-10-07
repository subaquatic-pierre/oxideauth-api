use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::token_blacklist::{
        TokenBlacklistFilter, TokenBlacklistForCreate, TokenBlacklistForUpdate, TokenBlacklistIden,
        TokenBlacklistRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::meta::{MutateStoreMeta, ReadStoreMeta, Store},
};
use modql::field::HasSeaFields;

pub struct TokenBlacklistStore {
    db: Arc<Dbx>,
}

impl TokenBlacklistStore {
    /// Creates a new `TokenBlacklistStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, TokenBlacklistStore implicitly gains
// its capabilities from the blanket implementations.

impl Store for TokenBlacklistStore {
    type Iden = TokenBlacklistIden;
    type Row = TokenBlacklistRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for TokenBlacklistStore {
    type FilterStoreParams = TokenBlacklistFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: TokenBlacklistIden::Table,
            pk: TokenBlacklistIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for TokenBlacklistStore {
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
