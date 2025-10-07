use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::token_blacklist::{
        TokenBlacklistFilter, TokenBlacklistForCreate, TokenBlacklistIden, TokenBlacklistRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::{
        crud::{Create, CreateMany, Delete, DeleteMany, Get, GetCount, GetFirst, List},
        meta::{MutateStoreMeta, ReadStoreMeta, Store},
    },
};

/// The struct for our TokenBlacklist store, holding the database connection wrapper.
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
// These implementations provide the core metadata for the store.

impl Store for TokenBlacklistStore {
    type Iden = TokenBlacklistIden;
    type Row = TokenBlacklistRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for TokenBlacklistStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: TokenBlacklistIden::Table,
            pk: TokenBlacklistIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for TokenBlacklistStore {
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

// region:    --- Functional Trait Implementations
// -----------------------------------------------------------------------------
// With the metadata defined above, these implementations are now very concise.
// We only need to specify the associated types for params (Create, Update, Filter).
// The actual method logic is handled by the default implementations in your traits.

impl Create for TokenBlacklistStore {
    type CreateStoreParams = TokenBlacklistForCreate;
}

impl Get for TokenBlacklistStore {}

impl List for TokenBlacklistStore {
    type FilterStoreParams = TokenBlacklistFilter;
}

impl Delete for TokenBlacklistStore {}

impl CreateMany for TokenBlacklistStore {}

impl DeleteMany for TokenBlacklistStore {}

impl GetFirst for TokenBlacklistStore {}

impl GetCount for TokenBlacklistStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
