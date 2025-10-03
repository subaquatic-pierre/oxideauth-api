use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    schema::token_blacklist::{
        TokenBlacklistFilter, TokenBlacklistForCreate, TokenBlacklistIden, TokenBlacklistRow,
    },
    traits::{
        crud::{
            Countable, Creatable, CreatableMany, Deletable, DeletableMany, Firstable, Listable,
            Readable,
        },
        meta::{MutableMeta, ReadableMeta, Store},
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

impl ReadableMeta for TokenBlacklistStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: TokenBlacklistIden::Table,
            pk: TokenBlacklistIden::Id,
            has_audit: true,
        }
    }
}

impl MutableMeta for TokenBlacklistStore {
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

impl Creatable for TokenBlacklistStore {
    type CreateStoreParams = TokenBlacklistForCreate;
}

impl Readable for TokenBlacklistStore {}

impl Listable for TokenBlacklistStore {
    type FilterStoreParams = TokenBlacklistFilter;
}

impl Deletable for TokenBlacklistStore {}

impl CreatableMany for TokenBlacklistStore {}

impl DeletableMany for TokenBlacklistStore {}

impl Firstable for TokenBlacklistStore {}

impl Countable for TokenBlacklistStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
