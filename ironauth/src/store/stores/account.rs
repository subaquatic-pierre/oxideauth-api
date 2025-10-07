use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::account::{
        AccountFilter, AccountForCreate, AccountForUpdate, AccountIden, AccountRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::meta::{MutateStoreMeta, ReadStoreMeta, Store},
};

/// The struct for our Account store, holding the database connection wrapper.
pub struct AccountStore {
    db: Arc<Dbx>,
}

impl AccountStore {
    /// Creates a new `AccountStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, AccountStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for AccountStore {
    type Iden = AccountIden;
    type Row = AccountRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for AccountStore {
    type FilterStoreParams = AccountFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: AccountIden::Table,
            pk: AccountIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for AccountStore {
    type CreateStoreParams = AccountForCreate;
    type UpdateStoreParams = AccountForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: AccountIden::Table,
            pk: AccountIden::Id,
            has_audit: true,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
