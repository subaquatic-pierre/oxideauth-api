use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::credential::{
        CredentialFilter, CredentialForCreate, CredentialForUpdate, CredentialIden, CredentialRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::meta::{MutateStoreMeta, ReadStoreMeta, Store},
};

/// The struct for our Credential store, holding the database connection wrapper.
pub struct CredentialStore {
    db: Arc<Dbx>,
}

impl CredentialStore {
    /// Creates a new `CredentialStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, CredentialStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for CredentialStore {
    type Iden = CredentialIden;
    type Row = CredentialRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for CredentialStore {
    type FilterStoreParams = CredentialFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: CredentialIden::Table,
            pk: CredentialIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for CredentialStore {
    type CreateStoreParams = CredentialForCreate;
    type UpdateStoreParams = CredentialForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: CredentialIden::Table,
            pk: CredentialIden::Id,
            has_audit: true,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
