use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::credential::{
        CredentialFilter, CredentialForCreate, CredentialForUpdate, CredentialIden, CredentialRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::{
        crud::{
            Create, CreateMany, Delete, DeleteMany, Get, GetCount, GetFirst, List, Update,
            UpdateMany,
        },
        meta::{MutateStoreMeta, ReadStoreMeta, Store},
    },
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
// These implementations provide the core metadata for the store.

impl Store for CredentialStore {
    type Iden = CredentialIden;
    type Row = CredentialRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for CredentialStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: CredentialIden::Table,
            pk: CredentialIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for CredentialStore {
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

// region:    --- Functional Trait Implementations
// -----------------------------------------------------------------------------
// With the metadata defined above, these implementations are now very concise.
// We only need to specify the associated types for params (Create, Update, Filter).
// The actual method logic is handled by the default implementations in your traits.

impl Create for CredentialStore {
    type CreateStoreParams = CredentialForCreate;
}

impl Get for CredentialStore {}

impl List for CredentialStore {
    type FilterStoreParams = CredentialFilter;
}

impl Update for CredentialStore {
    type UpdateStoreParams = CredentialForUpdate;
}

impl Delete for CredentialStore {}

impl CreateMany for CredentialStore {}

impl UpdateMany for CredentialStore {
    type UpdateStoreParams = CredentialForUpdate;
}

impl DeleteMany for CredentialStore {}

impl GetFirst for CredentialStore {}

impl GetCount for CredentialStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
