use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::credential::{
        CredentialFilter, CredentialForCreate, CredentialForUpdate, CredentialIden, CredentialRow,
    },
    queries::meta::{ContainsFilterQueryMeta, MutateQueryMeta, ReadQueryMeta},
    traits::meta::{ContainsFilterStoreMeta, MutateStore, ReadStore, Store},
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

impl ReadStore for CredentialStore {
    type FilterStoreParams = CredentialFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: CredentialIden::Table,
            pk: CredentialIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStore for CredentialStore {
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

impl ContainsFilterStoreMeta for CredentialStore {
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: CredentialIden::Table,
            col: CredentialIden::Tags,
        }
    }

    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: CredentialIden::Table,
            col: CredentialIden::Meta,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
