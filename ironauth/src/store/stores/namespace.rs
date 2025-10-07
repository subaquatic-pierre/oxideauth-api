use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::namespace::{
        NamespaceFilter, NamespaceForCreate, NamespaceForUpdate, NamespaceIden, NamespaceRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::meta::{MutateStoreMeta, ReadStoreMeta, Store},
};

/// The struct for our Namespace store, holding the database connection wrapper.
pub struct NamespaceStore {
    db: Arc<Dbx>,
}

impl NamespaceStore {
    /// Creates a new `NamespaceStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, NamespaceStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for NamespaceStore {
    type Iden = NamespaceIden;
    type Row = NamespaceRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for NamespaceStore {
    type FilterStoreParams = NamespaceFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: NamespaceIden::Table,
            pk: NamespaceIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for NamespaceStore {
    type CreateStoreParams = NamespaceForCreate;
    type UpdateStoreParams = NamespaceForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: NamespaceIden::Table,
            pk: NamespaceIden::Id,
            has_audit: true,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
