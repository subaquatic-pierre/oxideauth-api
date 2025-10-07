use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::permission::{
        PermissionFilter, PermissionForCreate, PermissionForUpdate, PermissionIden, PermissionRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::meta::{MutateStoreMeta, ReadStoreMeta, Store},
};

/// The struct for our Permission store, holding the database connection wrapper.
pub struct PermissionStore {
    db: Arc<Dbx>,
}

impl PermissionStore {
    /// Creates a new `PermissionStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, PermissionStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for PermissionStore {
    type Iden = PermissionIden;
    type Row = PermissionRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for PermissionStore {
    type FilterStoreParams = PermissionFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: PermissionIden::Table,
            pk: PermissionIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for PermissionStore {
    type CreateStoreParams = PermissionForCreate;
    type UpdateStoreParams = PermissionForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: PermissionIden::Table,
            pk: PermissionIden::Id,
            has_audit: true,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
