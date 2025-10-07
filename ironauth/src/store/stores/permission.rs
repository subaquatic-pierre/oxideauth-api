use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    schema::permission::{
        PermissionFilter, PermissionForCreate, PermissionForUpdate, PermissionIden, PermissionRow,
    },
    traits::{
        crud::{
            GetCount, Create, CreateMany, Delete, DeleteMany, GetFirst, Get, List, Update,
            UpdateMany,
        },
        meta::{MutateStoreMeta, ReadStoreMeta, Store},
    },
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
// These implementations provide the core metadata for the store.

impl Store for PermissionStore {
    type Iden = PermissionIden;
    type Row = PermissionRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for PermissionStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: PermissionIden::Table,
            pk: PermissionIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for PermissionStore {
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

// region:    --- Functional Trait Implementations
// -----------------------------------------------------------------------------
// With the metadata defined above, these implementations are now very concise.
// We only need to specify the associated types for params (Create, Update, Filter).
// The actual method logic is handled by the default implementations in your traits.

impl Create for PermissionStore {
    type CreateStoreParams = PermissionForCreate;
}

impl Get for PermissionStore {}

impl List for PermissionStore {
    type FilterStoreParams = PermissionFilter;
}

impl Update for PermissionStore {
    type UpdateStoreParams = PermissionForUpdate;
}

impl Delete for PermissionStore {}

impl CreateMany for PermissionStore {}

impl UpdateMany for PermissionStore {
    type UpdateStoreParams = PermissionForUpdate;
}

impl DeleteMany for PermissionStore {}

impl GetFirst for PermissionStore {}

impl GetCount for PermissionStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
