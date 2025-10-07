use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::role::{RoleFilter, RoleForCreate, RoleForUpdate, RoleIden, RoleRow},
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::{
        crud::{
            Create, CreateMany, Delete, DeleteMany, Get, GetCount, GetFirst, List, Update,
            UpdateMany,
        },
        meta::{MutateStoreMeta, ReadStoreMeta, Store},
    },
};

/// The struct for our Role store, holding the database connection wrapper.
pub struct RoleStore {
    db: Arc<Dbx>,
}

impl RoleStore {
    /// Creates a new `RoleStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// These implementations provide the core metadata for the store.

impl Store for RoleStore {
    type Iden = RoleIden;
    type Row = RoleRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for RoleStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: RoleIden::Table,
            pk: RoleIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for RoleStore {
    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: RoleIden::Table,
            pk: RoleIden::Id,
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

impl Create for RoleStore {
    type CreateStoreParams = RoleForCreate;
}

impl Get for RoleStore {}

impl List for RoleStore {
    type FilterStoreParams = RoleFilter;
}

impl Update for RoleStore {
    type UpdateStoreParams = RoleForUpdate;
}

impl Delete for RoleStore {}

impl CreateMany for RoleStore {}

impl UpdateMany for RoleStore {
    type UpdateStoreParams = RoleForUpdate;
}

impl DeleteMany for RoleStore {}

impl GetFirst for RoleStore {}

impl GetCount for RoleStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
