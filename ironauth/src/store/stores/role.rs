use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::role::{RoleFilter, RoleForCreate, RoleForUpdate, RoleIden, RoleRow},
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::meta::{MutateStore, ReadStore, Store},
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
// By implementing these meta traits, RoleStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for RoleStore {
    type Iden = RoleIden;
    type Row = RoleRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStore for RoleStore {
    type FilterStoreParams = RoleFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: RoleIden::Table,
            pk: RoleIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStore for RoleStore {
    type CreateStoreParams = RoleForCreate;
    type UpdateStoreParams = RoleForUpdate;

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
