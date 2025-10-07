use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::project::{
        ProjectFilter, ProjectForCreate, ProjectForUpdate, ProjectIden, ProjectRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::meta::{MutateStoreMeta, ReadStoreMeta, Store},
};

/// The struct for our Project store, holding the database connection wrapper.
pub struct ProjectStore {
    db: Arc<Dbx>,
}

impl ProjectStore {
    /// Creates a new `ProjectStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, ProjectStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for ProjectStore {
    type Iden = ProjectIden;
    type Row = ProjectRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for ProjectStore {
    type FilterStoreParams = ProjectFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: ProjectIden::Table,
            pk: ProjectIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for ProjectStore {
    type CreateStoreParams = ProjectForCreate;
    type UpdateStoreParams = ProjectForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: ProjectIden::Table,
            pk: ProjectIden::Id,
            has_audit: true,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
