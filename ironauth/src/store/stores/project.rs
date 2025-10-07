use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    schema::project::{ProjectFilter, ProjectForCreate, ProjectForUpdate, ProjectIden, ProjectRow},
    traits::{
        crud::{
            Create, CreateMany, Delete, DeleteMany, Get, GetCount, GetFirst, List, Update,
            UpdateMany,
        },
        meta::{MutateStoreMeta, ReadStoreMeta, Store},
    },
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
// These implementations provide the core metadata for the store.

impl Store for ProjectStore {
    type Iden = ProjectIden;
    type Row = ProjectRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for ProjectStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: ProjectIden::Table,
            pk: ProjectIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for ProjectStore {
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

// region:    --- Functional Trait Implementations
// -----------------------------------------------------------------------------
// With the metadata defined above, these implementations are now very concise.
// We only need to specify the associated types for params (Create, Update, Filter).
// The actual method logic is handled by the default implementations in your traits.

impl Create for ProjectStore {
    type CreateStoreParams = ProjectForCreate;
}

impl Get for ProjectStore {}

impl List for ProjectStore {
    type FilterStoreParams = ProjectFilter;
}

impl Update for ProjectStore {
    type UpdateStoreParams = ProjectForUpdate;
}

impl Delete for ProjectStore {}

impl CreateMany for ProjectStore {}

impl UpdateMany for ProjectStore {
    type UpdateStoreParams = ProjectForUpdate;
}

impl DeleteMany for ProjectStore {}

impl GetFirst for ProjectStore {}

impl GetCount for ProjectStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
