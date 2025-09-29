use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    schema::{
        meta::{MutateQueryMeta, ReadQueryMeta},
        project::{ProjectFilter, ProjectForCreate, ProjectForUpdate, ProjectIden, ProjectRow},
    },
    traits::{
        crud::{
            Countable, Creatable, CreatableMany, Deletable, DeletableMany, Firstable, Listable,
            Readable, Updatable, UpdatableMany,
        },
        meta::{MutableMeta, ReadableMeta, Store},
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

impl ReadableMeta for ProjectStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: ProjectIden::Table,
            pk: ProjectIden::Id,
            has_audit: true,
        }
    }
}

impl MutableMeta for ProjectStore {
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

impl Creatable for ProjectStore {
    type CreateStoreParams = ProjectForCreate;
}

impl Readable for ProjectStore {}

impl Listable for ProjectStore {
    type FilterStoreParams = ProjectFilter;
}

impl Updatable for ProjectStore {
    type UpdateStoreParams = ProjectForUpdate;
}

impl Deletable for ProjectStore {}

impl CreatableMany for ProjectStore {}

impl UpdatableMany for ProjectStore {
    type UpdateStoreParams = ProjectForUpdate;
}

impl DeletableMany for ProjectStore {}

impl Firstable for ProjectStore {}

impl Countable for ProjectStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
