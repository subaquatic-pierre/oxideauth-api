use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    schema::{
        meta::{MutateQueryMeta, ReadQueryMeta},
        permission::{
            PermissionFilter, PermissionForCreate, PermissionForUpdate, PermissionIden,
            PermissionRow,
        },
    },
    traits::{
        crud::{
            Countable, Creatable, CreatableMany, Deletable, DeletableMany, Firstable, Listable,
            Readable, Updatable, UpdatableMany,
        },
        meta::{MutableMeta, ReadableMeta, Store},
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

impl ReadableMeta for PermissionStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: PermissionIden::Table,
            pk: PermissionIden::Id,
            has_audit: true,
        }
    }
}

impl MutableMeta for PermissionStore {
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

impl Creatable for PermissionStore {
    type CreateStoreParams = PermissionForCreate;
}

impl Readable for PermissionStore {}

impl Listable for PermissionStore {
    type FilterStoreParams = PermissionFilter;
}

impl Updatable for PermissionStore {
    type UpdateStoreParams = PermissionForUpdate;
}

impl Deletable for PermissionStore {}

impl CreatableMany for PermissionStore {}

impl UpdatableMany for PermissionStore {
    type UpdateStoreParams = PermissionForUpdate;
}

impl DeletableMany for PermissionStore {}

impl Firstable for PermissionStore {}

impl Countable for PermissionStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
