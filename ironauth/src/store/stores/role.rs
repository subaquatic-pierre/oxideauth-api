use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    schema::{
        meta::{MutateQueryMeta, ReadQueryMeta},
        role::{RoleFilter, RoleForCreate, RoleForUpdate, RoleIden, RoleRow},
    },
    traits::{
        crud::{
            Countable, Creatable, CreatableMany, Deletable, DeletableMany, Firstable, Listable,
            Readable, Updatable, UpdatableMany,
        },
        meta::{MutableMeta, ReadableMeta, Store},
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

impl ReadableMeta for RoleStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: RoleIden::Table,
            pk: RoleIden::Id,
            has_audit: true,
        }
    }
}

impl MutableMeta for RoleStore {
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

impl Creatable for RoleStore {
    type CreateStoreParams = RoleForCreate;
}

impl Readable for RoleStore {}

impl Listable for RoleStore {
    type FilterStoreParams = RoleFilter;
}

impl Updatable for RoleStore {
    type UpdateStoreParams = RoleForUpdate;
}

impl Deletable for RoleStore {}

impl CreatableMany for RoleStore {}

impl UpdatableMany for RoleStore {
    type UpdateStoreParams = RoleForUpdate;
}

impl DeletableMany for RoleStore {}

impl Firstable for RoleStore {}

impl Countable for RoleStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
