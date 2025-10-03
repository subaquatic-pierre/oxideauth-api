use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    schema::membership::{
        MembershipFilter, MembershipForCreate, MembershipForUpdate, MembershipIden, MembershipRow,
    },
    traits::{
        crud::{
            Countable, Creatable, CreatableMany, Deletable, DeletableMany, Firstable, Listable,
            Readable, Updatable, UpdatableMany,
        },
        meta::{MutableMeta, ReadableMeta, Store},
    },
};

/// The struct for our Membership store, holding the database connection wrapper.
pub struct MembershipStore {
    db: Arc<Dbx>,
}

impl MembershipStore {
    /// Creates a new `MembershipStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// These implementations provide the core metadata for the store.

impl Store for MembershipStore {
    type Iden = MembershipIden;
    type Row = MembershipRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadableMeta for MembershipStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: MembershipIden::Table,
            pk: MembershipIden::Id,
            has_audit: true,
        }
    }
}

impl MutableMeta for MembershipStore {
    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: MembershipIden::Table,
            pk: MembershipIden::Id,
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

impl Creatable for MembershipStore {
    type CreateStoreParams = MembershipForCreate;
}

impl Readable for MembershipStore {}

impl Listable for MembershipStore {
    type FilterStoreParams = MembershipFilter;
}

impl Updatable for MembershipStore {
    type UpdateStoreParams = MembershipForUpdate;
}

impl Deletable for MembershipStore {}

impl CreatableMany for MembershipStore {}

impl UpdatableMany for MembershipStore {
    type UpdateStoreParams = MembershipForUpdate;
}

impl DeletableMany for MembershipStore {}

impl Firstable for MembershipStore {}

impl Countable for MembershipStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
