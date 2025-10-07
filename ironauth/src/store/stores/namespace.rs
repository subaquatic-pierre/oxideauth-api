use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::membership::{
        MembershipFilter, MembershipForCreate, MembershipForUpdate, MembershipIden, MembershipRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::{
        crud::{
            Create, CreateMany, Delete, DeleteMany, Get, GetCount, GetFirst, List, Update,
            UpdateMany,
        },
        meta::{MutateStoreMeta, ReadStoreMeta, Store},
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

impl ReadStoreMeta for MembershipStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: MembershipIden::Table,
            pk: MembershipIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for MembershipStore {
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

impl Create for MembershipStore {
    type CreateStoreParams = MembershipForCreate;
}

impl Get for MembershipStore {}

impl List for MembershipStore {
    type FilterStoreParams = MembershipFilter;
}

impl Update for MembershipStore {
    type UpdateStoreParams = MembershipForUpdate;
}

impl Delete for MembershipStore {}

impl CreateMany for MembershipStore {}

impl UpdateMany for MembershipStore {
    type UpdateStoreParams = MembershipForUpdate;
}

impl DeleteMany for MembershipStore {}

impl GetFirst for MembershipStore {}

impl GetCount for MembershipStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
