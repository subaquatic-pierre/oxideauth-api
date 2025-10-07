use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::membership::{
        MembershipFilter, MembershipForCreate, MembershipForUpdate, MembershipIden, MembershipRow,
    },
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::meta::{MutateStore, ReadStore, Store},
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
// By implementing these meta traits, MembershipStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for MembershipStore {
    type Iden = MembershipIden;
    type Row = MembershipRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStore for MembershipStore {
    type FilterStoreParams = MembershipFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: MembershipIden::Table,
            pk: MembershipIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStore for MembershipStore {
    type CreateStoreParams = MembershipForCreate;
    type UpdateStoreParams = MembershipForUpdate;

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
