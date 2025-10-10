use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::membership::{
        MembershipFilter, MembershipForCreate, MembershipForUpdate, MembershipIden, MembershipRow,
        MembershipWithRoles,
    },
    queries::meta::{ContainsFilterQueryMeta, ManyToManyQueryMeta, MutateQueryMeta, ReadQueryMeta},
    traits::meta::{ContainsFilterStore, ManyToManyStore, MutateStore, ReadStore, Store},
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

impl ManyToManyStore for MembershipStore {
    type ManyToManyRow = MembershipWithRoles;

    type FilterStoreParams = MembershipFilter;

    fn many_to_many_meta(&self) -> ManyToManyQueryMeta<Self::Iden> {
        ManyToManyQueryMeta {
            single_table: MembershipIden::Table,
            many_table: MembershipIden::Role,
            join_table: MembershipIden::MembershipRole,
            single_pk: MembershipIden::Id,
            many_pk: MembershipIden::RolePk,
            many_fk: MembershipIden::RoleId,
            join_fk: MembershipIden::MembershipId,
            agg_alias: MembershipIden::Roles,
            has_audit: true,
        }
    }
}

impl ContainsFilterStore for MembershipStore {
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: MembershipIden::Table,
            col: MembershipIden::Tags,
        }
    }

    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: MembershipIden::Table,
            col: MembershipIden::Meta,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
