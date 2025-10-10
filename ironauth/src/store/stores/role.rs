use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::role::{
        RoleFilter, RoleForCreate, RoleForUpdate, RoleIden, RoleRow, RoleWithPermissions,
    },
    queries::meta::{ContainsFilterQueryMeta, ManyToManyQueryMeta, MutateQueryMeta, ReadQueryMeta},
    traits::meta::{ContainsFilterStore, ManyToManyStore, MutateStore, ReadStore, Store},
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

impl ManyToManyStore for RoleStore {
    type ManyToManyRow = RoleWithPermissions;

    type FilterStoreParams = RoleFilter;

    fn many_to_many_meta(&self) -> ManyToManyQueryMeta<Self::Iden> {
        ManyToManyQueryMeta {
            single_table: RoleIden::Table,
            many_table: RoleIden::Permission,
            join_table: RoleIden::RolePermission,
            single_pk: RoleIden::Id,
            many_pk: RoleIden::PermissionPk,
            many_fk: RoleIden::PermissionId,
            join_fk: RoleIden::RoleId,
            agg_alias: RoleIden::Permissions,
            has_audit: true,
        }
    }
}

impl ContainsFilterStore for RoleStore {
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: RoleIden::Table,
            col: RoleIden::Tags,
        }
    }

    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: RoleIden::Table,
            col: RoleIden::Meta,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
