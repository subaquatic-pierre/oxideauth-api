use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::role::{RoleCreate, RoleFilter, RoleIden, RoleRow, RoleUpdate},
    traits::{
        crud::{
            CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, UpdateManyStore,
            UpdateStore,
        },
        meta::BaseMetaStore,
    },
};

pub struct RoleStore {
    db: Arc<Dbx>,
}

impl RoleStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl BaseMetaStore for RoleStore {
    type TableIden = RoleIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = RoleIden::TableName;
    const TABLE_PK: Self::TableIden = RoleIden::Id;

    type IdKind = Uuid;

    type Row = RoleRow;

    fn db(&self) -> &Dbx {
        &self.db
    }

    fn has_audit_fields() -> bool {
        true
    }
}

impl CreateStore for RoleStore {
    type CreateStoreParams = RoleCreate;
}

impl GetStore for RoleStore {}

impl ListStore for RoleStore {
    type FilterStoreParams = RoleFilter;
}

impl UpdateStore for RoleStore {
    type UpdateStoreParams = RoleUpdate;
}

impl DeleteManyStore for RoleStore {}

impl UpdateManyStore for RoleStore {
    type UpdateStoreParams = RoleUpdate;
}

impl DeleteStore for RoleStore {}
