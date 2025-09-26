use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::permission::{
        PermissionCreate, PermissionFilter, PermissionIden, PermissionRow, PermissionUpdate,
    },
    traits::{
        crud::{
            CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, UpdateManyStore,
            UpdateStore,
        },
        meta::BaseMetaStore,
    },
};

pub struct PermissionStore {
    db: Arc<Dbx>,
}

impl PermissionStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl BaseMetaStore for PermissionStore {
    type TableIden = PermissionIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = PermissionIden::TableName;
    const TABLE_PK: Self::TableIden = PermissionIden::Id;

    type IdKind = Uuid;

    type Row = PermissionRow;

    fn db(&self) -> &Dbx {
        &self.db
    }

    fn has_audit_fields() -> bool {
        true
    }
}

impl CreateStore for PermissionStore {
    type CreateStoreParams = PermissionCreate;
}

impl GetStore for PermissionStore {}

impl ListStore for PermissionStore {
    type FilterStoreParams = PermissionFilter;
}

impl UpdateStore for PermissionStore {
    type UpdateStoreParams = PermissionUpdate;
}

impl DeleteManyStore for PermissionStore {}

impl UpdateManyStore for PermissionStore {
    type UpdateStoreParams = PermissionUpdate;
}

impl DeleteStore for PermissionStore {}
