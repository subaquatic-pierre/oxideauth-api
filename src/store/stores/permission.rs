use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::{
        iden::TableIden,
        permission::{PermissionCreate, PermissionFilter, PermissionRow, PermissionUpdate},
    },
    stores::base::{
        CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, MetaStore, UpdateManyStore,
        UpdateStore,
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

impl MetaStore for PermissionStore {
    type Id = Uuid;
    type Row = PermissionRow;

    const TABLE: TableIden = TableIden::Permission;
    const HAS_AUDIT_FIELDS: bool = true;

    fn db(&self) -> &Dbx {
        &self.db
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
