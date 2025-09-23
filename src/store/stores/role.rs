use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::{
        iden::TableIden,
        role::{RoleCreate, RoleFilter, RoleRow, RoleUpdate},
    },
    stores::base::{
        CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, MetaStore, UpdateManyStore,
        UpdateStore,
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

impl MetaStore for RoleStore {
    type Id = Uuid;
    type Row = RoleRow;

    const TABLE: TableIden = TableIden::Role;
    const HAS_AUDIT_FIELDS: bool = true;

    fn db(&self) -> &Dbx {
        &self.db
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
