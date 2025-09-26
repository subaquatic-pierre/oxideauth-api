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
            Creatable, DeletableMany, Deletable	, Readable, Listable, UpdatableMany,
            Updatable,
        },
        meta::Store,
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

impl Store for PermissionStore {
    type TableIden = PermissionIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = PermissionIden::Table;
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

impl Creatable for PermissionStore {
    type CreateStoreParams = PermissionCreate;
}

impl Readable for PermissionStore {}

impl Listable for PermissionStore {
    type FilterStoreParams = PermissionFilter;
}

impl Updatable for PermissionStore {
    type UpdateStoreParams = PermissionUpdate;
}

impl DeletableMany for PermissionStore {}

impl UpdatableMany for PermissionStore {
    type UpdateStoreParams = PermissionUpdate;
}

impl Deletable	 for PermissionStore {}
