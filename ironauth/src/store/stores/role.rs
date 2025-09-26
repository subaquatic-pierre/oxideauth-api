use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::role::{RoleCreate, RoleFilter, RoleIden, RoleRow, RoleUpdate},
    traits::{
        crud::{
            Creatable, DeletableMany, Deletable	, Listable, Readable, UpdatableMany,
            Updatable,
        },
        meta::Store,
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

impl Store for RoleStore {
    type TableIden = RoleIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = RoleIden::Table;
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

impl Creatable for RoleStore {
    type CreateStoreParams = RoleCreate;
}

impl Readable for RoleStore {}

impl Listable for RoleStore {
    type FilterStoreParams = RoleFilter;
}

impl Updatable for RoleStore {
    type UpdateStoreParams = RoleUpdate;
}

impl DeletableMany for RoleStore {}

impl UpdatableMany for RoleStore {
    type UpdateStoreParams = RoleUpdate;
}

impl Deletable	 for RoleStore {}
