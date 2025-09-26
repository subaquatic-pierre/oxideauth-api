use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::project::{ProjectCreate, ProjectFilter, ProjectIden, ProjectRow, ProjectUpdate},
    traits::{
        crud::{
            CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, UpdateManyStore,
            UpdateStore,
        },
        meta::BaseMetaStore,
    },
};

pub struct ProjectStore {
    db: Arc<Dbx>,
}

impl ProjectStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl BaseMetaStore for ProjectStore {
    type TableIden = ProjectIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = ProjectIden::TableName;
    const TABLE_PK: Self::TableIden = ProjectIden::Id;

    type IdKind = Uuid;

    type Row = ProjectRow;

    fn db(&self) -> &Dbx {
        &self.db
    }

    fn has_audit_fields() -> bool {
        true
    }
}

impl CreateStore for ProjectStore {
    type CreateStoreParams = ProjectCreate;
}

impl GetStore for ProjectStore {}

impl ListStore for ProjectStore {
    type FilterStoreParams = ProjectFilter;
}

impl UpdateStore for ProjectStore {
    type UpdateStoreParams = ProjectUpdate;
}

impl DeleteManyStore for ProjectStore {}

impl UpdateManyStore for ProjectStore {
    type UpdateStoreParams = ProjectUpdate;
}

impl DeleteStore for ProjectStore {}
