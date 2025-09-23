use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::{
        iden::TableIden,
        project::{ProjectCreate, ProjectFilter, ProjectRow, ProjectUpdate},
    },
    stores::base::{
        CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, MetaStore, UpdateManyStore,
        UpdateStore,
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

impl MetaStore for ProjectStore {
    type Id = Uuid;
    type Row = ProjectRow;

    const TABLE: TableIden = TableIden::Project;
    const HAS_AUDIT_FIELDS: bool = true;

    fn db(&self) -> &Dbx {
        &self.db
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
