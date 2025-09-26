use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::project::{ProjectCreate, ProjectFilter, ProjectIden, ProjectRow, ProjectUpdate},
    traits::{
        crud::{Creatable, Deletable, DeletableMany, Listable, Readable, Updatable, UpdatableMany},
        meta::Store,
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

impl Store for ProjectStore {
    type TableIden = ProjectIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = ProjectIden::Table;
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

impl Creatable for ProjectStore {
    type CreateStoreParams = ProjectCreate;
}

impl Readable for ProjectStore {}

impl Listable for ProjectStore {
    type FilterStoreParams = ProjectFilter;
}

impl Updatable for ProjectStore {
    type UpdateStoreParams = ProjectUpdate;
}

impl DeletableMany for ProjectStore {}

impl UpdatableMany for ProjectStore {
    type UpdateStoreParams = ProjectUpdate;
}

impl Deletable for ProjectStore {}
