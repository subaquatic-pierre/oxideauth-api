use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::{
        iden::TableIden,
        namespace::{NamespaceCreate, NamespaceFilter, NamespaceRow, NamespaceUpdate},
    },
    stores::base::{
        CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, MetaStore, UpdateManyStore,
        UpdateStore,
    },
};

pub struct NamespaceStore {
    db: Arc<Dbx>,
}

impl NamespaceStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl MetaStore for NamespaceStore {
    type Id = Uuid;
    type Row = NamespaceRow;

    const TABLE: TableIden = TableIden::Namespace;
    const HAS_AUDIT_FIELDS: bool = true;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl CreateStore for NamespaceStore {
    type CreateStoreParams = NamespaceCreate;
}

impl GetStore for NamespaceStore {}

impl ListStore for NamespaceStore {
    type FilterStoreParams = NamespaceFilter;
}

impl UpdateStore for NamespaceStore {
    type UpdateStoreParams = NamespaceUpdate;
}

impl DeleteManyStore for NamespaceStore {}

impl UpdateManyStore for NamespaceStore {
    type UpdateStoreParams = NamespaceUpdate;
}

impl DeleteStore for NamespaceStore {}
