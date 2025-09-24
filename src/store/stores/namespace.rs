use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::namespace::{
        NamespaceCreate, NamespaceFilter, NamespaceIden, NamespaceRow, NamespaceUpdate,
    },
    traits::crud::{
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
    type TableIden = NamespaceIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = NamespaceIden::TableName;
    const TABLE_PK: Self::TableIden = NamespaceIden::Id;

    type IdKind = Uuid;

    type Row = NamespaceRow;

    fn db(&self) -> &Dbx {
        &self.db
    }

    fn has_audit_fields() -> bool {
        true
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
