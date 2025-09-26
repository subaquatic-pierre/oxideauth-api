use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::namespace::{
        NamespaceCreate, NamespaceFilter, NamespaceIden, NamespaceRow, NamespaceUpdate,
    },
    traits::{
        crud::{
            Creatable, DeletableMany, Deletable	, Listable, Readable, UpdatableMany,
            Updatable,
        },
        meta::Store,
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

impl Store for NamespaceStore {
    type TableIden = NamespaceIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = NamespaceIden::Table;
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

impl Creatable for NamespaceStore {
    type CreateStoreParams = NamespaceCreate;
}

impl Readable for NamespaceStore {}

impl Listable for NamespaceStore {
    type FilterStoreParams = NamespaceFilter;
}

impl Updatable for NamespaceStore {
    type UpdateStoreParams = NamespaceUpdate;
}

impl DeletableMany for NamespaceStore {}

impl UpdatableMany for NamespaceStore {
    type UpdateStoreParams = NamespaceUpdate;
}

impl Deletable	 for NamespaceStore {}
