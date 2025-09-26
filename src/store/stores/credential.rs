use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::credential::{
        CredentialCreate, CredentialFilter, CredentialIden, CredentialRow, CredentialUpdate,
    },
    traits::{
        crud::{
            CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, UpdateManyStore,
            UpdateStore,
        },
        meta::BaseMetaStore,
    },
};

pub struct CredentialStore {
    db: Arc<Dbx>,
}

impl CredentialStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl BaseMetaStore for CredentialStore {
    type TableIden = CredentialIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = CredentialIden::TableName;
    const TABLE_PK: Self::TableIden = CredentialIden::Id;

    type IdKind = Uuid;

    type Row = CredentialRow;

    fn db(&self) -> &Dbx {
        &self.db
    }

    fn has_audit_fields() -> bool {
        true
    }
}

impl CreateStore for CredentialStore {
    type CreateStoreParams = CredentialCreate;
}

impl GetStore for CredentialStore {}

impl ListStore for CredentialStore {
    type FilterStoreParams = CredentialFilter;
}

impl UpdateStore for CredentialStore {
    type UpdateStoreParams = CredentialUpdate;
}

impl DeleteManyStore for CredentialStore {}

impl UpdateManyStore for CredentialStore {
    type UpdateStoreParams = CredentialUpdate;
}

impl DeleteStore for CredentialStore {}
