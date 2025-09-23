use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::{
        credential::{CredentialCreate, CredentialFilter, CredentialRow, CredentialUpdate},
        iden::TableIden,
    },
    stores::base::{
        CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, MetaStore, UpdateManyStore,
        UpdateStore,
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

impl MetaStore for CredentialStore {
    type Id = Uuid;
    type Row = CredentialRow;

    const TABLE: TableIden = TableIden::Credential;
    const HAS_AUDIT_FIELDS: bool = true;

    fn db(&self) -> &Dbx {
        &self.db
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
