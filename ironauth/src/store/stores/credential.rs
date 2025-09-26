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
            Creatable, Deletable, DeletableMany, Listable, Readable, Updatable, UpdatableMany,
        },
        meta::Store,
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

impl Store for CredentialStore {
    type TableIden = CredentialIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = CredentialIden::Table;
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

impl Creatable for CredentialStore {
    type CreateStoreParams = CredentialCreate;
}

impl Readable for CredentialStore {}

impl Listable for CredentialStore {
    type FilterStoreParams = CredentialFilter;
}

impl Updatable for CredentialStore {
    type UpdateStoreParams = CredentialUpdate;
}

impl DeletableMany for CredentialStore {}

impl UpdatableMany for CredentialStore {
    type UpdateStoreParams = CredentialUpdate;
}

impl Deletable for CredentialStore {}
