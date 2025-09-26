use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::token_blacklist::{
        TokenBlacklistCreate, TokenBlacklistFilter, TokenBlacklistIden, TokenBlacklistRow,
        TokenBlacklistUpdate,
    },
    traits::{
        crud::{Creatable, Deletable, DeletableMany, Listable, Readable, Updatable, UpdatableMany},
        meta::Store,
    },
};

pub struct TokenBlacklistStore {
    db: Arc<Dbx>,
}

impl TokenBlacklistStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl Store for TokenBlacklistStore {
    type TableIden = TokenBlacklistIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = TokenBlacklistIden::Table;
    const TABLE_PK: Self::TableIden = TokenBlacklistIden::Id;

    type IdKind = Uuid;

    type Row = TokenBlacklistRow;

    fn db(&self) -> &Dbx {
        &self.db
    }

    fn has_audit_fields() -> bool {
        true
    }
}

impl Creatable for TokenBlacklistStore {
    type CreateStoreParams = TokenBlacklistCreate;
}

impl Readable for TokenBlacklistStore {}

impl Listable for TokenBlacklistStore {
    type FilterStoreParams = TokenBlacklistFilter;
}

impl DeletableMany for TokenBlacklistStore {}

impl Deletable for TokenBlacklistStore {}
