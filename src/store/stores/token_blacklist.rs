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
    traits::crud::{
        CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, MetaStore, UpdateManyStore,
        UpdateStore,
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

impl MetaStore for TokenBlacklistStore {
    type TableIden = TokenBlacklistIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = TokenBlacklistIden::TableName;
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

impl CreateStore for TokenBlacklistStore {
    type CreateStoreParams = TokenBlacklistCreate;
}

impl GetStore for TokenBlacklistStore {}

impl ListStore for TokenBlacklistStore {
    type FilterStoreParams = TokenBlacklistFilter;
}

impl DeleteManyStore for TokenBlacklistStore {}

impl DeleteStore for TokenBlacklistStore {}
