use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::{
        iden::TableIden,
        token_blacklist::{
            TokenBlacklistCreate, TokenBlacklistFilter, TokenBlacklistRow, TokenBlacklistUpdate,
        },
    },
    stores::base::{
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
    type Id = Uuid;
    type Row = TokenBlacklistRow;

    const TABLE: TableIden = TableIden::TokenBlacklist;
    const HAS_AUDIT_FIELDS: bool = false;

    fn db(&self) -> &Dbx {
        &self.db
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
