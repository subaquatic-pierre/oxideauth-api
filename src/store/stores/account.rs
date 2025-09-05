use std::sync::Arc;

use modql::SIden;
use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::{
        account::{AccountCreate, AccountFilter, AccountRow, AccountUpdate},
        iden::TableIden,
    },
    stores::base::{
        CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, MetaStore, UpdateManyStore,
        UpdateStore,
    },
};

pub struct AccountStore {
    db: Arc<Dbx>,
}

impl AccountStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl MetaStore for AccountStore {
    type Id = Uuid;
    type Row = AccountRow;

    const TABLE: TableIden = TableIden::Account;
    const HAS_AUDIT_FIELDS: bool = true;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl CreateStore for AccountStore {
    type CreateStoreParams = AccountCreate;
}

impl GetStore for AccountStore {}

impl ListStore for AccountStore {
    type FilterStoreParams = AccountFilter;
}

impl UpdateStore for AccountStore {
    type UpdateStoreParams = AccountUpdate;
}

impl DeleteManyStore for AccountStore {}

impl UpdateManyStore for AccountStore {
    type UpdateStoreParams = AccountUpdate;
}

impl DeleteStore for AccountStore {}
