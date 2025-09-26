use std::sync::Arc;

use modql::SIden;
use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::account::{AccountCreate, AccountFilter, AccountIden, AccountRow, AccountUpdate},
    traits::{
        crud::{
            CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, UpdateManyStore,
            UpdateStore,
        },
        meta::{BaseMetaStore, CrudMetaStore, CrudQueryMeta},
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

impl BaseMetaStore for AccountStore {
    type TableIden = AccountIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = AccountIden::TableName;
    const TABLE_PK: Self::TableIden = AccountIden::Id;

    type IdKind = Uuid;

    type Row = AccountRow;

    fn db(&self) -> &Dbx {
        &self.db
    }

    fn has_audit_fields() -> bool {
        true
    }
}

impl CrudMetaStore for AccountStore {
    type Iden = AccountIden;

    fn crud_meta(&self) -> CrudQueryMeta<Self::Iden> {
        let meta = CrudQueryMeta {
            table: AccountIden::TableName,
            pk: AccountIden::Id,
            has_audit: true,
        };
        meta
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
