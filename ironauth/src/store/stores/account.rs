use std::sync::Arc;

use modql::SIden;
use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::account::{AccountCreate, AccountFilter, AccountIden, AccountRow, AccountUpdate},
    traits::{
        crud::{Creatable, Deletable, DeletableMany, Listable, Readable, Updatable, UpdatableMany},
        meta::{Crud, CrudMeta, Store},
    },
};

pub struct AcCountable {
    db: Arc<Dbx>,
}

impl AcCountable {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl Store for AcCountable {
    type TableIden = AccountIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = AccountIden::Table;
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

impl Crud for AcCountable {
    type Iden = AccountIden;

    fn crud_meta(&self) -> CrudMeta<Self::Iden> {
        let meta = CrudMeta {
            table: AccountIden::Table,
            pk: AccountIden::Id,
            has_audit: true,
        };
        meta
    }
}

impl Creatable for AcCountable {
    type CreateStoreParams = AccountCreate;
}

impl Readable for AcCountable {}

impl Listable for AcCountable {
    type FilterStoreParams = AccountFilter;
}

impl Updatable for AcCountable {
    type UpdateStoreParams = AccountUpdate;
}

impl DeletableMany for AcCountable {}

impl UpdatableMany for AcCountable {
    type UpdateStoreParams = AccountUpdate;
}

impl Deletable for AcCountable {}
