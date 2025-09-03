use std::sync::Arc;

use modql::SIden;
use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::account::{AccountCreate, AccountFilter, AccountRow, AccountUpdate},
    stores::base::StoreMeta,
};

pub struct AccountStore {
    db: Arc<Dbx>,
}

impl AccountStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl StoreMeta for AccountStore {
    const TABLE: &'static str = "accounts";

    #[doc = " Whether this table has the standard audit fields."]
    const HAS_AUDIT_FIELDS: bool = true;

    type Id = Uuid;
    type Row = AccountRow;
    type CreateParams = AccountCreate;
    type UpdateParams = AccountUpdate;
    type FilterParams = AccountFilter;

    fn db(&self) -> &Dbx {
        &self.db
    }
}
