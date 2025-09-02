use std::sync::Arc;

use modql::SIden;
use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::db::{dbx::Dbx, stores::base::StoreMeta};

pub struct AccountStore {
    db: Arc<Dbx>,
}

impl AccountStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl StoreMeta for AccountStore {
    fn table_ref(&self) -> TableRef {
        TableRef::Table(SIden("accounts").into_iden())
    }

    fn db(&self) -> &Dbx {
        &self.db
    }

    fn has_audit(&self) -> bool {
        true
    }
}
