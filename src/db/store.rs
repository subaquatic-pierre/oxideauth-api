use std::sync::Arc;

use sqlx::PgPool;

use crate::db::{dbx::Dbx, error::Result, stores::account::AccountStore, DbPool};

#[derive(Clone)]
pub struct DataStore {
    dbx: Arc<Dbx>,

    // --- specific table stores
    account: AccountStore,
}

impl DataStore {
    pub fn new(db_pool: DbPool) -> Self {
        let dbx = Dbx::new(db_pool, false);
        let dbx_c = Arc::new(dbx);
        let account = AccountStore::new(dbx_c.clone());

        Self {
            dbx: dbx_c.clone(),
            account,
        }
    }

    pub fn db(&self) -> &DbPool {
        self.dbx.db()
    }
}
