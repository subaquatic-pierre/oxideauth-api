use std::sync::Arc;

use sqlx::PgPool;

use crate::store::{dbx::Dbx, error::Result, stores::account::AcCountable, DbPool};

pub struct StoreManager {
    dbx: Arc<Dbx>,

    // --- specific table stores
    account: AcCountable,
}

impl StoreManager {
    pub fn new(db: DbPool) -> Self {
        let dbx = Dbx::new(db);
        let dbx_c = Arc::new(dbx);
        let account = AcCountable::new(dbx_c.clone());

        Self {
            dbx: dbx_c.clone(),
            account,
        }
    }

    pub fn db(&self) -> Arc<Dbx> {
        self.dbx.clone()
    }
}
