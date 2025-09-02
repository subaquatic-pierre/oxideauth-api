use std::sync::Arc;

use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::db::dbx::Dbx;

pub struct AccountStore {
    db: Arc<Dbx>,
}

impl AccountStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}
