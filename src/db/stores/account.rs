use std::sync::Arc;

use uuid::Uuid;

use crate::db::dbx::Dbx;

struct AccountRow {
    id: Uuid,
    name: String,
}

struct AccountCreate {
    name: String,
}

struct AccountUpdate {
    name: Option<String>,
}

#[derive(Clone)]
pub struct AccountStore {
    db: Arc<Dbx>,
}

impl AccountStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}
