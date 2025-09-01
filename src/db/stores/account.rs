use std::sync::Arc;

use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::db::dbx::Dbx;

#[derive(Debug, FromRow)]
pub struct AccountRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub acc_type: String,
    pub provider: String,
    pub provider_id: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub verified: bool,
    pub enabled: bool,
}

struct AccountCreate {
    name: String,
}

struct AccountUpdate {
    name: Option<String>,
}

pub struct AccountStore {
    db: Arc<Dbx>,
}

impl AccountStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}
