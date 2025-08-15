use diesel::prelude::*;
use uuid::Uuid;

use crate::schema::{account_roles, accounts, roles};

// Minimal DB role (namespaced)
#[derive(Queryable, Identifiable, Debug, Clone)]
#[diesel(table_name = roles)]
pub struct DbRole {
    pub id: Uuid,
    pub namespace_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
