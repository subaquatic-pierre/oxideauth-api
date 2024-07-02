use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Role {
    id: Uuid,
    name: String,
    permissions: Vec<String>,
}

impl Default for Role {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "defaultRole".to_string(),
            permissions: vec!["users.getSelf".to_string()],
        }
    }
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct UserRoleBinding {
    pub user_id: Uuid,
    pub role_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Permission {
    pub id: Uuid,
    pub name: String,
}
