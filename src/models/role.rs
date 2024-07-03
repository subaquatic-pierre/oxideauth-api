use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub permissions: Vec<String>,
}

impl Role {
    pub fn new(name: &str, permissions: Vec<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            permissions,
        }
    }

    pub fn id_str(&self) -> String {
        self.id.to_string()
    }
}

impl Default for Role {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "defaultRole".to_string(),
            permissions: vec!["auth.users.getSelf".to_string()],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRoleBinding {
    pub user_id: Uuid,
    pub role_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Permission {
    pub id: Uuid,
    pub name: String,
}

impl Permission {
    pub fn new(name: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
        }
    }
}
