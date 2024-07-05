use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RolePermissions {
    pub permissions: Vec<String>,
    #[serde(skip)]
    pub skip: bool,
    #[serde(skip)]
    pub index: usize,
}

impl RolePermissions {
    pub fn new(permissions: Vec<String>) -> Self {
        Self {
            permissions,
            skip: false,
            index: 0,
        }
    }
    pub fn should_skip(&self) -> bool {
        self.skip
    }
}

impl Iterator for RolePermissions {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.permissions.len() {
            let result = self.permissions[self.index].clone();
            self.index += 1;
            Some(result)
        } else {
            self.index = 0;
            None
        }
    }
}

impl<'a> IntoIterator for &'a RolePermissions {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.permissions.iter()
    }
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "RolePermissions::should_skip")]
    pub permissions: RolePermissions,
    pub description: Option<String>,
}

impl Role {
    pub fn new(name: &str, permissions: Vec<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            permissions: RolePermissions::new(permissions),
            description: None,
        }
    }

    pub fn id_str(&self) -> String {
        self.id.to_string()
    }

    pub fn set_skip_serialize_permissions(&mut self, val: bool) {
        self.permissions.skip = val;
    }
}

impl Default for Role {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "defaultRole".to_string(),
            permissions: RolePermissions::new(vec!["auth.users.getSelf".to_string()]),
            description: None,
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
