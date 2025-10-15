use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
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

    pub fn contains(&self, val: &String) -> bool {
        self.permissions.contains(val)
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

#[derive(Debug, Serialize, Deserialize, FromRow, Clone, PartialEq)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "RolePermissions::should_skip")]
    pub permissions: RolePermissions,
    // #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Role {
    pub fn new(name: &str, permissions: Vec<String>, description: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            permissions: RolePermissions::new(permissions),
            description,
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

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_role_permissions_new() {
        let permissions = vec!["read".to_string(), "write".to_string()];
        let role_permissions = RolePermissions::new(permissions.clone());

        assert_eq!(role_permissions.permissions, permissions);
        assert_eq!(role_permissions.should_skip(), false);
    }

    #[test]
    fn test_role_permissions_contains() {
        let permissions = vec!["read".to_string(), "write".to_string()];
        let role_permissions = RolePermissions::new(permissions);

        assert!(role_permissions.contains(&"read".to_string()));
        assert!(!role_permissions.contains(&"delete".to_string()));
    }

    #[test]
    fn test_role_permissions_iterator() {
        let permissions = vec!["read".to_string(), "write".to_string()];
        let mut role_permissions = RolePermissions::new(permissions);

        assert_eq!(role_permissions.next(), Some("read".to_string()));
        assert_eq!(role_permissions.next(), Some("write".to_string()));
        assert_eq!(role_permissions.next(), None);
    }

    #[test]
    fn test_role_new() {
        let name = "Admin";
        let permissions = vec!["read".to_string(), "write".to_string()];
        let description = Some("Administrator role".to_string());

        let role = Role::new(name, permissions.clone(), description.clone());

        assert_eq!(role.name, name);
        assert_eq!(role.permissions.permissions, permissions);
        assert_eq!(role.description, description);
    }

    #[test]
    fn test_role_id_str() {
        let role = Role::default();

        assert_eq!(role.id_str().len(), 36); // UUID length
    }

    #[test]
    fn test_role_set_skip_serialize_permissions() {
        let mut role = Role::default();

        assert_eq!(role.permissions.should_skip(), false);

        role.set_skip_serialize_permissions(true);
        assert_eq!(role.permissions.should_skip(), true);
    }

    #[test]
    fn test_user_role_binding() {
        let user_id = Uuid::new_v4();
        let role_id = Uuid::new_v4();

        let binding = UserRoleBinding { user_id, role_id };

        assert_eq!(binding.user_id, user_id);
        assert_eq!(binding.role_id, role_id);
    }

    #[test]
    fn test_permission_new() {
        let name = "read";
        let permission = Permission::new(name);

        assert_eq!(permission.name, name);
        assert_eq!(permission.id.to_string().len(), 36); // UUID length
    }
}
