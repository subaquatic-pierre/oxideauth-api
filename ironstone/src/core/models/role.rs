use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::core::models::permission::{PermissionCheck, PermissionChecker};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Role {
    name: String,
    permissions: RolePermissions,
}

impl Role {
    pub fn new(name: &str, perms: &[PermissionCheck]) -> Self {
        Self {
            name: name.to_string(),
            permissions: RolePermissions::new(perms),
        }
    }

    pub fn permissions(&self) -> &RolePermissions {
        &self.permissions
    }

    pub fn extend_permissions(&mut self, perms: &[PermissionCheck]) {
        self.permissions.extend(perms);
    }

    pub fn remove_permissions(&mut self, perms: &[PermissionCheck]) {
        self.permissions.remove(perms);
    }

    pub fn build_permission_checker(&self) -> PermissionChecker {
        self.permissions.build_checker()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RolePermissions {
    perms: HashSet<PermissionCheck>,
}

impl RolePermissions {
    pub fn new(perms: &[PermissionCheck]) -> Self {
        let mut _self = Self {
            perms: HashSet::new(),
        };

        _self.extend(perms);

        _self
    }

    pub fn extend(&mut self, perms: &[PermissionCheck]) {
        for perm in perms {
            self.perms.insert(perm.clone());
        }
    }

    pub fn remove(&mut self, perms: &[PermissionCheck]) {
        for perm in perms {
            self.perms.remove(&perm);
        }
    }

    pub fn build_checker(&self) -> PermissionChecker {
        let size = self.perms.len();
        let mut perms: Vec<PermissionCheck> = Vec::with_capacity(size);
        for perm in self.perms.iter() {
            perms.push(perm.clone())
        }

        PermissionChecker::new(perms)
    }
}

impl Iterator for RolePermissions {
    type Item = PermissionCheck;

    fn next(&mut self) -> Option<Self::Item> {
        self.perms.iter().next().cloned()
    }
}
