use std::collections::HashSet;

use crate::core::models::permission::{Permission, PermissionCheck, PermissionChecker};

pub struct Role {
    name: String,
    permissions: RolePermissions,
}

impl Role {
    pub fn new(name: &str, perms: &[Permission]) -> Self {
        Self {
            name: name.to_string(),
            permissions: RolePermissions::new(perms),
        }
    }

    pub fn permissions(&self) -> &RolePermissions {
        &self.permissions
    }

    pub fn extend_permissions(&mut self, perms: &[Permission]) {
        self.permissions.extend(perms);
    }

    pub fn remove_permissions(&mut self, perms: &[Permission]) {
        self.permissions.remove(perms);
    }

    pub fn build_permission_checker(&self) -> PermissionChecker<'_> {
        self.permissions.build_checker()
    }
}

pub struct RolePermissions {
    perms: HashSet<Permission>,
}

impl RolePermissions {
    pub fn new(perms: &[Permission]) -> Self {
        let mut _self = Self {
            perms: HashSet::new(),
        };

        _self.extend(perms);

        _self
    }

    pub fn extend(&mut self, perms: &[Permission]) {
        for perm in perms {
            self.perms.insert(perm.clone());
        }
    }

    pub fn remove(&mut self, perms: &[Permission]) {
        for perm in perms {
            self.perms.remove(&perm);
        }
    }

    pub fn build_checker(&self) -> PermissionChecker<'_> {
        let size = self.perms.len();
        let mut perms: Vec<PermissionCheck> = Vec::with_capacity(size);
        for perm in self.perms.iter() {
            let perm_check: PermissionCheck = perm.to_check();
            perms.push(perm_check)
        }

        PermissionChecker::new(&perms)
    }
}

impl Iterator for RolePermissions {
    type Item = Permission;

    fn next(&mut self) -> Option<Self::Item> {
        self.perms.iter().next().cloned()
    }
}
