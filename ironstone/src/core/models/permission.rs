use std::collections::{HashMap, HashSet};

use crate::core::error::CoreError;

pub struct RolePermissions<'a> {
    // Key: resource name (e.g., "projects").
    // Value: Set of actions for that resource (e.g., {"*", "read"}).
    granted: HashMap<&'a str, HashSet<&'a str>>,
}

impl<'a> RolePermissions<'a> {
    pub fn new(perms: HashSet<PermissionCheck<'a>>) -> Self {
        let mut granted: HashMap<&str, HashSet<&str>> = HashMap::new();

        for perm in perms {
            if let Some(resource) = granted.get_mut(perm.resource) {
                resource.insert(perm.action);
            } else {
                granted.insert(perm.resource, HashSet::new());
            }
        }

        Self { granted }
    }

    pub fn is_allowed(&self, required: &PermissionCheck) -> bool {
        // Check for a global resource wildcard first, e.g., "*:delete"
        if let Some(actions) = self.granted.get("*") {
            if actions.contains("*") || actions.contains(required.action) {
                return true;
            }
        }

        // Check for a specific resource, e.g., "projects:*" or "projects:delete"
        if let Some(actions) = self.granted.get(required.resource) {
            if actions.contains("*") || actions.contains(required.action) {
                return true;
            }
        }

        false
    }
}

// A lightweight, in-memory representation of a permission to be checked.
// It implements parsing and can be created from multiple sources.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PermissionCheck<'a> {
    pub resource: &'a str,
    pub action: &'a str,
}

impl<'a> PermissionCheck<'a> {
    fn matches_str(&self, granted: &str, required: &str) -> bool {
        if required == "*" || granted == "*" {
            return true;
        }

        if granted == required {
            return true;
        }

        return false;
    }

    /// Checks if this pattern matches a required permission.
    /// `self` represents the granted pattern (e.g., from the user's roles).
    /// `required_resource` and `required_action` are the specific permissions
    /// being checked (e.g., "projects", "delete").
    pub fn matches(&self, perm: &PermissionCheck) -> bool {
        self.matches_str(self.action, perm.action) && self.matches_str(self.resource, perm.resource)
    }
}

impl<'a> TryFrom<&'a str> for PermissionCheck<'a> {
    type Error = CoreError;

    // Parses a string like "projects:create" into the struct.
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        // Find the position of the first ':'
        if let Some(index) = value.find(':') {
            let (resource, action_with_colon) = value.split_at(index);
            // The action part includes the colon, so we slice it off.
            let action = &action_with_colon[1..];

            if resource.is_empty() || action.is_empty() {
                Err(CoreError::ParseError(
                    "Permission string cannot have empty parts.".to_string(),
                ))
            } else {
                Ok(PermissionCheck { resource, action })
            }
        } else {
            Err(CoreError::ParseError(
                "Permission string must contain a ':' delimiter.".to_string(),
            ))
        }
    }
}
