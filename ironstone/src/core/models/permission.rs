use std::collections::{HashMap, HashSet};

use crate::core::error::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Permission {
    resource: String,
    action: String,
}

impl Permission {
    pub fn to_check(&self) -> PermissionCheck {
        PermissionCheck {
            resource: self.resource.clone(),
            action: self.action.clone(),
        }
    }
}

impl TryFrom<String> for Permission {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for Permission {
    type Error = CoreError;

    // Parses a string like "projects:create" into the struct.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
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
                Ok(Self {
                    resource: resource.to_string(),
                    action: action.to_string(),
                })
            }
        } else {
            Err(CoreError::ParseError(
                "Permission string must contain a ':' delimiter.".to_string(),
            ))
        }
    }
}

pub struct PermissionChecker {
    // Key: resource name (e.g., "projects").
    // Value: Set of actions for that resource (e.g., {"*", "read"}).
    granted: HashMap<String, HashSet<String>>,
}

impl PermissionChecker {
    pub fn new(perms: Vec<PermissionCheck>) -> Self {
        let mut _self = Self {
            granted: HashMap::new(),
        };
        _self.extend(perms);
        _self
    }

    pub fn from_str_slice(perms: &[&str]) -> CoreResult<PermissionChecker> {
        let perms: CoreResult<Vec<PermissionCheck>> = perms
            .iter()
            .map(|&el| PermissionCheck::try_from(el))
            .collect();

        let perms = perms?;

        let checker = PermissionChecker::new(perms);

        Ok(checker)
    }

    pub fn new_perms(perms: &[&str]) -> CoreResult<Vec<PermissionCheck>> {
        let perms: CoreResult<Vec<PermissionCheck>> = perms
            .iter()
            .map(|&el| PermissionCheck::try_from(el))
            .collect();

        perms
    }

    pub fn extend(&mut self, perms: Vec<PermissionCheck>) {
        for perm in perms {
            if let Some(resource) = self.granted.get_mut(&perm.resource) {
                resource.insert(perm.action);
            } else {
                self.granted.insert(perm.resource, HashSet::new());
            }
        }
    }

    pub fn has_subset(&self, required: &[PermissionCheck]) -> bool {
        required.iter().all(|needed| self.is_allowed(needed))
    }

    pub fn is_allowed(&self, required: &PermissionCheck) -> bool {
        // Check for a global resource wildcard first, e.g., "*:delete"
        if let Some(actions) = self.granted.get("*") {
            if actions.contains("*") || actions.contains(&required.action) {
                return true;
            }
        }

        // Check for a specific resource, e.g., "projects:*" or "projects:delete"
        if let Some(actions) = self.granted.get(&required.resource) {
            if actions.contains("*") || actions.contains(&required.action) {
                return true;
            }
        }

        false
    }
}

// A lightweight, in-memory representation of a permission to be checked.
// It implements parsing and can be created from multiple sources.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PermissionCheck {
    pub resource: String,
    pub action: String,
}

impl PermissionCheck {
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
        self.matches_str(&self.action, &perm.action)
            && self.matches_str(&self.resource, &perm.resource)
    }
}

impl TryFrom<&str> for PermissionCheck {
    type Error = CoreError;

    // Parses a string like "projects:create" into the struct.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
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
                Ok(PermissionCheck {
                    resource: resource.to_string(),
                    action: action.to_string(),
                })
            }
        } else {
            Err(CoreError::ParseError(
                "Permission string must contain a ':' delimiter.".to_string(),
            ))
        }
    }
}
