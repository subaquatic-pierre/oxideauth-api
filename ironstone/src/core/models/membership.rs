use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::models::{
    account::Account, permission::ALL_PERMISSIONS, role::Role, workspace::Workspace,
};

#[derive(Default)]
pub struct Membership {
    pub id: Uuid,
    account: Account,
    workspace: Workspace,
    roles: Vec<Role>,
}

impl Membership {
    pub fn new(account: Account, workspace: Workspace, roles: Vec<Role>) -> Self {
        Self {
            id: Uuid::new_v4(),
            account,
            workspace,
            roles,
        }
    }
}

#[derive(Serialize, Debug, Clone, Deserialize)]
pub struct CachedMembership {
    pub id: Uuid,
    pub account_id: Uuid,
    pub workspace_id: Uuid,
    pub role_ids: Vec<Uuid>,
    pub permissions: Vec<String>,
}

impl Default for CachedMembership {
    fn default() -> Self {
        let permissions = ALL_PERMISSIONS.iter().map(|el| el.to_string()).collect();

        Self {
            id: Default::default(),
            account_id: Default::default(),
            workspace_id: Default::default(),
            role_ids: Default::default(),
            permissions,
        }
    }
}

pub struct MembershipCreateParams {}

pub struct MembershipDescribeParams {}
