use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::models::{account::Account, role::Role, workspace::Workspace};

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

#[derive(Serialize, Deserialize)]
pub struct CachedMembership {
    pub id: Uuid,
    pub account_id: Uuid,
    pub workspace_id: Uuid,
    pub role_ids: Vec<Uuid>,
    pub permissions: Vec<String>,
}

pub struct MembershipCreateParams {}

pub struct MembershipDescribeParams {}
