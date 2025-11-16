use uuid::Uuid;

use crate::core::models::{account::Account, role::Role, workspace::Workspace};

#[derive(Default)]
pub struct Membership {
    pub id: Uuid,
    account: Account,
    workspace: Workspace,
    roles: Vec<Role>,
}

impl Membership {}

pub struct MembershipCreateParams {}

pub struct MembershipDescribeParams {}
