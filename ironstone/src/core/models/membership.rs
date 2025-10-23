use uuid::Uuid;

use crate::core::models::{account::Account, role::Role, workspace::Workspace};

pub struct Membership {
    account: Account,
    workspace: Workspace,
    roles: Vec<Role>,
}

impl Membership {}
