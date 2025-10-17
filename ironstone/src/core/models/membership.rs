use uuid::Uuid;

use crate::core::models::{account::Account, namespace::Namespace, role::Role};

pub struct Membership {
    account: Account,
    namespace: Namespace,
    roles: Vec<Role>,
}

impl Membership {}
