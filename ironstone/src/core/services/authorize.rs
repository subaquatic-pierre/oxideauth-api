use std::{collections::HashSet, sync::Arc};

use crate::{
    core::models::permission::{PermissionCheck, RolePermissions},
    store::manager::StoreManager,
};

pub struct AuthorizeService {
    sm: Arc<StoreManager>,
}

impl AuthorizeService {
    pub fn new(sm: Arc<StoreManager>) -> Self {
        Self { sm }
    }

    pub fn validate_perms<'a>(
        &self,
        granted: RolePermissions<'a>,
        required: HashSet<PermissionCheck<'a>>,
    ) -> bool {
        let all_required_match_granted = required.iter().all(|needed| granted.is_allowed(needed));
        all_required_match_granted
    }
}
