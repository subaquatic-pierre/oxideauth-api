use std::{collections::HashSet, sync::Arc};

use crate::{
    core::models::permission::{PermissionCheck, PermissionChecker},
    store::{dbx::PgDbx, manager::StoreManager},
};

pub struct AuthorizeService {
    sm: Arc<StoreManager<PgDbx>>,
}

impl AuthorizeService {
    pub fn new(sm: Arc<StoreManager<PgDbx>>) -> Self {
        Self { sm }
    }

    pub fn validate_perms<'a>(
        &self,
        granted: PermissionChecker<'a>,
        required: &[PermissionCheck<'a>],
    ) -> bool {
        let all_required_match_granted = granted.has_subset(required);
        all_required_match_granted
    }
}
