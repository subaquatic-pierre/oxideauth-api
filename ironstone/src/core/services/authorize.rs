use std::{collections::HashSet, sync::Arc};

use crate::{
    core::{
        models::permission::{PermissionCheck, PermissionChecker},
        services::account::AccountService,
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        manager::StoreManager,
    },
};

pub struct AuthorizeService<'a, Dbx>
where
    Dbx: DbExecutor,
{
    acc_svc: &'a AccountService<'a, Dbx>,
}

impl<'a, Dbx: DbExecutor> AuthorizeService<'a, Dbx> {
    pub fn new(acc_svc: &'a AccountService<'a, Dbx>) -> Self {
        Self { acc_svc }
    }

    pub fn validate_perms<'b>(
        &self,
        granted: PermissionChecker<'b>,
        required: &[PermissionCheck<'b>],
    ) -> bool {
        let all_required_match_granted = granted.has_subset(required);
        all_required_match_granted
    }
}
