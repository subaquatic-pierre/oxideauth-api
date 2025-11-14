use std::{collections::HashSet, sync::Arc};

use crate::{
    core::{
        ctx::CoreCtx,
        error::CoreResult,
        models::permission::{PermissionCheck, PermissionChecker},
        services::account::AccountService,
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        manager::StoreManager,
    },
};

pub struct AuthorizeService<D>
where
    D: DbExecutor,
{
    acc_svc: AccountService<D>,
}

impl<D: DbExecutor> AuthorizeService<D> {
    pub fn new(acc_svc: AccountService<D>) -> Self {
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

    pub async fn register_account(&self, ctx: &CoreCtx) -> CoreResult<()> {
        Ok(())
    }

    pub async fn black_list_token(&self, ctx: &CoreCtx) -> CoreResult<()> {
        Ok(())
    }

    pub async fn revoke_token(&self, ctx: &CoreCtx) -> CoreResult<()> {
        Ok(())
    }

    pub async fn refresh_token(&self, ctx: &CoreCtx) -> CoreResult<()> {
        Ok(())
    }

    pub async fn request_token(&self, ctx: &CoreCtx) -> CoreResult<()> {
        Ok(())
    }
}
