use std::{collections::HashSet, sync::Arc};

use uuid::Uuid;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::permission::{PermissionCheck, PermissionChecker},
        services::account::AccountService,
    },
    store::{dbx::PgDbx, manager::StoreManager, traits::dbx::DbExecutor},
};

pub struct AuthService<D>
where
    D: DbExecutor,
{
    acc_svc: AccountService<D>,
}

impl<D: DbExecutor> AuthService<D> {
    pub fn new(acc_svc: AccountService<D>) -> Self {
        Self { acc_svc }
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

pub struct AuthValidator {}

impl AuthValidator {
    pub fn validate_perms<'b>(
        granted: PermissionChecker<'b>,
        required: &[PermissionCheck<'b>],
    ) -> bool {
        let all_required_match_granted = granted.has_subset(required);
        all_required_match_granted
    }

    pub fn validate_workspace<'b>(
        ctx: &CoreCtx,
        workspace_id: Option<Uuid>,
    ) -> CoreResult<Option<Uuid>> {
        let is_global_context = ctx.is_global_workspace()?;

        if (is_global_context) {
            return Ok(workspace_id);
        }

        if (!is_global_context && workspace_id.is_none()) {
            return Err(CoreError::Auth("workspace_id required".to_string()));
        }

        // check membership workspace_id matches requested workspace_id

        Err(CoreError::Auth("invalid workspace".to_string()))
    }
}
