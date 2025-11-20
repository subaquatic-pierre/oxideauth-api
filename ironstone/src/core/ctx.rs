use std::ops::Deref;
use std::str::FromStr;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    core::{
        error::CoreResult,
        models::{
            account::Account,
            membership::CachedMembership,
            permission::{PermissionCheck, PermissionChecker},
            workspace::{Workspace, GLOBAL_WS_ID},
        },
    },
    store::ctx::StoreCtx,
    utils::time::now_utc,
};

#[derive(Clone, Debug)]
pub struct CoreCtx {
    pub cached_mem: CachedMembership,
    pub account: Account,
    pub workspace: Workspace,
}

impl CoreCtx {
    pub fn new(cached_mem: CachedMembership, account: Account, workspace: Workspace) -> Self {
        Self {
            cached_mem,
            account,
            workspace,
        }
    }

    pub fn new_test() -> Self {
        let ctx_acc = Account::default();
        let ctx_ns = Workspace::default();
        let cm = CachedMembership::default();
        Self {
            cached_mem: cm,
            account: ctx_acc,
            workspace: ctx_ns,
        }
    }

    pub fn permission_checker(&self) -> CoreResult<PermissionChecker> {
        // 1. Convert the owned Vec<String> to a temporary Vec<&str>.
        // This vector is owned by this function, but the references *inside* // point safely back to the String data owned by `self.cached_mem.permissions`.
        let perms_slice_vec: Vec<&str> = self
            .cached_mem
            .permissions
            .iter()
            .map(|s| s.as_str())
            .collect();

        // 2. The critical step: Call the validator with the slice reference.
        // The lifetime of the result is tied to the lifetime of the data that
        // `perms_slice_vec` references (the content of `self.cached_mem.permissions`, which lives as long as `self`).
        let cached_perms = PermissionChecker::from_str_slice(perms_slice_vec.deref())?;

        // 3. Return the checker. The compiler knows that the references inside
        // `cached_perms` point to data that lives as long as `self`, satisfying the `PermissionChecker<'_>` return signature.
        Ok(cached_perms)
    }

    pub fn workspace_id(&self) -> Uuid {
        self.cached_mem.workspace_id
    }

    pub fn is_global_workspace(&self) -> CoreResult<bool> {
        let global_ws_id = Uuid::try_parse(GLOBAL_WS_ID)?;
        Ok(self.workspace.id == global_ws_id)
    }
}

impl From<CoreCtx> for StoreCtx {
    fn from(ctx: CoreCtx) -> Self {
        Self::new(ctx.account.id, ctx.workspace.id)
    }
}

impl From<&CoreCtx> for StoreCtx {
    fn from(ctx: &CoreCtx) -> Self {
        Self::new(ctx.account.id, ctx.workspace.id)
    }
}
