use std::str::FromStr;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    core::{
        error::CoreResult,
        models::{
            account::Account,
            workspace::{Workspace, GLOBAL_WS_ID},
        },
    },
    store::ctx::StoreCtx,
    utils::time::now_utc,
};

#[derive(Clone, Debug)]
pub struct CoreCtx {
    pub account: Account,
    pub workspace: Workspace,
}

impl CoreCtx {
    pub fn new(account: Account, workspace: Workspace) -> Self {
        Self { account, workspace }
    }

    pub fn new_test() -> Self {
        let ctx_acc = Account::default();
        let ctx_ns = Workspace::default();
        Self {
            account: ctx_acc,
            workspace: ctx_ns,
        }
    }

    pub fn workspace_id(&self) -> Uuid {
        self.workspace.id
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
