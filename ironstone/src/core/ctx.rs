use std::str::FromStr;

use uuid::Uuid;

use crate::{
    core::models::{account::Account, workspace::Workspace},
    store::ctx::StoreCtx,
};

#[derive(Clone)]
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
