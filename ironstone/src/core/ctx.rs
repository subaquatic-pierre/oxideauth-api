use std::str::FromStr;

use uuid::Uuid;

use crate::{
    core::models::{account::Account, namespace::Namespace},
    store::ctx::StoreCtx,
};

pub struct CoreCtx {
    pub account: Account,
    pub namespace: Namespace,
}

impl CoreCtx {
    pub fn new(account: Account, namespace: Namespace) -> Self {
        Self { account, namespace }
    }
}

impl From<CoreCtx> for StoreCtx {
    fn from(ctx: CoreCtx) -> Self {
        Self::new(ctx.account.id, ctx.namespace.id)
    }
}

impl From<&CoreCtx> for StoreCtx {
    fn from(ctx: &CoreCtx) -> Self {
        Self::new(ctx.account.id, ctx.namespace.id)
    }
}
