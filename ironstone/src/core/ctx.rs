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

    #[cfg(test)]
    pub fn new_test() -> Self {
        let ctx_acc = Account::default();
        let ctx_ns = Namespace::default();
        Self {
            account: ctx_acc,
            namespace: ctx_ns,
        }
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
