use std::str::FromStr;

use uuid::Uuid;

use crate::store::ctx::StoreCtx;

pub struct CoreCtx {
    pub user_id: Uuid,
    pub ns_id: Uuid,
}

impl CoreCtx {
    pub fn new(user_id: Uuid, ns_id: Uuid) -> Self {
        Self { user_id, ns_id }
    }

    pub fn new_root() -> Self {
        let root_user_id: Uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let root_namespace_id: Uuid =
            Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap();

        Self {
            user_id: root_user_id,
            ns_id: root_namespace_id,
        }
    }
}

impl From<CoreCtx> for StoreCtx {
    fn from(ctx: CoreCtx) -> Self {
        Self::new(ctx.user_id, ctx.ns_id)
    }
}

impl From<&CoreCtx> for StoreCtx {
    fn from(ctx: &CoreCtx) -> Self {
        Self::new(ctx.user_id, ctx.ns_id)
    }
}
