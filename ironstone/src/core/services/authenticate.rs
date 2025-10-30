use std::{collections::HashMap, sync::Arc};

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        services::account::AccountService,
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        manager::StoreManager,
        stores::token_blacklist::TokenBlacklistStore,
    },
};

pub struct AuthenticateService<Dbx: DbExecutor>
where
    Dbx: DbExecutor,
{
    store_manager: Arc<StoreManager<Dbx>>,
}

impl<Dbx: DbExecutor> AuthenticateService<Dbx> {
    pub fn new(store_manager: Arc<StoreManager<Dbx>>) -> Self {
        Self { store_manager }
    }

    pub async fn resolve_ctx(&self, token: Option<&str>) -> CoreResult<CoreCtx> {
        Ok(CoreCtx::new_test())
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
