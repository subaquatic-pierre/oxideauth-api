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

pub struct AuthenticateService<'a, Dbx>
where
    Dbx: DbExecutor,
{
    acc_svc: &'a AccountService<'a, Dbx>,
    token_blacklist_store: &'a TokenBlacklistStore<Dbx>,
}

impl<'a, Dbx: DbExecutor> AuthenticateService<'a, Dbx> {
    pub fn new(
        acc_svc: &'a AccountService<'a, Dbx>,
        token_blacklist_store: &'a TokenBlacklistStore<Dbx>,
    ) -> Self {
        Self {
            acc_svc,
            token_blacklist_store,
        }
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
