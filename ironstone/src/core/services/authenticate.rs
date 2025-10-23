use crate::{
    core::{
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

    // Methods use the stored dependency via `self`.
    pub async fn register_account(&self, email: &str, password: &str) -> CoreResult<()> {
        // The method signature is clean and focused on its own logic.
        Ok(())
    }

    pub async fn black_list_token(&self, email: &str, password: &str) -> CoreResult<()> {
        // The method signature is clean and focused on its own logic.
        Ok(())
    }

    pub async fn revoke_token(&self, email: &str, password: &str) -> CoreResult<()> {
        // The method signature is clean and focused on its own logic.
        Ok(())
    }

    pub async fn refresh_token(&self, email: &str, password: &str) -> CoreResult<()> {
        // The method signature is clean and focused on its own logic.
        Ok(())
    }
}
