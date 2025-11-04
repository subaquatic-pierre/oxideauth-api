use std::sync::Arc;

use crate::{
    app::AppState,
    core::services::{account::AccountService, token::TokenService},
    store::{dbx::DbExecutor, manager::StoreManager},
};

pub struct ServiceFactory<Dbx: DbExecutor> {
    sm: Arc<StoreManager<Dbx>>,
}

impl<Dbx: DbExecutor> ServiceFactory<Dbx> {
    pub fn new(sm: Arc<StoreManager<Dbx>>) -> Self {
        Self { sm }
    }

    pub fn account(&self) -> AccountService<'_, Dbx> {
        let svc = AccountService::new(&self.sm.account);
        svc
    }

    pub fn token(&self) -> TokenService<'_, Dbx> {
        let svc = TokenService::new(&self.sm.token_blacklist);
        svc
    }
}
