use std::sync::Arc;

use crate::{
    app::AppState,
    cache::{manager::CacheManager, traits::CacheExecutor},
    core::services::{
        account::AccountService,
        auth::AuthService,
        token::{TokenService, TokenServiceConfig},
        workspace::WorkspaceService,
    },
    store::{manager::StoreManager, traits::dbx::DbExecutor},
};

pub struct ServiceFactory<D, C>
where
    D: DbExecutor,
    C: CacheExecutor,
{
    sm: Arc<StoreManager<D>>,
    cm: Arc<CacheManager<C>>,
}

impl<D, C> ServiceFactory<D, C>
where
    D: DbExecutor,
    C: CacheExecutor,
{
    pub fn new(sm: Arc<StoreManager<D>>, cm: Arc<CacheManager<C>>) -> Self {
        Self { sm, cm }
    }

    pub fn account(&self) -> AccountService<D> {
        let svc = AccountService::new(self.sm.clone());
        svc
    }

    pub fn workspace(&self) -> WorkspaceService<D> {
        let svc = WorkspaceService::new(self.sm.clone());
        svc
    }

    pub fn auth(&self) -> AuthService<D> {
        let acc_svc = self.account();
        let svc = AuthService::new(acc_svc);
        svc
    }

    pub fn token(&self) -> TokenService<D, C> {
        // TODO: get config from storage, first check cache, if not found then check database and update cache
        let config = TokenServiceConfig::default();
        let svc = TokenService::new(self.sm.clone(), self.cm.clone(), config);
        svc
    }
}
