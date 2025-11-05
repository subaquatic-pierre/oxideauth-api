use std::sync::Arc;

use crate::{
    app::AppState,
    cache::traits::CacheExecutor,
    core::services::{
        account::AccountService,
        token::{TokenService, TokenServiceConfig},
        workspace::WorkspaceService,
    },
    store::{dbx::DbExecutor, manager::StoreManager},
};

pub struct ServiceFactory<D, C>
where
    D: DbExecutor,
    C: CacheExecutor,
{
    sm: Arc<StoreManager<D>>,
    cache: Arc<C>,
}

impl<D, C> ServiceFactory<D, C>
where
    D: DbExecutor,
    C: CacheExecutor,
{
    pub fn new(sm: Arc<StoreManager<D>>, cache: Arc<C>) -> Self {
        Self { sm, cache }
    }

    pub fn account(&self) -> AccountService<'_, D> {
        let svc = AccountService::new(&self.sm.account);
        svc
    }

    pub fn workspace(&self) -> WorkspaceService<'_, D> {
        let svc = WorkspaceService::new(&self.sm.workspace);
        svc
    }

    pub fn token(&self) -> TokenService<'_, D, C> {
        // TODO: get config from storage, first check cache, if not found then check database and update cache
        let config = TokenServiceConfig::default();
        let svc = TokenService::new(&self.sm.token_blacklist, self.cache.as_ref(), config);
        svc
    }
}
