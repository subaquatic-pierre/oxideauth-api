use std::{collections::HashMap, sync::Arc};

use axum::{extract::Request, http::HeaderMap};
use tracing::info;

use crate::{
    cache::traits::CacheExecutor,
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        services::{account::AccountService, factory::ServiceFactory, token::TokenService},
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        manager::StoreManager,
        stores::token_blacklist::TokenBlacklistStore,
    },
};

pub struct CtxConfig {}

pub struct CtxService<D, C>
where
    D: DbExecutor,
    C: CacheExecutor,
{
    svc_build: Arc<ServiceFactory<D, C>>,
}

impl<D, C> CtxService<D, C>
where
    D: DbExecutor,
    C: CacheExecutor,
{
    pub fn new(svc_build: Arc<ServiceFactory<D, C>>, config: CtxConfig) -> Self {
        Self { svc_build }
    }

    pub async fn resolve_ctx(&self, headers: &HeaderMap) -> CoreResult<CoreCtx> {
        let token = match TokenService::<D, C>::token_str_from_req(&headers) {
            Some(t) => {
                let token_svc = self.svc_build.token();
                // if token exists and is in blacklist return unauthorized response
                if token_svc.is_blacklisted(t) {
                    return Err(CoreError::Auth("token blacklisted".to_string()));
                }
                Some(t)
            }
            None => None,
        };

        info!("TOKEN {token:?} - resolve_ctx");

        // TODO: return correct built context
        Ok(CoreCtx::new_test())
    }
}
