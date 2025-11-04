use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
};

use crate::{
    cache::traits::CacheExecutor,
    store::{dbx::DbExecutor, stores::token_blacklist::TokenBlacklistStore},
};

pub struct TokenService<'a, D: DbExecutor, C: CacheExecutor> {
    token_blacklist_store: &'a TokenBlacklistStore<D>,
    cache: &'a C,
}

impl<'a, D, C> TokenService<'a, D, C>
where
    D: DbExecutor,
    C: CacheExecutor,
{
    pub fn new(token_blacklist_store: &'a TokenBlacklistStore<D>, cache: &'a C) -> Self {
        Self {
            token_blacklist_store,
            cache,
        }
    }

    pub fn is_blacklisted(&self, token: &str) -> bool {
        // TODO: check token against cache
        return false;
    }

    pub fn token_from_req<'b>(headers: &'b HeaderMap) -> Option<&'b str> {
        let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());

        let token = match auth_header {
            Some(str) => {
                let mut iter = str.split(" ").into_iter();

                let start = iter.next();
                let token = iter.next();
                token
            }
            None => None,
        };

        token
    }
}
