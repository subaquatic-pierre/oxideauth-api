use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
};

use crate::store::{dbx::DbExecutor, stores::token_blacklist::TokenBlacklistStore};

pub struct TokenService<'a, Dbx: DbExecutor> {
    token_blacklist_store: &'a TokenBlacklistStore<Dbx>,
}

impl<'a, Dbx: DbExecutor> TokenService<'a, Dbx> {
    pub fn new(token_blacklist_store: &'a TokenBlacklistStore<Dbx>) -> Self {
        Self {
            token_blacklist_store,
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
