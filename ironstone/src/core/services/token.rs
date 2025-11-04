use std::time::Duration;

use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use tracing::debug;

use crate::{
    cache::traits::CacheExecutor,
    core::{
        error::{CoreError, CoreResult},
        models::token::TokenClaims,
    },
    store::{dbx::DbExecutor, stores::token_blacklist::TokenBlacklistStore},
    utils::time::now_utc,
};

pub struct TokenServiceConfig {
    jwt_secret: String,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    jwt_max_age: u64,
    algo: Validation,
}

impl Default for TokenServiceConfig {
    fn default() -> Self {
        let jwt_secret = "***REMOVED***".to_string();
        let jwt_max_age = 86400;
        let jwt_secret_bytes = jwt_secret.as_bytes();
        let encoding_key = EncodingKey::from_secret(&jwt_secret_bytes);
        let decoding_key = DecodingKey::from_secret(&jwt_secret_bytes);
        let algo = Validation::new(Algorithm::HS256);
        Self {
            jwt_secret,
            jwt_max_age,
            encoding_key,
            decoding_key,
            algo,
        }
    }
}

pub struct TokenService<'a, D: DbExecutor, C: CacheExecutor> {
    token_blacklist_store: &'a TokenBlacklistStore<D>,
    cache: &'a C,
    config: TokenServiceConfig,
}

impl<'a, D, C> TokenService<'a, D, C>
where
    D: DbExecutor,
    C: CacheExecutor,
{
    pub fn new(
        token_blacklist_store: &'a TokenBlacklistStore<D>,
        cache: &'a C,
        config: TokenServiceConfig,
    ) -> Self {
        Self {
            token_blacklist_store,
            cache,
            config,
        }
    }

    pub fn is_blacklisted(&self, token: &TokenClaims) -> bool {
        // TODO: check token against cache
        return false;
    }

    pub fn decode_token_str(&self, token_str: &str) -> CoreResult<TokenClaims> {
        let data = decode::<TokenClaims>(&token_str, &self.config.decoding_key, &self.config.algo)?;

        debug!(
            "TokenClaims in TokenService.decode_token_str: {:?}",
            data.claims
        );

        Ok(data.claims)
    }

    pub fn token_header(&self) -> Header {
        Header::default()
    }

    pub fn encode_token_claims(&self, claims: &TokenClaims) -> CoreResult<String> {
        let token = encode(&Header::default(), &claims, &self.config.encoding_key)?;

        Ok(token)
    }

    fn gen_token_exp_time(max_age: u64) -> usize {
        let now = now_utc();
        let expire_duration = Duration::from_secs(max_age);
        let future_time = now + expire_duration;
        future_time.unix_timestamp_nanos() as usize
    }

    pub fn is_token_exp(token: &TokenClaims) -> bool {
        let now = now_utc().unix_timestamp() as usize;
        if token.exp < now {
            true
        } else {
            false
        }
    }

    pub fn token_str_from_req<'b>(headers: &'b HeaderMap) -> Option<&'b str> {
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
