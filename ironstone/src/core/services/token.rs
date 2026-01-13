use sqlx;
use std::{sync::Arc, time::Duration};
use tracing::{debug, info};

use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use tokio::{task::JoinHandle, time::interval};

use crate::{
    cache::{manager::CacheManager, traits::CacheExecutor},
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::{
            list::ListResponse,
            token::{
                Token, TokenClaims, TokenCreateParams, TokenDeleteParams, TokenDescribeParams,
                TokenListParams,
            },
        },
        services::{auth::AuthValidator, workspace::WorkspaceService},
        traits::service::{
            CoreModelCreateService, CoreModelDeleteService, CoreModelDescribeService,
            CoreModelListService, CoreModelService,
        },
    },
    store::{manager::StoreManager, stores::token::TokenStore, traits::dbx::DbExecutor, PgPool},
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

pub struct TokenService<D: DbExecutor, C: CacheExecutor> {
    sm: Arc<StoreManager<D>>,
    cm: Arc<CacheManager<C>>,
    ws_svc: WorkspaceService<D>,
    config: TokenServiceConfig,
}

impl<D, C> TokenService<D, C>
where
    D: DbExecutor,
    C: CacheExecutor,
{
    pub fn new(
        sm: Arc<StoreManager<D>>,
        cm: Arc<CacheManager<C>>,
        ws_svc: WorkspaceService<D>,
        config: TokenServiceConfig,
    ) -> Self {
        Self {
            sm,
            cm,
            config,
            ws_svc,
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

    fn gen_token_exp_time(&self) -> usize {
        let now = now_utc();
        let expire_duration = Duration::from_secs(self.config.jwt_max_age);
        let future_time = now + expire_duration;
        future_time.unix_timestamp_nanos() as usize
    }

    pub fn is_token_exp(token: &TokenClaims) -> bool {
        token.is_expired()
    }

    pub fn token_str_from_headers<'b>(headers: &'b HeaderMap) -> Option<&'b str> {
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

impl<D: DbExecutor, C: CacheExecutor> CoreModelService<D> for TokenService<D, C> {
    type CoreModel = Token;
    type ServiceStore = TokenStore<D>;

    fn store(&self) -> &Self::ServiceStore {
        &self.sm.token
    }

    fn ws_svc(&self) -> &WorkspaceService<D> {
        &self.ws_svc
    }
}

impl<D: DbExecutor, C: CacheExecutor> CoreModelCreateService<D> for TokenService<D, C> {
    type CreateParams = TokenCreateParams;
    const CREATE_PERMISSION: &'static str = "token:create";

    async fn create(
        &self,
        _ctx: &mut CoreCtx,
        _params: Self::CreateParams,
    ) -> CoreResult<Self::CoreModel> {
        // TODO: Logic to generate secure token, store in DB, and optionally prime the cache
        todo!()
    }
}

impl<D: DbExecutor, C: CacheExecutor> CoreModelDescribeService<D> for TokenService<D, C> {
    type DescribeParams = TokenDescribeParams;
    const DESCRIBE_PERMISSION: &'static str = "token:describe";

    async fn describe(
        &self,
        _ctx: &mut CoreCtx,
        _params: Self::DescribeParams,
    ) -> CoreResult<Self::CoreModel> {
        // TODO: Logic to check CacheManager first (C), fallback to StoreManager (D)
        todo!()
    }
}

impl<D: DbExecutor, C: CacheExecutor> CoreModelListService<D> for TokenService<D, C> {
    type ListParams = TokenListParams;
    const LIST_PERMISSION: &'static str = "token:list";

    async fn list(
        &self,
        _ctx: &mut CoreCtx,
        _params: Self::ListParams,
    ) -> CoreResult<ListResponse<Self::CoreModel>> {
        // TODO: Implement paginated list from Database
        todo!()
    }
}

impl<D: DbExecutor, C: CacheExecutor> CoreModelDeleteService<D> for TokenService<D, C> {
    type DeleteParams = TokenDeleteParams;
    const DELETE_PERMISSION: &'static str = "token:delete";

    async fn delete(
        &self,
        _ctx: &mut CoreCtx,
        _params: Self::DeleteParams,
    ) -> CoreResult<Self::CoreModel> {
        // TODO: Remove from database and purge from cache
        todo!()
    }
}
