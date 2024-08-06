use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, Responder};
use log::{debug, error, info};
use sqlx::{Error, PgPool, Pool};

use crate::{
    db::queries::{
        account::get_account_db,
        role::{get_role_db, get_role_permissions_db},
    },
    models::{api::ApiError, token::TokenType},
    utils::token::{get_token_from_req, is_token_exp},
};

use super::{account::Account, api::ApiResult, token::TokenClaims};

pub struct AuthGuard {
    jwt_secret: String,
    pub db: Arc<PgPool>,
}

impl AuthGuard {
    pub fn new(jwt_secret: &str, db: Arc<PgPool>) -> Self {
        Self {
            jwt_secret: jwt_secret.to_string(),
            db,
        }
    }

    pub async fn get_token_claims(&self, token_str: &str) -> ApiResult<TokenClaims> {
        let claims = match TokenClaims::from_str(self.jwt_secret.as_ref(), &token_str) {
            Ok(claims) => claims,
            Err(e) => {
                error!("Error building TokenClaims from string, {:?}", e);
                return Err(e);
            }
        };

        Ok(claims)
    }

    pub async fn authorize_req(
        &self,
        req: &HttpRequest,
        required_perms: &[&str],
    ) -> ApiResult<TokenClaims> {
        // check user exists in DB

        let token_str = match get_token_from_req(&req) {
            Some(token) => token,
            None => return Err(ApiError::new("Unable to get token from request", 400)),
        };

        // info!("Token: {token_str:?}");

        let claims = match TokenClaims::from_str(self.jwt_secret.as_ref(), &token_str) {
            Ok(claims) => claims,
            Err(e) => {
                error!("Error building TokenClaims from string, {:?}", e);
                return Err(e);
            }
        };

        // info!("Token Claims: {claims:?}");

        // TODO: validate token expiry
        if is_token_exp(&claims) {
            return Err(ApiError::new("Token is expired", 403));
        }

        // check token type
        if claims.token_type != TokenType::Auth {
            return Err(ApiError::new("Invalid token type", 403));
        }

        let account = match get_account_db(&self.db, &claims.sub).await {
            Ok(acc) => acc,
            Err(e) => match e {
                Error::RowNotFound => {
                    return Err(ApiError::new(
                        &format!("User not found for '{}'", claims.sub),
                        404,
                    ))
                }
                _ => return Err(ApiError::new(&e.to_string(), 400)),
            },
        };

        // info!(
        //     "Account returned from DB {account:?}, given TokenClaims.sub {}",
        //     claims.sub
        // );

        let mut account_permissions: Vec<String> = vec![];
        for role in account.roles {
            account_permissions.extend(role.permissions)
        }

        // info!("Account permissions: {account_permissions:?}");
        // info!("Required permissions: {required_perms:?}");

        for perm in required_perms {
            if !account_permissions.contains(&perm.to_string()) {
                return Err(ApiError::new(
                    &format!("Invalid token permissions, Token does not contain '{perm}'",),
                    403,
                ));
            }
        }

        Ok(claims)
    }
}
