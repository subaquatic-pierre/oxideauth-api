use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, Responder};
use log::{debug, error, info};
use sqlx::{Error, PgPool, Pool};

use crate::{
    db::queries::{
        account::get_account_db,
        role::{get_role_db, get_role_permissions_db},
    },
    lib::{auth::contains_all, token::get_token_from_req},
    models::api::ApiError,
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

    pub async fn authorize_req(&self, req: &HttpRequest, required_perms: &[&str]) -> ApiResult<()> {
        // check user exists in DB

        let token_str = match get_token_from_req(&req) {
            Some(token) => token,
            None => return Err(ApiError::new("Unable to get token from request")),
        };

        info!("Token: {token_str:?}");

        let claims = match TokenClaims::from_str(self.jwt_secret.as_ref(), &token_str) {
            Ok(claims) => claims,
            Err(e) => {
                error!("Error building TokenClaims from string, {:?}", e);
                return Err(e);
            }
        };

        let account = match get_account_db(&self.db, &claims.sub).await {
            Ok(acc) => acc,
            Err(e) => match e {
                Error::RowNotFound => {
                    return Err(ApiError::new(&format!(
                        "User not found for '{}'",
                        claims.sub
                    )))
                }
                _ => return Err(ApiError::new(&e.to_string())),
            },
        };

        info!("Token Claims: {claims:?}");

        info!("Account from TokenClaims.sub {account:?}");

        let mut account_permissions: Vec<String> = vec![];
        for role in account.roles {
            account_permissions.extend(role.permissions)
        }

        let mut token_permissions: Vec<String> = vec![];
        for role_name in claims.roles {
            match get_role_db(&self.db, &role_name).await {
                Ok(role) => match get_role_permissions_db(&self.db, &role.id).await {
                    Ok(perms) => token_permissions.extend(perms),
                    Err(e) => {
                        error!("Unable to get permissions for '{role_name}', {:?}", e);
                    }
                },
                Err(e) => {
                    error!("Unable to get role_id for '{role_name}', {:?}", e);
                }
            }
        }

        info!("Token permissions: {token_permissions:?}");
        info!("Account permissions: {account_permissions:?}");
        info!("Required permissions: {required_perms:?}");

        for perm in required_perms {
            if !account_permissions.contains(&perm.to_string()) {
                return Err(ApiError::new(&format!(
                    "Invalid token permissions, Token does not contain '{perm}'",
                )));
            }
        }

        Ok(())
    }
}
