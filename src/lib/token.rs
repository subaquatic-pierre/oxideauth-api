use actix_web::HttpRequest;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::debug;

use crate::{
    app::AppConfig,
    models::{
        account::Account,
        api::{ApiError, ApiResult},
        token::TokenClaims,
    },
};

pub fn gen_token(app_config: &AppConfig, user: &Account) -> ApiResult<String> {
    let jwt_secret = &app_config.jwt_secret;

    let token_claims = TokenClaims::new(
        user,
        None,
        user.roles.iter().map(|i| i.name.to_string()).collect(),
    );

    let token = encode(
        &Header::default(),
        &token_claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|e| ApiError::new(&e.to_string()));
    token
}

pub fn decode_token(jwt_secret: &str, token: &str) -> ApiResult<TokenClaims> {
    let data = decode::<TokenClaims>(
        &token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| ApiError::new(&e.to_string()))?;

    debug!("{data:?}");

    Ok(data.claims)
}

pub fn get_token_from_req(req: &HttpRequest) -> Option<String> {
    let headers = req.headers();

    if let Some(t) = headers.get("Authorization") {
        if let Ok(token_str) = t.to_str() {
            let split: Vec<String> = token_str.split(' ').map(|i| i.to_string()).collect();

            if split.len() == 2 {
                return Some(split[1].clone());
            } else {
                return None;
            }
        }
    }

    None
}
