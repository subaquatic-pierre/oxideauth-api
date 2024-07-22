use actix_web::HttpRequest;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::debug;

use crate::{
    app::AppConfig,
    models::{
        account::Account,
        api::{ApiError, ApiResult},
        token::{TokenClaims, TokenType},
    },
};

pub fn gen_token(
    app_config: &AppConfig,
    user: &Account,
    token_type: TokenType,
) -> ApiResult<String> {
    let jwt_secret = &app_config.jwt_secret;
    let exp_future = gen_token_exp_time(app_config);

    let token_claims = TokenClaims::new_token(user, exp_future, token_type);

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
    // TODO: remove {e} from error message, to obviscate actual error for user response
    .map_err(|e| ApiError::new(&format!("Decoding token error, {e}")))?;

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

fn gen_token_exp_time(config: &AppConfig) -> usize {
    let now = Utc::now();
    let expire_duration = Duration::seconds(config.jwt_max_age);
    let future_time = now + expire_duration;
    future_time.timestamp() as usize
}
