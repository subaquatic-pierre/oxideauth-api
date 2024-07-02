use jsonwebtoken::{encode, EncodingKey, Header};

use crate::{
    app::AppConfig,
    models::{
        account::Account,
        error::{ApiError, ApiResult},
        token::TokenClaims,
    },
};

pub fn gen_token(app_config: &AppConfig, user: &Account) -> ApiResult<String> {
    let jwt_secret = &app_config.jwt_secret;

    let token_claims = TokenClaims::new(user, None, None);

    let token = encode(
        &Header::default(),
        &token_claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|e| ApiError::new(&e.to_string()));
    token
}
