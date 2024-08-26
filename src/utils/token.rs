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
    exp_future: Option<i64>,
) -> ApiResult<String> {
    let jwt_max_age = match exp_future {
        Some(num) => num,
        None => app_config.jwt_max_age,
    };
    let jwt_secret = &app_config.jwt_secret;
    let exp_future = gen_token_exp_time(jwt_max_age);

    let token_claims = TokenClaims::new_token(user, exp_future, token_type);

    let token = encode(
        &Header::default(),
        &token_claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|e| ApiError::new_400(&e.to_string()));
    token
}

pub fn decode_token(jwt_secret: &str, token: &str) -> ApiResult<TokenClaims> {
    let data = decode::<TokenClaims>(
        &token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    // TODO: remove {e} from error message, to obviscate actual error for user response
    .map_err(|e| ApiError::new_400(&format!("Decoding token error")))?;

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

fn gen_token_exp_time(max_age: i64) -> usize {
    let now = Utc::now();
    let expire_duration = Duration::seconds(max_age);
    let future_time = now + expire_duration;
    future_time.timestamp() as usize
}

pub fn is_token_exp(token: &TokenClaims) -> bool {
    let now = Utc::now().timestamp() as usize;
    if token.exp < now {
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::account::{Account, AccountType};
    use crate::models::token::TokenType;
    use actix_web::test::TestRequest;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    fn mock_app_config() -> AppConfig {
        AppConfig::mock_config()
    }

    fn mock_account() -> Account {
        Account::default()
    }

    #[test]
    fn test_gen_token() {
        let config = mock_app_config();
        let account = mock_account();
        let token_type = TokenType::Auth;

        let token = gen_token(&config, &account, token_type, None).unwrap();
        assert!(!token.is_empty(), "Generated token should not be empty");
    }

    #[test]
    fn test_decode_token() {
        let config = mock_app_config();
        let account = mock_account();
        let token_type = TokenType::Auth;

        let token = gen_token(&config, &account, token_type, None).unwrap();
        let decoded_claims = decode_token(&config.jwt_secret, &token).unwrap();

        assert_eq!(decoded_claims.sub, account.id.to_string());
        assert_eq!(decoded_claims.token_type, token_type);
    }

    #[test]
    fn test_decode_invalid_token() {
        let config = mock_app_config();
        let invalid_token = "invalid.token.here";

        let result = decode_token(&config.jwt_secret, invalid_token);
        assert!(
            result.is_err(),
            "Decoding invalid token should return an error"
        );
    }

    #[test]
    fn test_get_token_from_req() {
        let token = "Bearer some_valid_token";
        let req = TestRequest::default()
            .insert_header(("Authorization", token))
            .to_http_request();

        let extracted_token = get_token_from_req(&req);
        assert_eq!(extracted_token, Some("some_valid_token".to_string()));
    }

    #[test]
    fn test_get_token_from_req_missing_header() {
        let req = TestRequest::default().to_http_request();
        let extracted_token = get_token_from_req(&req);

        assert_eq!(
            extracted_token, None,
            "Should return None if Authorization header is missing"
        );
    }

    #[test]
    fn test_is_token_exp() {
        let config = mock_app_config();
        let account = mock_account();
        let token_type = TokenType::Auth;
        let token = gen_token(&config, &account, token_type, None).unwrap();
        let claims = decode_token(&config.jwt_secret, &token).unwrap();

        assert!(!is_token_exp(&claims), "Token should not be expired");

        // Simulate an expired token by setting exp time in the past
        let expired_claims = TokenClaims {
            exp: (Utc::now() - Duration::seconds(10)).timestamp() as usize,
            ..claims
        };

        assert!(is_token_exp(&expired_claims), "Token should be expired");
    }
}
