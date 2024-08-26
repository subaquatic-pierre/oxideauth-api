use std::fmt::Display;

use chrono::{prelude::*, Duration};
use log::debug;

use crate::{
    app::AppConfig,
    utils::token::{decode_token, encode_token, is_token_exp},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    account::{Account, AccountType, Principal},
    api::ApiResult,
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum TokenType {
    Auth,
    ResetPassword,
    ConfirmAccount,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub acc_type: String,
    pub token_type: TokenType,
}

impl TokenClaims {
    pub fn new_token(account: &Account, exp: usize, token_type: TokenType) -> Self {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        Self {
            sub: account.id(),
            exp,
            iat,
            token_type,
            acc_type: account.acc_type.to_string(),
        }
    }

    pub fn new_auth_token(account: &Account, exp: Option<usize>) -> Self {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        Self {
            sub: account.id(),
            exp: 9999999999999999,
            iat,
            token_type: TokenType::Auth,
            acc_type: account.acc_type.to_string(),
        }
    }

    pub fn new_confirm_token(account: &Account, exp: Option<usize>) -> Self {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        Self {
            sub: account.id(),
            exp: 9999999999999999,
            iat,
            token_type: TokenType::ConfirmAccount,
            acc_type: account.acc_type.to_string(),
        }
    }

    pub fn new_reset_token(account: &Account, exp: Option<usize>) -> Self {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        Self {
            sub: account.id(),
            exp: 9999999999999999,
            iat,
            token_type: TokenType::ResetPassword,
            acc_type: account.acc_type.to_string(),
        }
    }

    pub fn from_str(jwt_secret: &str, token: &str) -> ApiResult<Self> {
        decode_token(jwt_secret, token)
    }

    pub fn is_expired(&self) -> bool {
        is_token_exp(&self)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::token::encode_token;

    use super::*;
    use chrono::Utc;

    // Helper function to create a mock account
    fn mock_account() -> Account {
        Account::new_local_user("test@example.com", "Test User", "hashed_password", None)
    }

    // Helper function to generate a token
    fn generate_token(claims: &TokenClaims, jwt_secret: &str) -> String {
        encode_token(jwt_secret, claims).unwrap() // Assuming you have this function
    }

    #[test]
    fn test_new_auth_token() {
        let account = mock_account();
        let exp = Some((Utc::now() + Duration::days(1)).timestamp() as usize);
        let claims = TokenClaims::new_auth_token(&account, exp);

        assert_eq!(claims.sub, account.id());
        assert_eq!(claims.token_type, TokenType::Auth);
        assert_eq!(claims.acc_type, account.acc_type.to_string());
    }

    #[test]
    fn test_new_confirm_token() {
        let account = mock_account();
        let exp = Some((Utc::now() + Duration::days(1)).timestamp() as usize);
        let claims = TokenClaims::new_confirm_token(&account, exp);

        assert_eq!(claims.sub, account.id());
        assert_eq!(claims.token_type, TokenType::ConfirmAccount);
        assert_eq!(claims.acc_type, account.acc_type.to_string());
    }

    #[test]
    fn test_new_reset_token() {
        let account = mock_account();
        let exp = Some((Utc::now() + Duration::days(1)).timestamp() as usize);
        let claims = TokenClaims::new_reset_token(&account, exp);

        assert_eq!(claims.sub, account.id());
        assert_eq!(claims.token_type, TokenType::ResetPassword);
        assert_eq!(claims.acc_type, account.acc_type.to_string());
    }

    #[test]
    fn test_from_str() {
        let account = mock_account();
        let jwt_secret = "secret";
        let claims = TokenClaims::new_auth_token(&account, None);
        let token = generate_token(&claims, jwt_secret);

        let decoded_claims = TokenClaims::from_str(jwt_secret, &token).unwrap();

        assert_eq!(decoded_claims.sub, claims.sub);
        assert_eq!(decoded_claims.token_type, claims.token_type);
        assert_eq!(decoded_claims.acc_type, claims.acc_type);
    }

    #[test]
    fn test_is_expired() {
        let account = mock_account();
        let claims = TokenClaims::new_auth_token(
            &account,
            Some((Utc::now() + Duration::seconds(10)).timestamp() as usize),
        );

        // Check that token is not expired
        assert!(!claims.is_expired());

        // Set an expiration time in the past
        let expired_claims = TokenClaims {
            exp: (Utc::now() - Duration::days(1)).timestamp() as usize,
            ..claims
        };

        // Check that token is expired
        assert!(expired_claims.is_expired());
    }
}
