use chrono::{prelude::*, Duration};
use log::debug;

use crate::{
    app::AppConfig,
    utils::token::{decode_token, is_token_exp},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    account::{Account, AccountType, Principal},
    api::ApiResult,
};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Auth,
    ResetPassword,
    ConfirmAccount,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: usize,
    iat: usize,
    acc_type: String,
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
