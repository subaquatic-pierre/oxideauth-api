use log::debug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{app::AppConfig, lib::token::decode_token};

use super::{
    account::{Account, AccountType, Principal},
    api::ApiResult,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub user_id: Uuid,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    exp: usize,
    acc_type: String,
}

impl TokenClaims {
    pub fn new(account: &Account, exp: Option<u64>) -> Self {
        Self {
            sub: account.id(),
            exp: 9999999999999999,
            // acc_type: principal.acc_type().to_string(),
            acc_type: account.acc_type.to_string(),
        }
    }

    pub fn from_str(jwt_secret: &str, token: &str) -> ApiResult<Self> {
        decode_token(jwt_secret, token)
    }
}
