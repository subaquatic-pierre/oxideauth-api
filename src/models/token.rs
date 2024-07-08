use chrono::{prelude::*, Duration};
use log::debug;

use crate::{app::AppConfig, utils::token::decode_token};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    iat: usize,
    acc_type: String,
}

impl TokenClaims {
    pub fn new(account: &Account, exp: Option<usize>) -> Self {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        Self {
            sub: account.id(),
            exp: 9999999999999999,
            iat,
            // acc_type: principal.acc_type().to_string(),
            acc_type: account.acc_type.to_string(),
        }
    }

    pub fn from_str(jwt_secret: &str, token: &str) -> ApiResult<Self> {
        decode_token(jwt_secret, token)
    }
}
