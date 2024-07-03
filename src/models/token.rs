use log::debug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{app::AppConfig, utils::token::decode_token};

use super::{error::ApiResult, principal::Principal};

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub user_id: Uuid,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    sub: String,
    exp: usize,
    roles: Vec<String>,
}

impl TokenClaims {
    pub fn new(principal: impl Principal, exp: Option<u64>, roles: Vec<String>) -> Self {
        Self {
            sub: principal.email(),
            exp: 9999999999999999,
            roles,
        }
    }

    pub fn from_str(token: &str, app_config: &AppConfig) -> ApiResult<Self> {
        decode_token(app_config, token)
    }
}
