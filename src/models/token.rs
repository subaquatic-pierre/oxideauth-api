use log::debug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{app::AppConfig, lib::token::decode_token};

use super::{account::Principal, api::ApiResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub user_id: Uuid,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    exp: usize,
    pub roles: Vec<String>,
}

impl TokenClaims {
    pub fn new(principal: impl Principal, exp: Option<u64>, roles: Vec<String>) -> Self {
        Self {
            sub: principal.email(),
            exp: 9999999999999999,
            roles,
        }
    }

    pub fn from_str(jwt_secret: &str, token: &str) -> ApiResult<Self> {
        decode_token(jwt_secret, token)
    }
}
