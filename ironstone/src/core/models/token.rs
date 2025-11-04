use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    core::models::membership::Membership,
    utils::time::{format_time, now_utc},
};

#[derive(Serialize, Clone, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    sub: String, // membership ID
    iss: String,
    aud: String,
    iat: String,
    exp: String,
    ty: TokenType,
}

#[derive(Serialize, PartialEq, Eq, Clone, Copy, Deserialize)]
pub enum TokenType {
    Auth,
    ResetPassword,
    Refresh,
    ConfirmAccount,
}

impl TokenClaims {
    pub fn new(mem: Membership, exp: OffsetDateTime, ty: TokenType) -> Self {
        Self {
            sub: mem.id.to_string(),
            iss: "ironstone.app".to_string(),
            aud: "ironstone.api".to_string(),
            iat: format_time(now_utc()),
            exp: format_time(exp),
            ty,
        }
    }
}
