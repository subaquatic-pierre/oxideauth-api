use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    core::models::membership::Membership,
    utils::time::{format_time, now_utc},
};

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    sub: String, // Account ID
    ws: String,  // Workspace ID
    mem: String, // Membership ID
    iss: String,
    aud: String,
    pub exp: usize,
    pub iat: usize,
    ty: TokenType,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy, Deserialize)]
pub enum TokenType {
    Auth,
    PasswordReset,
    Refresh,
    AccountConfirm,
}

impl TokenClaims {
    pub fn new(sub: Uuid, ws: Uuid, mem: Uuid, exp: OffsetDateTime, ty: TokenType) -> Self {
        Self {
            sub: sub.to_string(),
            ws: ws.to_string(),
            mem: mem.to_string(),
            iss: "ironstone.app".to_string(),
            aud: "ironstone.api".to_string(),
            iat: now_utc().unix_timestamp() as usize,
            exp: exp.unix_timestamp() as usize,
            ty,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = now_utc().unix_timestamp() as usize;
        if self.exp < now {
            true
        } else {
            false
        }
    }
}
