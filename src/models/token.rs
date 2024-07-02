use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::principal::Principal;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    sub: String,
    exp: usize,
    roles: Vec<String>,
}

impl TokenClaims {
    pub fn new(principal: impl Principal, exp: Option<u64>, roles: Option<Vec<&str>>) -> Self {
        Self {
            sub: principal.email(),
            exp: 100000,
            roles: vec!["admin".to_string()],
        }
    }
}
