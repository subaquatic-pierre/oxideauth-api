use std::fmt::Display;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{principal::Principal, role::Role};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountType {
    User,
    Service,
    Unknown,
}

impl Display for AccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountType::Service => write!(f, "service"),
            AccountType::User => write!(f, "user"),
            AccountType::Unknown => write!(f, "unknown"),
        }
    }
}

impl From<&str> for AccountType {
    fn from(value: &str) -> Self {
        match value {
            "service" => AccountType::Service,
            "user" => AccountType::User,
            _ => AccountType::Unknown,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub acc_type: AccountType,
    pub roles: Vec<Role>,
}

impl Account {
    pub fn new(
        email: &str,
        name: &str,
        password_hash: &str,
        acc_type: AccountType,
        roles: Vec<Role>,
    ) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            name: name.to_string(),
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            acc_type,
            roles,
        }
    }
}

impl Default for Account {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "default".to_string(),
            email: "Account@default.com".to_string(),
            password_hash: "hashed password".to_string(),
            acc_type: AccountType::User,
            roles: vec![],
        }
    }
}

impl Principal for Account {
    fn email(&self) -> String {
        self.email.to_string()
    }
}

impl Principal for &Account {
    fn email(&self) -> String {
        self.email.to_string()
    }
}
