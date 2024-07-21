use std::fmt::Display;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::role::Role;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    #[serde(rename = "type")]
    pub acc_type: AccountType,
    pub provider: AccountProvider,
    #[serde(skip_serializing)]
    pub provider_id: Option<String>,
    pub roles: Vec<Role>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    pub verified: bool,
    pub enabled: bool,
}

impl Account {
    pub fn new(
        email: &str,
        name: &str,
        password_hash: &str,
        acc_type: AccountType,
        provider: AccountProvider,
        provider_id: Option<String>,
        roles: Vec<Role>,
        image_url: Option<String>,
    ) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            name: name.to_string(),
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            provider,
            provider_id,
            acc_type,
            roles,
            description: None,
            image_url,
            verified: false,
            enabled: true,
        }
    }

    pub fn new_local_user(
        email: &str,
        name: &str,
        password_hash: &str,
        image_url: Option<String>,
    ) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            name: name.to_string(),
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            acc_type: AccountType::User,
            provider: AccountProvider::Local,
            provider_id: None,
            roles: vec![],
            description: None,
            image_url,
            verified: false,
            enabled: true,
        }
    }

    pub fn new_provider_user(
        email: &str,
        name: &str,
        provider: AccountProvider,
        provider_id: Option<String>,
        image_url: Option<String>,
        verified: bool,
    ) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            name: name.to_string(),
            email: email.to_string(),
            password_hash: "".to_string(),
            acc_type: AccountType::User,
            provider,
            provider_id,
            roles: vec![],
            description: None,
            image_url,
            verified,
            enabled: true,
        }
    }

    pub fn new_service_account(email: &str, name: &str, description: Option<String>) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            name: name.to_string(),
            email: email.to_string(),
            password_hash: "".to_string(),
            acc_type: AccountType::Service,
            provider: AccountProvider::Local,
            provider_id: None,
            roles: vec![],
            description,
            image_url: None,
            verified: true,
            enabled: true,
        }
    }

    pub fn set_skip_serialize_permissions(&mut self, val: bool) {
        for role in self.roles.iter_mut() {
            role.set_skip_serialize_permissions(val)
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
            description: None,
            provider: AccountProvider::Local,
            provider_id: None,
            image_url: None,
            verified: true,
            enabled: true,
        }
    }
}

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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AccountProvider {
    Local,
    Google,
    Unknown,
}

impl Display for AccountProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountProvider::Local => write!(f, "local"),
            AccountProvider::Google => write!(f, "google"),
            AccountProvider::Unknown => write!(f, "unknown"),
        }
    }
}

impl From<&str> for AccountProvider {
    fn from(value: &str) -> Self {
        match value {
            "local" => AccountProvider::Local,
            "google" => AccountProvider::Google,
            _ => AccountProvider::Unknown,
        }
    }
}

impl Principal for Account {
    fn email(&self) -> String {
        self.email.to_string()
    }
    fn id(&self) -> String {
        self.id.to_string()
    }
    fn acc_type(&self) -> AccountType {
        self.acc_type()
    }
}

impl Principal for &Account {
    fn email(&self) -> String {
        self.email.to_string()
    }
    fn id(&self) -> String {
        self.id.to_string()
    }
    fn acc_type(&self) -> AccountType {
        self.acc_type()
    }
}

pub trait Principal {
    fn email(&self) -> String;
    fn id(&self) -> String;
    fn acc_type(&self) -> AccountType;
}
