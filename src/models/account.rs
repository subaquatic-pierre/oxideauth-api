use std::fmt::Display;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::role::Role;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Copy, Clone)]
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
        self.acc_type
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
        self.acc_type
    }
}

pub trait Principal {
    fn email(&self) -> String;
    fn id(&self) -> String;
    fn acc_type(&self) -> AccountType;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;
    use uuid::Uuid;

    #[test]
    fn test_account_creation() {
        let email = "test@example.com";
        let name = "Test User";
        let password_hash = "hashed_password";
        let acc_type = AccountType::User;
        let provider = AccountProvider::Local;
        let provider_id = Some("provider_id".to_string());
        let roles = vec![];
        let image_url = Some("http://example.com/image.png".to_string());

        let account = Account::new(
            email,
            name,
            password_hash,
            acc_type,
            provider,
            provider_id.clone(),
            roles.clone(),
            image_url.clone(),
        );

        assert_eq!(account.email, email);
        assert_eq!(account.name, name);
        assert_eq!(account.password_hash, password_hash);
        assert_eq!(account.acc_type, acc_type);
        assert_eq!(account.provider, provider);
        assert_eq!(account.provider_id, provider_id);
        assert_eq!(account.roles, roles);
        assert_eq!(account.image_url, image_url);
        assert_eq!(account.verified, false);
        assert_eq!(account.enabled, true);
    }

    #[test]
    fn test_new_local_user() {
        let email = "local@example.com";
        let name = "Local User";
        let password_hash = "hashed_password";
        let image_url = Some("http://example.com/local_image.png".to_string());

        let account = Account::new_local_user(email, name, password_hash, image_url.clone());

        assert_eq!(account.email, email);
        assert_eq!(account.name, name);
        assert_eq!(account.password_hash, password_hash);
        assert_eq!(account.acc_type, AccountType::User);
        assert_eq!(account.provider, AccountProvider::Local);
        assert_eq!(account.provider_id, None);
        assert_eq!(account.roles, vec![]);
        assert_eq!(account.image_url, image_url);
        assert_eq!(account.verified, false);
        assert_eq!(account.enabled, true);
    }

    #[test]
    fn test_new_provider_user() {
        let email = "provider@example.com";
        let name = "Provider User";
        let provider = AccountProvider::Google;
        let provider_id = Some("provider_id".to_string());
        let image_url = Some("http://example.com/provider_image.png".to_string());
        let verified = true;

        let account = Account::new_provider_user(
            email,
            name,
            provider,
            provider_id.clone(),
            image_url.clone(),
            verified,
        );

        assert_eq!(account.email, email);
        assert_eq!(account.name, name);
        assert_eq!(account.password_hash, "".to_string());
        assert_eq!(account.acc_type, AccountType::User);
        assert_eq!(account.provider, provider);
        assert_eq!(account.provider_id, provider_id);
        assert_eq!(account.roles, vec![]);
        assert_eq!(account.image_url, image_url);
        assert_eq!(account.verified, verified);
        assert_eq!(account.enabled, true);
    }

    #[test]
    fn test_new_service_account() {
        let email = "service@example.com";
        let name = "Service Account";
        let description = Some("A service account".to_string());

        let account = Account::new_service_account(email, name, description.clone());

        assert_eq!(account.email, email);
        assert_eq!(account.name, name);
        assert_eq!(account.password_hash, "".to_string());
        assert_eq!(account.acc_type, AccountType::Service);
        assert_eq!(account.provider, AccountProvider::Local);
        assert_eq!(account.provider_id, None);
        assert_eq!(account.roles, vec![]);
        assert_eq!(account.description, description);
        assert_eq!(account.image_url, None);
        assert_eq!(account.verified, true);
        assert_eq!(account.enabled, true);
    }

    #[test]
    fn test_set_skip_serialize_permissions() {
        let mut account = Account::default();
        account.set_skip_serialize_permissions(true);
        // Assuming Role has a method or field that we can verify if permissions are skipped
        // Here we just validate if the method is invoked without panicking
    }

    #[test]
    fn test_account_type_display() {
        assert_eq!(format!("{}", AccountType::User), "user");
        assert_eq!(format!("{}", AccountType::Service), "service");
        assert_eq!(format!("{}", AccountType::Unknown), "unknown");
    }

    #[test]
    fn test_account_provider_display() {
        assert_eq!(format!("{}", AccountProvider::Local), "local");
        assert_eq!(format!("{}", AccountProvider::Google), "google");
        assert_eq!(format!("{}", AccountProvider::Unknown), "unknown");
    }

    #[test]
    fn test_account_type_from_str() {
        assert_eq!(AccountType::from("user"), AccountType::User);
        assert_eq!(AccountType::from("service"), AccountType::Service);
        assert_eq!(AccountType::from("unknown"), AccountType::Unknown);
    }

    #[test]
    fn test_account_provider_from_str() {
        assert_eq!(AccountProvider::from("local"), AccountProvider::Local);
        assert_eq!(AccountProvider::from("google"), AccountProvider::Google);
        assert_eq!(AccountProvider::from("unknown"), AccountProvider::Unknown);
    }
}
