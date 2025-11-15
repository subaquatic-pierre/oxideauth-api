use serde::Serialize;
use uuid::Uuid;

use crate::{
    core::dto::audit::CoreAuditFields,
    store::entities::account::{AccountMeta, AccountRow},
};

#[derive(Serialize, Debug, Clone)]
pub struct Account {
    pub id: Uuid,
    // Identity
    pub email: String,
    pub name: String,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    // Global Status
    pub enabled: bool,
    pub verified: bool,
    // Content
    pub tags: Vec<String>,
    pub meta: AccountMeta,
    // Audit
    #[serde(flatten)]
    pub audit: CoreAuditFields,
}

impl From<AccountRow> for Account {
    /// Maps the database-specific `AccountRow` entity to the full core `Account` model.
    fn from(value: AccountRow) -> Self {
        Self {
            // Primary Key Conversion
            id: value.id.into(),

            // Identity Fields (simple copy/clone)
            email: value.email,
            name: value.name,
            description: value.description,
            avatar_url: value.avatar_url,

            // Global Status
            enabled: value.enabled,
            verified: value.verified,

            // Content Fields
            tags: value.tags,
            meta: value.meta, // Assuming AccountMeta is reusable

            // Nested Audit Field Conversion
            audit: value.audit.into(),
        }
    }
}

impl Default for Account {
    /// Provides a default instance of the `Account` core model, where all fields
    /// are initialized to their respective default values (e.g., Uuid::nil, empty strings,
    /// false booleans, empty vectors, and default nested structs).
    fn default() -> Self {
        Self {
            id: Uuid::default(), // Uuid::nil()
            email: String::default(),
            name: String::default(),
            description: Option::default(),
            avatar_url: Option::default(),
            enabled: bool::default(),  // false
            verified: bool::default(), // false
            tags: Vec::default(),
            meta: AccountMeta::default(),
            audit: CoreAuditFields::default(),
        }
    }
}
