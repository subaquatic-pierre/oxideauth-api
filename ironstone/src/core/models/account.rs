use serde::Serialize;
use uuid::Uuid;

use crate::{
    core::{
        models::{
            audit::CoreAuditFields,
            list::{RequestFilterParams, RequestListOptions},
        },
        traits::list::RequestListParams,
    },
    store::entities::account::{
        AccountFilter as StoreAccountFilter, AccountMeta as StoreAccountMeta, AccountRow,
    },
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

#[derive(Default)]
pub struct AccountCreateParams {
    // Basic/Mandatory fields
    pub email: String,
    pub password: String, // Likely required for creation
    pub name: String,     // Mandatory from Store struct

    // Optional fields mirroring Store struct (AccountForCreate)
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub tags: Option<Vec<String>>,
    // Note: AccountMeta must be defined elsewhere
    pub meta: Option<AccountMeta>,
}

#[derive(Default)]
pub struct AccountDescribeParams {
    pub email: Option<String>,
    pub id: Option<Uuid>,
}

pub struct AccountDeleteParams {
    pub email: Option<String>,
    pub id: Option<Uuid>,
}

pub struct AccountUpdateParams {
    // Account Identifier (from initial basic struct)
    pub email: Option<String>,
    pub id: Option<Uuid>,

    // Fields to Update (mirroring AccountForUpdate, but omitting ID fields)
    pub name: Option<String>,
    pub description: Option<String>,
    pub avatar_url: Option<String>,

    pub enabled: Option<bool>,  // Can be updated by an admin/service call
    pub verified: Option<bool>, // Can be updated by an admin/service call

    pub tags: Option<Vec<String>>,
    pub meta: Option<AccountMeta>,
    // Note: Password update would typically be a separate specialized struct
    // pub new_password: Option<String>,
}
pub struct AccountListParams {
    pub filter: Option<RequestFilterParams<AccountFilter>>,
    pub options: Option<RequestListOptions>,
}

impl RequestListParams<AccountFilter> for AccountListParams {
    fn filter(&self) -> Option<RequestFilterParams<AccountFilter>> {
        self.filter.clone()
    }

    fn options(&self) -> Option<RequestListOptions> {
        self.options.clone()
    }

    fn workspace_id(&self) -> Option<Uuid> {
        todo!()
    }
}

pub type AccountMeta = StoreAccountMeta;
pub type AccountFilter = StoreAccountFilter;
