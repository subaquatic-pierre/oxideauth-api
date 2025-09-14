use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsString, OpValsValue};
use sea_query::{sea_value_to_json_value, Nullable, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::store::schema::audit::AuditFilter;
use crate::store::utils::{json_to_sea_value, time_to_sea_value};

// --- Row (DB-facing) ---
#[derive(Debug, FromRow)]
pub struct AccountRow {
    pub id: Uuid,

    // Identity
    pub email: String,
    pub password_hash: String, // internal only
    pub name: String,
    pub acc_type: String,
    pub provider: String,
    pub provider_id: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub verified: bool,
    pub enabled: bool,

    // Scope
    pub namespace_id: Option<Uuid>,
    pub project_id: Option<Uuid>,

    // Free-form
    pub tags: Vec<String>,
    #[sqlx(json)]
    pub meta: AccountMeta,

    // Audit
    pub created_by: Uuid,
    pub created_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
    pub updated_at: Option<OffsetDateTime>,
}

// --- Create (store input) ---
#[derive(Debug, Fields)]
pub struct AccountCreate {
    // Identity
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub acc_type: String,
    pub provider: String,
    pub provider_id: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub verified: bool,
    pub enabled: bool,

    // Scope
    pub namespace_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    // Free-form
    pub tags: Vec<String>,
    pub meta: AccountMeta,
}

// --- Update (store input) ---
#[derive(Debug, Fields, Clone)]
pub struct AccountUpdate {
    pub name: Option<String>,
    pub acc_type: Option<String>,
    pub provider: Option<String>,
    pub provider_id: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub verified: Option<bool>,
    pub enabled: Option<bool>,

    // Scope
    pub namespace_id: Option<Uuid>,
    pub project_id: Option<Uuid>,

    // Free-form
    pub tags: Option<Vec<String>>,
    pub meta: Option<AccountMeta>,
}

#[derive(Debug, Default, Fields, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct AccountMeta {
    pub schema_version: String,
}

impl Nullable for AccountMeta {
    fn null() -> SeaValue {
        SeaValue::Json(None)
    }
}

impl From<AccountMeta> for SeaValue {
    fn from(value: AccountMeta) -> Self {
        json_to_sea_value(serde_json::to_value(value).unwrap()).unwrap()
    }
}

/// Filtering options for queries
#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct AccountFilter {
    // Core identifiers / status
    pub id: Option<OpValsValue>, // UUID (eq/in)
    pub email: Option<OpValsString>,
    pub name: Option<OpValsString>,
    pub acc_type: Option<OpValsString>,
    pub provider: Option<OpValsString>,
    pub provider_id: Option<OpValsString>,
    pub description: Option<OpValsString>,
    pub image_url: Option<OpValsString>,

    pub verified: Option<OpValsValue>, // bool
    pub enabled: Option<OpValsValue>,  // bool

    // Scope
    pub namespace_id: Option<OpValsValue>, // UUID (eq/in)
    pub project_id: Option<OpValsValue>,   // UUID (eq/in)

    // Free-form filtering
    // tags: use array containment queries (e.g., @>)
    pub tags: Option<OpValsValue>,
    // meta: use JSONB containment (@> '{"k":"v"}')
    pub meta: Option<OpValsValue>,

    // Audit filters (created_by/at, updated_by/at)
    #[modql(cast_as = "uuid")]
    pub created_by: Option<String>,

    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub created_at: Option<OpValsValue>,

    #[modql(cast_as = "uuid")]
    pub updated_by: Option<String>,

    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub updated_at: Option<OpValsValue>,
    // #[serde(flatten)]
    // pub audit: AuditFilter,
}

#[cfg(test)]
impl Default for AccountCreate {
    fn default() -> Self {
        Self {
            email: "user1@example.com".into(),
            password_hash: "$argon2id$v=19$m=65536,t=3,p=1$testsalt$testhash".into(),
            name: "Test User".into(),
            acc_type: "user".into(),
            provider: "local".into(),
            provider_id: None,
            description: Some("Fixture account for create() test".into()),
            image_url: None,
            verified: false,
            enabled: true,
            namespace_id: None,
            project_id: None,
            tags: vec![],
            meta: AccountMeta {
                schema_version: "1".into(),
            },
        }
    }
}

#[cfg(test)]
impl Default for AccountUpdate {
    fn default() -> Self {
        Self {
            // Basic identity
            name: None,
            acc_type: None,    // e.g. "user" | "admin" | "service"
            provider: None,    // e.g. "local" | "google" | "github"
            provider_id: None, // set if provider != local

            // Profile / status
            description: None,
            image_url: None,
            verified: None,
            enabled: None,

            // Scope (left unset by default to avoid FK issues)
            namespace_id: None,
            project_id: None,

            // Free-form meta; keep structure present but empty
            meta: None,
            tags: None,
        }
    }
}
