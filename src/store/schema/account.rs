use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsString, OpValsValue};
use sea_query::{sea_value_to_json_value, Nullable, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::store::error::Error;
use crate::store::schema::audit::AuditFields;
use crate::store::utils::{json_to_sea_value, time_to_sea_value};

// --- Row (DB-facing) ---
#[derive(Debug, FromRow, Deserialize)]
pub struct AccountRow {
    pub id: Uuid,

    // Identity
    pub email: String,
    pub name: String,
    pub description: Option<String>,
    pub avatar_url: Option<String>,

    // Global Status
    pub enabled: bool,
    pub verified: bool,

    pub tags: Vec<String>,
    #[sqlx(json)]
    pub meta: AccountMeta,

    #[sqlx(flatten)]
    pub audit: AuditFields,
}

// --- Create (store input) ---
#[derive(Debug, Fields)]
pub struct AccountCreate {
    pub email: String,
    pub name: String,
    pub description: Option<String>,
    pub avatar_url: Option<String>,

    pub enabled: bool,
    pub verified: bool,

    pub tags: Vec<String>,
    pub meta: AccountMeta,
}

// --- Update (store input) ---
#[derive(Debug, Fields, Clone)]
pub struct AccountUpdate {
    pub email: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub avatar_url: Option<String>,

    pub enabled: Option<bool>,
    pub verified: Option<bool>,

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
    #[modql(cast_as = "uuid")]
    pub id: Option<String>,
    pub email: Option<OpValsString>,
    pub name: Option<OpValsString>,
    pub description: Option<OpValsString>,
    pub avatar_url: Option<OpValsString>,

    pub verified: Option<OpValsValue>, // bool
    pub enabled: Option<OpValsValue>,  // bool

    // TODO: Must update modql to handle filter by text[] and jsonb
    // Free-form filtering
    // tags: use array containment queries (e.g., @>)
    // pub tags: Option<OpValsValue>,
    // meta: use JSONB containment (@> '{"k":"v"}')
    // pub meta: Option<OpValsValue>,

    // Audit filters (created_by/at, updated_by/at)
    #[modql(cast_as = "uuid")]
    pub created_by: Option<String>,

    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub created_at: Option<OpValsValue>,

    #[modql(cast_as = "uuid")]
    pub updated_by: Option<String>,

    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub updated_at: Option<OpValsValue>,
}

impl TryFrom<JsonValue> for AccountFilter {
    type Error = Error;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(|e| Error::JsonError(e))
    }
}

#[cfg(test)]
impl Default for AccountCreate {
    fn default() -> Self {
        Self {
            email: "user1@example.com".into(),
            name: "Test User".into(),
            description: Some("Fixture account for create() test".into()),
            avatar_url: Some("avatar_url.com".into()),
            verified: false,
            enabled: true,
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
            name: None,
            email: None,

            // Profile / status
            description: None,
            avatar_url: None,
            verified: None,
            enabled: None,

            // Free-form meta; keep structure present but empty
            meta: None,
            tags: None,
        }
    }
}
