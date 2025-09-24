use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsString, OpValsValue};
use sea_query::{Nullable, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::store::error::{Result,Error};
use crate::store::schema::audit::AuditFields;
use crate::store::utils::{json_to_sea_value, time_to_sea_value};

// --- Row (DB-facing) ---
/// Maps to the `role` SQL table.
#[derive(Debug, FromRow, Deserialize)]
pub struct RoleRow {
    pub id: Uuid,
    pub namespace_id: Uuid,

    // Role identity
    pub name: String,
    pub description: Option<String>,

    pub tags: Vec<String>,
    #[sqlx(json)]
    pub meta: RoleMeta,

    #[sqlx(flatten)]
    pub audit: AuditFields,
}

// --- Create (store input) ---
/// Input for creating a new `role`.
#[derive(Debug, Fields)]
pub struct RoleCreate {
    pub namespace_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub meta: RoleMeta,
}

// --- Update (store input) ---
/// Input for updating an existing `role`.
#[derive(Debug, Fields, Clone)]
pub struct RoleUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub meta: Option<RoleMeta>,
}

#[derive(Debug, Default, Fields, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct RoleMeta {
    pub schema_version: String,
}

impl Nullable for RoleMeta {
    fn null() -> SeaValue {
        SeaValue::Json(None)
    }
}

impl From<RoleMeta> for SeaValue {
    fn from(value: RoleMeta) -> Self {
        json_to_sea_value(serde_json::to_value(value).unwrap()).unwrap()
    }
}

/// Filtering options for `role` queries.
#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct RoleFilter {
    #[modql(cast_as = "uuid")]
    pub id: Option<String>,
    #[modql(cast_as = "uuid")]
    pub namespace_id: Option<String>,
    pub name: Option<OpValsString>,
    pub description: Option<OpValsString>,

    // NOTE: Filtering on JSONB and TEXT[] fields would require custom modql logic.
    // pub tags: Option<OpValsValue>,
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

impl TryFrom<JsonValue> for RoleFilter {
    type Error = Error;

    fn try_from(value: JsonValue) -> Result<Self> {
        serde_json::from_value(value).map_err(|e| Error::JsonError(e))
    }
}

// --- Defaults for testing ---
#[cfg(test)]
impl Default for RoleCreate {
    fn default() -> Self {
        Self {
            namespace_id: Uuid::new_v4(),
            name: "default-role".to_string(),
            description: Some("A default role for testing.".to_string()),
            tags: vec![],
            meta: RoleMeta {
                schema_version: "1".to_string(),
            },
        }
    }
}

#[cfg(test)]
impl Default for RoleUpdate {
    fn default() -> Self {
        Self {
            name: None,
            description: None,
            tags: None,
            meta: None,
        }
    }
}
