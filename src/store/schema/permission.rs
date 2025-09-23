use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsString, OpValsValue};
use sea_query::{Nullable, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::store::error::Error;
use crate::store::schema::audit::{AuditFields, AuditFilter};
use crate::store::utils::{json_to_sea_value, time_to_sea_value};

// --- Row (DB-facing) ---
/// Maps to the `permission` SQL table.
#[derive(Debug, FromRow, Deserialize)]
pub struct PermissionRow {
    pub id: Uuid,
    pub namespace_id: Uuid,

    // Permission identity
    pub name: String,
    pub code: Option<String>,
    pub description: Option<String>,

    // START Meta & Tags
    pub tags: Vec<String>,
    #[sqlx(json)]
    pub meta: PermissionMeta,
    // END Meta & Tags

    // START Audit
    #[sqlx(flatten)]
    pub audit: AuditFields,
    // END Audit
}

// --- Create (store input) ---
/// Input for creating a new `permission`.
#[derive(Debug, Fields)]
pub struct PermissionCreate {
    pub namespace_id: Uuid,
    pub name: String,
    pub code: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub meta: PermissionMeta,
}

// --- Update (store input) ---
/// Input for updating an existing `permission`.
#[derive(Debug, Fields, Clone)]
pub struct PermissionUpdate {
    pub name: Option<String>,
    pub code: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub meta: Option<PermissionMeta>,
}

#[derive(Debug, Default, Fields, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct PermissionMeta {
    pub schema_version: String,
}

impl Nullable for PermissionMeta {
    fn null() -> SeaValue {
        SeaValue::Json(None)
    }
}

impl From<PermissionMeta> for SeaValue {
    fn from(value: PermissionMeta) -> Self {
        json_to_sea_value(serde_json::to_value(value).unwrap()).unwrap()
    }
}

/// Filtering options for `permission` queries.
#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct PermissionFilter {
    #[modql(cast_as = "uuid")]
    pub id: Option<String>,
    #[modql(cast_as = "uuid")]
    pub namespace_id: Option<String>,
    pub name: Option<OpValsString>,
    pub code: Option<OpValsString>,
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

impl TryFrom<JsonValue> for PermissionFilter {
    type Error = Error;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(|e| Error::JsonError(e))
    }
}

// --- Defaults for testing ---
#[cfg(test)]
impl Default for PermissionCreate {
    fn default() -> Self {
        Self {
            namespace_id: Uuid::new_v4(),
            name: "default.permission".to_string(),
            code: Some("default-perm".to_string()),
            description: Some("A default permission for testing.".to_string()),
            tags: vec![],
            meta: PermissionMeta {
                schema_version: "1".to_string(),
            },
        }
    }
}

#[cfg(test)]
impl Default for PermissionUpdate {
    fn default() -> Self {
        Self {
            name: None,
            code: None,
            description: None,
            tags: None,
            meta: None,
        }
    }
}
