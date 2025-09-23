use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsString, OpValsValue};
use sea_query::{sea_value_to_json_value, Nullable, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::store::error::Error;
use crate::store::schema::audit::{AuditFields, AuditFilter, AuditMeta};
use crate::store::utils::{json_to_sea_value, time_to_sea_value};

// --- Row (DB-facing) ---
/// Maps to the `namespace` SQL table.
#[derive(Debug, FromRow, Deserialize)]
pub struct NamespaceRow {
    pub id: Uuid,

    // Identity
    pub name: String,
    pub slug: String,
    pub description: Option<String>,

    // Config
    #[sqlx(json)]
    pub config: NamespaceConfig,

    // START Meta & Tags
    pub tags: Vec<String>,
    #[sqlx(json)]
    pub meta: NamespaceMeta,
    // END Meta & Tags

    // START Audit
    #[sqlx(flatten)]
    pub audit: AuditFields,
    // END Audit
}

// --- Create (store input) ---
/// Input for creating a new `namespace`.
#[derive(Debug, Fields)]
pub struct NamespaceCreate {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub config: NamespaceConfig,
    pub tags: Vec<String>,
    pub meta: NamespaceMeta,
}

// --- Update (store input) ---
/// Input for updating an existing `namespace`.
#[derive(Debug, Fields, Clone)]
pub struct NamespaceUpdate {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub description: Option<String>,
    pub config: Option<NamespaceConfig>,
    pub tags: Option<Vec<String>>,
    pub meta: Option<NamespaceMeta>,
}

#[derive(Debug, Default, Fields, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct NamespaceConfig {
    pub schema_version: String,
}

impl Nullable for NamespaceConfig {
    fn null() -> SeaValue {
        SeaValue::Json(None)
    }
}

impl From<NamespaceConfig> for SeaValue {
    fn from(value: NamespaceConfig) -> Self {
        json_to_sea_value(serde_json::to_value(value).unwrap()).unwrap()
    }
}

#[derive(Debug, Default, Fields, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct NamespaceMeta {
    pub schema_version: String,
}

impl Nullable for NamespaceMeta {
    fn null() -> SeaValue {
        SeaValue::Json(None)
    }
}

impl From<NamespaceMeta> for SeaValue {
    fn from(value: NamespaceMeta) -> Self {
        json_to_sea_value(serde_json::to_value(value).unwrap()).unwrap()
    }
}

/// Filtering options for `namespace` queries.
#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct NamespaceFilter {
    #[modql(cast_as = "uuid")]
    pub id: Option<String>,
    pub name: Option<OpValsString>,
    pub slug: Option<OpValsString>,
    pub description: Option<OpValsString>,

    // NOTE: Filtering on JSONB fields like `config` and `meta` would require custom modql logic.
    // pub config: Option<OpValsValue>,
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

impl TryFrom<JsonValue> for NamespaceFilter {
    type Error = Error;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(|e| Error::JsonError(e))
    }
}

// --- Defaults for testing ---
#[cfg(test)]
impl Default for NamespaceCreate {
    fn default() -> Self {
        Self {
            name: "Default Namespace".into(),
            slug: "default-namespace".into(),
            description: Some("A default namespace for testing.".into()),
            config: NamespaceConfig {
                schema_version: "1".into(),
            },
            tags: vec![],
            meta: NamespaceMeta {
                schema_version: "1".into(),
            },
        }
    }
}

#[cfg(test)]
impl Default for NamespaceUpdate {
    fn default() -> Self {
        Self {
            name: None,
            slug: None,
            description: None,
            config: None,
            tags: None,
            meta: None,
        }
    }
}
