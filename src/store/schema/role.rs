use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsString, OpValsValue};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::error::Error;
use crate::store::schema::audit::AuditFields;
use crate::store::utils::time_to_sea_value;

// --- Row (DB-facing) ---
#[derive(Debug, FromRow, Deserialize)]
pub struct RoleRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,

    // Audit
    #[serde(flatten)]
    #[sqlx(flatten)]
    pub audit: AuditFields,
}

// --- Create (store input) ---
#[derive(Debug, Fields)]
pub struct RoleCreate {
    pub name: String,
    pub description: Option<String>,
}

// --- Update (store input) ---
#[derive(Debug, Fields, Clone)]
pub struct RoleUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// Filtering options for queries
#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct RoleFilter {
    #[modql(cast_as = "uuid")]
    pub id: Option<String>,
    pub name: Option<OpValsString>,
    pub description: Option<OpValsString>,

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

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(Error::JsonError)
    }
}

#[cfg(test)]
impl Default for RoleCreate {
    fn default() -> Self {
        Self {
            name: "Editor".into(),
            description: Some("Can edit resources".into()),
        }
    }
}

#[cfg(test)]
impl Default for RoleUpdate {
    fn default() -> Self {
        Self {
            name: None,
            description: None,
        }
    }
}
