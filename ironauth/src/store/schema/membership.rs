use ironauth_macros::HasId;
use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsString, OpValsValue};
use sea_query::{Iden, Nullable, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sqlx::prelude::FromRow;
use sqlx::Type;
use std::fmt::{self, Display};
use strum_macros::{Display, EnumString};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::store::error::{Result, StoreError};
use crate::store::schema::audit::{AuditFields, AuditMeta};
use crate::store::schema::id::DbId;
use crate::store::traits::meta::HasId;
use crate::store::utils::{json_to_sea_value, time_to_sea_value};

#[derive(Iden, Copy, Clone)]

pub enum MembershipIden {
    #[iden = "membership"]
    Table, // TABLE_NAME
    Id, // TABLE_PK
}

// --- Row (DB-facing) ---
/// Maps to the `membership` SQL table.
#[derive(Debug, FromRow, Deserialize, HasId)]
pub struct MembershipRow {
    pub id: DbId,

    pub account_id: Uuid,
    pub namespace_id: Uuid,
    pub scope: MembershipScope,
    pub status: MembershipStatus,
    pub project_id: Option<Uuid>,
    pub tags: Vec<String>,
    #[sqlx(json)]
    pub meta: MembershipMeta,
    #[sqlx(flatten)]
    pub audit: AuditFields,
}

#[derive(Debug, Display, Serialize, Deserialize, Clone, Type)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum MembershipScope {
    Namespace,
    Project,
}

impl From<MembershipScope> for SeaValue {
    fn from(value: MembershipScope) -> Self {
        let s = format!("{value}");
        SeaValue::String(Some(Box::new(s)))
    }
}

impl Nullable for MembershipScope {
    fn null() -> SeaValue {
        SeaValue::Json(None)
    }
}

#[derive(Debug, Display, Serialize, Deserialize, Clone, Type)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum MembershipStatus {
    Invited,
    Active,
    Suspended,
}

impl From<MembershipStatus> for SeaValue {
    fn from(value: MembershipStatus) -> Self {
        let s = format!("{value}");
        SeaValue::String(Some(Box::new(s)))
    }
}

impl Nullable for MembershipStatus {
    fn null() -> SeaValue {
        SeaValue::Json(None)
    }
}

// --- Create (store input) ---
/// Input for creating a new `membership`.
#[derive(Debug, Fields)]
pub struct MembershipForCreate {
    pub account_id: Uuid,
    pub namespace_id: Uuid,
    pub scope: MembershipScope,
    pub status: MembershipStatus,
    pub project_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub meta: MembershipMeta,
}

// --- Update (store input) ---
/// Input for updating an existing `membership`.
#[derive(Debug, Fields, Clone)]
pub struct MembershipForUpdate {
    pub scope: Option<MembershipScope>,
    pub status: Option<MembershipStatus>,
    pub project_id: Option<Uuid>,
    pub tags: Option<Vec<String>>,
    pub meta: Option<MembershipMeta>,
}

#[derive(Debug, Default, Fields, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct MembershipMeta {
    pub schema_version: String,
}

impl Nullable for MembershipMeta {
    fn null() -> SeaValue {
        SeaValue::Json(None)
    }
}

impl From<MembershipMeta> for SeaValue {
    fn from(value: MembershipMeta) -> Self {
        json_to_sea_value(serde_json::to_value(value).unwrap()).unwrap()
    }
}

/// Filtering options for `membership` queries.
#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct MembershipFilter {
    #[modql(cast_as = "uuid")]
    pub id: Option<String>,
    #[modql(cast_as = "uuid")]
    pub account_id: Option<String>,
    #[modql(cast_as = "uuid")]
    pub namespace_id: Option<String>,
    pub scope: Option<OpValsString>,
    #[modql(cast_as = "uuid")]
    pub project_id: Option<String>,
    pub status: Option<OpValsString>,

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

impl TryFrom<JsonValue> for MembershipFilter {
    type Error = StoreError;

    fn try_from(value: JsonValue) -> Result<Self> {
        let res = serde_json::from_value(value)?;
        Ok(res)
    }
}

// --- Defaults for testing ---
#[cfg(test)]
impl Default for MembershipForCreate {
    fn default() -> Self {
        Self {
            account_id: Uuid::new_v4(),
            namespace_id: Uuid::new_v4(),
            scope: MembershipScope::Namespace,
            project_id: None,
            status: MembershipStatus::Active,
            tags: vec![],
            meta: MembershipMeta {
                schema_version: "1".to_string(),
            },
        }
    }
}

#[cfg(test)]
impl Default for MembershipForUpdate {
    fn default() -> Self {
        Self {
            scope: None,
            project_id: None,
            status: None,
            tags: None,
            meta: None,
        }
    }
}
