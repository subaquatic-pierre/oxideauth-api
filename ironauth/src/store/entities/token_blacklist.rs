use std::ops::{Deref, DerefMut};

use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsString, OpValsValue};
use sea_query::{Iden, Nullable, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::store::entities::id::DbId;
use crate::store::traits::meta::HasId;
use ironauth_macros::HasId;

use crate::store::entities::audit::{AuditFields, AuditMeta};
use crate::store::entities::hash::Sha256Hash;
use crate::store::error::{Result, StoreError};
use crate::store::utils::{bytes_to_sea_value, json_to_sea_value, time_to_sea_value};

#[derive(Iden, Copy, Clone)]
pub enum TokenBlacklistIden {
    #[iden = "token_blacklist"]
    Table, // TABLE_NAME
    Id, // TABLE_PK
}

// --- Row (DB-facing) ---
/// Maps to the `token_blacklist` SQL table.
#[derive(Debug, FromRow, Deserialize, HasId)]
pub struct TokenBlacklistRow {
    pub id: DbId,
    pub token_hash: Sha256Hash,
    pub account_id: Option<Uuid>,
    pub namespace_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub reason: Option<String>,
    // pub tags: Vec<String>,
    // #[sqlx(json)]
    // pub meta: TokenBlacklistMeta,
    #[sqlx(flatten)]
    pub audit: AuditFields,
}

// --- Create (store input) ---
/// Input for creating a new `token_blacklist` entry.
#[derive(Debug, Fields)]
pub struct TokenBlacklistForCreate {
    pub token_hash: Sha256Hash,
    pub account_id: Option<Uuid>,
    pub namespace_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub reason: Option<String>,
    // pub tags: Vec<String>,
    // pub meta: TokenBlacklistMeta,
}

// --- Update (store input) ---
/// Input for updating an existing `token_blacklist` entry.
#[derive(Debug, Fields, Clone)]
pub struct TokenBlacklistForUpdate {
    pub account_id: Option<Uuid>,
    pub namespace_id: Option<Uuid>,
    pub expires_at: Option<OffsetDateTime>,
    pub reason: Option<String>,
    // pub tags: Option<Vec<String>>,
    // pub meta: Option<TokenBlacklistMeta>,
}

#[derive(Debug, Default, Fields, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct TokenBlacklistMeta {
    pub schema_version: String,
}

impl Nullable for TokenBlacklistMeta {
    fn null() -> SeaValue {
        SeaValue::Json(None)
    }
}

impl From<TokenBlacklistMeta> for SeaValue {
    fn from(value: TokenBlacklistMeta) -> Self {
        json_to_sea_value(serde_json::to_value(value).unwrap()).unwrap()
    }
}

/// Filtering options for `token_blacklist` queries.
#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct TokenBlacklistFilter {
    #[modql(cast_as = "uuid")]
    pub id: Option<OpValsString>,
    pub token_hash: Option<Sha256Hash>,
    #[modql(cast_as = "uuid")]
    pub account_id: Option<OpValsString>,
    #[modql(cast_as = "uuid")]
    pub namespace_id: Option<OpValsString>,
    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub expires_at: Option<OpValsValue>,
    pub reason: Option<OpValsString>,

    // Audit filters
    #[modql(cast_as = "uuid")]
    pub created_by: Option<OpValsString>,
    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub created_at: Option<OpValsValue>,
    #[modql(cast_as = "uuid")]
    pub updated_by: Option<OpValsString>,
    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub updated_at: Option<OpValsValue>,
}

impl TryFrom<JsonValue> for TokenBlacklistFilter {
    type Error = StoreError;

    fn try_from(value: JsonValue) -> Result<Self> {
        let res = serde_json::from_value(value)?;
        Ok(res)
    }
}

// --- Defaults for testing ---
#[cfg(test)]
impl Default for TokenBlacklistForCreate {
    fn default() -> Self {
        Self {
            token_hash: Sha256Hash::gen_rand(),
            account_id: None,
            namespace_id: None,
            expires_at: OffsetDateTime::now_utc(),
            reason: Some("test_revoke".into()),
            // tags: vec![],
            // meta: TokenBlacklistMeta {
            //     schema_version: "1".into(),
            // },
        }
    }
}

#[cfg(test)]
impl Default for TokenBlacklistForUpdate {
    fn default() -> Self {
        Self {
            account_id: None,
            namespace_id: None,
            expires_at: None,
            reason: None,
            // tags: None,
            // meta: None,
        }
    }
}
