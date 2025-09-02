use std::sync::Arc;

use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsInt64, OpValsString, OpValsValue};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::dbx::Dbx;
use crate::db::schema::audit::{AuditFields, AuditFilter};

use crate::utils::modql::time_to_sea_value;

#[serde_as]
#[derive(Debug, Clone, FromRow, Fields, Serialize)]
pub struct AccountRow {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String, // skip serializing, prevent leaks to logs or api
    pub name: String,
    pub acc_type: String,
    pub provider: String,
    pub provider_id: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub verified: bool,
    pub enabled: bool,

    // audit as UUID + timestamptz
    pub cid: uuid::Uuid,
    #[field(cast_as = "timestamptz")]
    #[modql(to_sea_value_fn = "time_to_sea_value")]
    #[serde(with = "time::serde::rfc3339")]
    pub ctime: time::OffsetDateTime,

    pub mid: uuid::Uuid,
    #[field(cast_as = "timestamptz")]
    #[modql(to_sea_value_fn = "time_to_sea_value")]
    #[serde(with = "time::serde::rfc3339")]
    pub mtime: time::OffsetDateTime,
}

#[derive(Debug, Deserialize, Fields)]
pub struct AccountCreate {
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
}

#[derive(Debug, Deserialize)]
struct AccountUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub verified: Option<bool>,
    pub enabled: Option<bool>,
}

/// Filtering options for queries
#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct AccountFilter {
    // Core identifiers / status
    pub id: Option<OpValsValue>, // Uuid (use Value to support eq/in)
    pub email: Option<OpValsString>,
    pub name: Option<OpValsString>,
    pub acc_type: Option<OpValsString>,
    pub provider: Option<OpValsString>,
    pub provider_id: Option<OpValsString>,
    pub description: Option<OpValsString>,
    pub image_url: Option<OpValsString>,

    pub verified: Option<OpValsValue>, // bool via Value (eq/in)
    pub enabled: Option<OpValsValue>,  // bool via Value (eq/in)

    #[serde(flatten)]
    pub audit: AuditFilter,
}

#[cfg(test)]
impl Default for AccountCreate {
    fn default() -> Self {
        Self {
            email: "user1@example.com".into(),
            // any string is fine for the DB; it's not verified here
            password_hash: "$argon2id$v=19$m=65536,t=3,p=1$testsalt$testhash".into(),
            name: "Test User".into(),
            acc_type: "user".into(),
            provider: "local".into(),
            provider_id: None,
            description: Some("Fixture account for create() test".into()),
            image_url: None,
            verified: false,
            enabled: true,
        }
    }
}
