use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsValue};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::store::utils::time_to_sea_value;

#[derive(Debug, FromRow, Deserialize)]
pub struct AuditFields {
    pub created_by: Uuid,
    pub created_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
    pub updated_at: Option<OffsetDateTime>,

    #[sqlx(json, rename = "audit")]
    pub meta: AuditMeta,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct AuditMeta {
    pub schema_version: String,
}
