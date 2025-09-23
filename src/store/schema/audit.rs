use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsValue};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::store::utils::time_to_sea_value;

#[derive(Debug, Deserialize, FromRow)]
pub struct AuditFields {
    pub created_by: Uuid,
    pub created_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
    pub updated_at: Option<OffsetDateTime>,

    #[sqlx(json, rename = "audit_meta")]
    pub meta: AuditMeta,
}

#[derive(Debug, Default, Fields, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct AuditMeta {
    pub schema_version: String,
}

#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct AuditFilter {
    #[modql(cast_as = "uuid")]
    pub created_by: Option<String>,

    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub created_at: Option<OpValsValue>,

    #[modql(cast_as = "uuid")]
    pub updated_by: Option<String>,

    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub updated_at: Option<OpValsValue>,
}
