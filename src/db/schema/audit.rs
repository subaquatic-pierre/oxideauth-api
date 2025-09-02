use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsInt64, OpValsValue};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::utils::modql::time_to_sea_value;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Fields)]
pub struct AuditFields {
    // audit as UUID + timestamptz
    pub cid: uuid::Uuid,
    #[modql(to_sea_value_fn = "time_to_sea_value")]
    #[serde(with = "time::serde::rfc3339")]
    pub ctime: time::OffsetDateTime,

    pub mid: uuid::Uuid,
    #[modql(to_sea_value_fn = "time_to_sea_value")]
    #[serde(with = "time::serde::rfc3339")]
    pub mtime: time::OffsetDateTime,
}

#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct AuditFilter {
    pub cid: Option<OpValsValue>,
    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub ctime: Option<OpValsValue>,
    pub mid: Option<OpValsValue>,
    #[modql(to_sea_value_fn = "time_to_sea_value")]
    pub mtime: Option<OpValsValue>,
}
