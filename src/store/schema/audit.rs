use modql::field::Fields;
use modql::filter::{FilterNodes, OpValsValue};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::utils::modql::time_to_sea_value;

#[derive(Debug, Clone, Fields)]
pub struct AuditFields {
    pub cid: Uuid,
    pub ctime: OffsetDateTime,
    pub mid: Uuid,
    pub mtime: OffsetDateTime,
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
