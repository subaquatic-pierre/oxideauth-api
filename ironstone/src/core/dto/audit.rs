use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    store::entities::{
        audit::{AuditFields, AuditMeta},
        id::DbId,
    },
    utils::id::map_optional_db_id,
};

/// The Core business model representation of standard audit fields.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CoreAuditFields {
    pub created_by: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub updated_at: Option<OffsetDateTime>,
    pub meta: AuditMeta,
}

// Implementation to convert the store's AuditFields to the core's CoreAuditFields
impl From<AuditFields> for CoreAuditFields {
    fn from(value: AuditFields) -> Self {
        Self {
            created_by: value.created_by.into(),
            created_at: value.created_at,
            updated_by: map_optional_db_id(value.updated_by),
            updated_at: value.updated_at,
            meta: value.meta,
        }
    }
}

impl Default for CoreAuditFields {
    /// Provides a default instance of audit fields, initializing `created_by` to the nil UUID
    /// and `created_at` to the Unix epoch. Optional fields are set to `None`.
    fn default() -> Self {
        Self {
            created_by: Uuid::nil(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_by: None,
            updated_at: None,
            meta: AuditMeta::default(),
        }
    }
}
