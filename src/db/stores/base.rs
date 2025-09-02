use modql::{
    field::{HasSeaFields, SeaField, SeaFields},
    filter::FilterGroups,
    SIden,
};
use sea_query::{Iden, IntoIden, TableRef};
use serde::Deserialize;
use sqlx::{postgres::PgRow, FromRow};
use std::sync::Arc;
use uuid::Uuid;

use anyhow::Error;
use async_trait::async_trait;

use crate::{
    db::{dbx::Dbx, init::DbPool, schema::iden::AuditIden, stores::utils::prepare_audit_fields},
    utils::time::now_utc,
};

const LIST_LIMIT_DEFAULT: i64 = 100;
const LIST_LIMIT_MAX: i64 = 500;

#[derive(Debug, Deserialize, Default)]
pub struct ListOpts {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub sort_by: Option<String>, // e.g. "name" or "-ctime"
}

#[async_trait]
pub trait StoreCrud: Send + Sync {
    type Row: for<'r> FromRow<'r, PgRow> + Unpin + Send + HasSeaFields;
    type CreateParams: HasSeaFields + Send;
    type UpdateParams: HasSeaFields + Send;
    type FilterParams: Into<FilterGroups> + Send;

    async fn create(&self, data: Self::CreateParams) -> Result<(), Error> {
        Ok(())
    }
}

#[async_trait]
pub trait StoreMeta {
    fn table_ref(&self) -> TableRef;
    fn db(&self) -> &Dbx;
    fn has_audit(&self) -> bool;
}
