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
    db::{dbx::Dbx, init::DbPool, schema::iden::AuditIden},
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
pub trait BaseStore: Send + Sync {
    const TABLE: &'static str;

    type Row: for<'r> FromRow<'r, PgRow> + Unpin + Send + HasSeaFields;
    type CreateParams: HasSeaFields + Send;
    type UpdateParams: HasSeaFields + Send;
    type FilterParams: Into<FilterGroups> + Send;

    // Needs to implement
    fn db(&self) -> &Dbx;
    fn has_audit(&self) -> bool;

    // default methods
    fn table_ref(&self) -> TableRef {
        TableRef::Table(SIden(Self::TABLE).into_iden())
    }

    fn prepare_audit_fields(&self, fields: &mut SeaFields, user_id: Uuid, is_create: bool) {
        if (self.has_audit()) {
            let now = now_utc();
            fields.push(SeaField::new(AuditIden::Mid, user_id));
            fields.push(SeaField::new(AuditIden::Mtime, now));

            if is_create {
                fields.push(SeaField::new(AuditIden::Cid, user_id));
                fields.push(SeaField::new(AuditIden::Ctime, now));
            }
        }
    }

    // --- Main query methods ---
    async fn create(&self, data: Self::CreateParams) -> Result<(), Error> {
        Ok(())
    }
}
