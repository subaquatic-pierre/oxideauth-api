use modql::{field::HasSeaFields, filter::FilterGroups, SIden};
use sea_query::{Iden, IntoIden, TableRef};
use sqlx::{postgres::PgRow, FromRow};
use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;

use crate::db::{dbx::Dbx, init::DbPool};

// pub struct BaseStore {
//     db: Arc<DbPool>,
// }

#[async_trait]
pub trait BaseStore: Send + Sync {
    const TABLE: &'static str;

    type Row: for<'r> FromRow<'r, PgRow> + Unpin + Send + HasSeaFields;
    type CreateParams: HasSeaFields + Send;
    type UpdateParams: HasSeaFields + Send;
    type FilterParams: Into<FilterGroups> + Send;

    // Needs to implement
    fn db(&self) -> &Dbx;

    // default methods
    fn table_ref(&self) -> TableRef {
        TableRef::Table(SIden(Self::TABLE).into_iden())
    }

    fn has_timestamps(&self) -> bool {
        true
    }

    fn has_owner(&self) -> bool {
        true
    }

    async fn create(&self, data: Self::CreateParams) -> Result<(), Error> {
        Ok(())
    }
}
