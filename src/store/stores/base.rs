use modql::{
    field::{HasSeaFields, SeaField, SeaFields},
    filter::{FilterGroups, ListOptions},
    SIden,
};
use sea_query::{Iden, IntoIden, TableRef};
use serde::Deserialize;
use sqlx::{postgres::PgRow, FromRow};
use std::sync::Arc;
use uuid::Uuid;

use crate::store::error::{Error, Result};
use async_trait::async_trait;

use crate::{
    store::{
        ctx::Ctx,
        dbx::Dbx,
        init::DbPool,
        queries::crud::{create, get},
        schema::iden::AuditIden,
        stores::utils::prepare_audit_fields,
    },
    utils::time::now_utc,
};

/// Trait defining common CRUD operations available to all stores.
///
/// Each method delegates to a shared `queries::crud` function,
/// so individual store implementations don’t need to duplicate logic.
#[async_trait]
pub trait StoreCrud
where
    // StoreCrud only applies to types that also implement StoreMeta
    // and are thread-safe (`Send + Sync`) and concrete (`Sized`).
    Self: StoreMeta + Send + Sync + Sized,
{
    /// Insert a new row into the store’s table.
    async fn create(&self, ctx: &Ctx, data: Self::CreateParams) -> Result<Self::Row> {
        create(&ctx, self, data).await
    }

    /// Retrieve a single row by its primary key.
    async fn get(&self, ctx: &Ctx, id: Self::Id) -> Result<Self::Row> {
        get(&ctx, self, id).await
    }

    /// List rows, optionally filtered and/or paginated.
    async fn list(
        &self,
        ctx: &Ctx,
        filter: Option<Self::FilterParams>,
        opts: Option<ListOptions>,
    ) -> Result<Vec<Self::Row>> {
        todo!()
    }

    /// Update a row and return the new version.
    async fn update(&self, ctx: &Ctx, data: Self::UpdateParams) -> Result<Self::Row> {
        todo!()
    }

    /// Delete a row by its primary key, returning the deleted row.
    async fn delete(&self, ctx: &Ctx, id: Self::Id) -> Result<Self::Row> {
        todo!()
    }
}

// Blanket impl so that any type implementing StoreMeta
// automatically gains StoreCrud (with its default method bodies).
#[async_trait]
impl<T> StoreCrud for T where T: StoreMeta + Send + Sync + Sized {}

/// Trait defining metadata every store must provide.
///
/// This links a Rust store type to its underlying SQL table
/// and specifies the associated data types used in CRUD operations.
#[async_trait]
pub trait StoreMeta {
    /// Backing table name (as a static string).
    const TABLE: &'static str;

    /// Whether this table has the standard audit fields
    /// (e.g., ctime, mtime, cid, mid).
    const HAS_AUDIT_FIELDS: bool = false;

    /// The Rust type used for the table’s primary key.
    /// - `ToString`: needed for debugging/logging.
    /// - `Into<sea_query::Value>`: so it can be embedded directly in SeaQuery expressions.
    /// - `Send`: ensures it can safely cross await boundaries in async code.
    type Id: ToString + Into<sea_query::Value> + Send;

    /// The row type returned from queries.
    /// - `FromRow`: allows mapping from `sqlx::PgRow`.
    /// - `Unpin`: needed because sqlx streams rows across await points.
    /// - `Send + Sync`: required for async trait usage.
    /// - `HasSeaFields`: provides column definitions for SeaQuery.
    type Row: for<'r> FromRow<'r, PgRow> + Unpin + Send + Sync + HasSeaFields;

    /// Parameters used when inserting a new row.
    type CreateParams: HasSeaFields + Send;

    /// Parameters used when updating an existing row.
    type UpdateParams: HasSeaFields + Send;

    /// Filtering options for list/select queries.
    type FilterParams: Into<FilterGroups> + Send;

    /// Accessor for the database connection wrapper.
    fn db(&self) -> &Dbx;

    /// Returns a `TableRef` for this store’s table.
    /// Defaults to using the static `TABLE` identifier.
    fn table_ref(&self) -> TableRef {
        TableRef::Table(SIden(Self::TABLE).into_iden())
    }
}
