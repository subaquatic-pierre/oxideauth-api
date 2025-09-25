use modql::{
    field::{HasSeaFields, SeaField, SeaFields},
    filter::{FilterGroups, ListOptions},
    SIden,
};
use sea_query::{Iden, IntoIden, IntoTableRef, TableRef};
use serde::Deserialize;
use sqlx::{postgres::PgRow, FromRow};
use std::sync::Arc;
use uuid::Uuid;

use crate::store::{
    error::Result,
    queries::{
        batch::{create_many, delete_many, update_many},
        count::count,
        crud::{delete, delete_opt, get_opt, list, update, update_opt},
        first::{self, first, first_opt},
    },
};
use async_trait::async_trait;

use crate::store::{
    ctx::StoreCtx,
    dbx::Dbx,
    init::DbPool,
    queries::crud::{create, get},
    utils::prepare_audit_fields,
};

/// Base trait describing static metadata every store must provide.
///
/// This trait connects a store type to its underlying SQL table,
/// defines the types used in CRUD operations, and exposes the `Dbx`
/// accessor for database access.
#[async_trait]
pub trait MetaStore {
    /// Table identifiers
    type TableIden: 'static + Iden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden;
    const TABLE_PK: Self::TableIden;

    /// Primary key kind.
    /// - `ToString`: for logging/debugging
    /// - `Into<Value>`: so it can embed in SeaQuery expressions
    /// - `Send`: so it can cross `await` points safely
    type IdKind: ToString + Into<sea_query::Value> + Send;

    /// Row type returned from queries.
    /// Must be able to map from a Postgres row
    type Row: for<'r> FromRow<'r, PgRow> + Unpin + Send + Sync;

    /// Access to the underlying connection wrapper.
    fn db(&self) -> &Dbx;

    fn has_audit_fields() -> bool {
        false
    }
}
