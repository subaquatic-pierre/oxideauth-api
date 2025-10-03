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
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    traits::crud::Creatable,
};
use async_trait::async_trait;

use crate::store::{
    ctx::StoreCtx,
    dbx::Dbx,
    init::DbPool,
    queries::crud::{create, get},
    utils::prepare_audit_fields,
};
pub trait TableIden: 'static + Copy + Iden + Send + Sync {}

pub trait StoreId: ToString + Into<sea_query::Value> + Send + Sync + Clone + Copy {}
pub trait HasId {
    type Id: StoreId;
}
pub trait StoreRow: HasId + for<'r> FromRow<'r, PgRow> + Unpin + Send + Sync {}

impl<T> StoreRow for T where T: HasId + for<'r> FromRow<'r, PgRow> + Unpin + Send + Sync {}
impl<T> StoreId for T where T: ToString + Into<sea_query::Value> + Send + Sync + Clone + Copy {}
impl<T: 'static + Copy + Iden + Send + Sync> TableIden for T {}

/// Base trait describing static metadata every store must provide.
///
/// This trait connects a store type to its underlying SQL table,
/// defines the types used in CRUD operations, and exposes the `Dbx`
/// accessor for database access.
#[async_trait]
pub trait Store: Sized + Send + Sync {
    type Iden: TableIden;
    /// Row type returned from queries.
    /// Must be able to map from a Postgres row
    type Row: StoreRow;

    /// Access to the underlying connection wrapper.
    fn db(&self) -> &Dbx;
}

/// Trait for stores that support read operations.
pub trait ReadableMeta: Store {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden>;
}

/// Trait for stores that support mutating operations.
pub trait MutableMeta: Store {
    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden>;
}
