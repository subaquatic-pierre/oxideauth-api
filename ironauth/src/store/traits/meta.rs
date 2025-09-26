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

use crate::store::error::Result;
use async_trait::async_trait;

use crate::store::{
    ctx::StoreCtx,
    dbx::Dbx,
    init::DbPool,
    queries::crud::{create, get},
    utils::prepare_audit_fields,
};

pub trait StoreRow: HasId + for<'r> FromRow<'r, PgRow> + Unpin + Send + Sync {}
pub trait StoreId: ToString + Into<sea_query::Value> + Send + Sync + Clone {}
impl StoreId for Uuid {}
pub trait HasId {
    type Id: StoreId;
}

/// Base trait describing static metadata every store must provide.
///
/// This trait connects a store type to its underlying SQL table,
/// defines the types used in CRUD operations, and exposes the `Dbx`
/// accessor for database access.
#[async_trait]
pub trait Store: Sized + Send + Sync {
    type IdKind: StoreId;

    /// Row type returned from queries.
    /// Must be able to map from a Postgres row
    type Row: StoreRow;

    /// Access to the underlying connection wrapper.
    fn db(&self) -> &Dbx;
}

/// Metadata for read-only operations like `list`, `get`, `first`, `count`.
pub struct ReadMeta<I: Iden> {
    pub table: I,
    pub pk: I,
}

/// Metadata for mutating operations like `create`, `update`, `delete`.
pub struct MutateMeta<I: Iden> {
    pub table: I,
    pub pk: I,
    pub has_audit: bool,
}

/// Trait for stores that support read operations.
pub trait ReadableMeta: Store {
    type Iden: Iden;
    fn read_meta(&self) -> ReadMeta<Self::Iden>;
}

/// Trait for stores that support mutating operations.
pub trait MutableMeta: Store {
    type Iden: Iden;
    fn mutate_meta(&self) -> MutateMeta<Self::Iden>;
}

pub type ReadManyMeta<I> = ReadMeta<I>;
pub type MutateManyMeta<I> = MutateMeta<I>;

pub type CountMeta<I> = ReadMeta<I>;
