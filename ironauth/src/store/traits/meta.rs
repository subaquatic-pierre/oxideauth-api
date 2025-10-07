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
    queries::meta::{
        ContainsFilterQueryMeta, ManyToManyQueryMeta, MutateQueryMeta, OneToManyQueryMeta,
        ReadQueryMeta,
    },
    traits::crud::Create,
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
pub trait ReadStoreMeta: Store {
    /// Parameters used to filter queries.
    type FilterStoreParams: Into<FilterGroups> + Send;
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden>;
}

/// Trait for stores that support mutating operations.
pub trait MutateStoreMeta: Store {
    /// Parameters used to insert a new row.
    type CreateStoreParams: HasSeaFields + Send;
    /// Parameters used when updating a row.
    type UpdateStoreParams: HasSeaFields + Clone + Send + Sync + Sized;
    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden>;
}

/// Trait for stores that support one to many operations.
pub trait OneToManyStoreMeta: Store {
    fn one_to_many_meta(&self) -> OneToManyQueryMeta<Self::Iden>;
}

/// Trait for stores that support many to many operations.
pub trait ManyToManyStoreMeta: Store {
    fn one_to_many_meta(&self) -> ManyToManyQueryMeta<Self::Iden>;
}

/// Trait for stores that support filtering on 'tags' and 'meta' columns.
pub trait ContainsFilterStoreMeta: Store {
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden>;
    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden>;
}
