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
    traits::meta::{
        CountMeta, MutableMeta, MutateManyMeta, MutateMeta, ReadManyMeta, ReadMeta, ReadableMeta,
        Store,
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

/// Trait for "create" capability of a store.
#[async_trait]
pub trait Creatable
where
    Self: MutableMeta,
{
    /// Parameters used to insert a new row.
    type CreateStoreParams: HasSeaFields + Send;

    fn meta(&self) -> MutateMeta<Self::Iden> {
        self.mutate_meta()
    }

    /// Insert a new row and return the created record.
    async fn create(&self, ctx: &StoreCtx, data: Self::CreateStoreParams) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.meta();
        create(&ctx, self, data).await
    }
}

/// Trait for "get by id" capability of a store.
#[async_trait]
pub trait Readable
where
    Self: ReadableMeta,
{
    fn meta(&self) -> ReadMeta<Self::Iden> {
        self.read_meta()
    }

    /// Fetch a single row by its primary key.
    async fn get(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.read_meta();
        get(&ctx, self, id).await
    }

    /// TODO: Docs
    async fn get_opt(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.meta();
        get_opt(&ctx, self, id).await
    }
}

/// Trait for "list/filter" capability of a store.
#[async_trait]
pub trait Listable
where
    Self: ReadableMeta,
{
    /// Parameters used to filter queries.
    type FilterStoreParams: Into<FilterGroups> + Send;

    fn meta(&self) -> ReadMeta<Self::Iden> {
        self.read_meta()
    }

    /// Return all rows matching the filter and list options.
    async fn list(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.meta();
        list(ctx, self, filter, opts).await
    }
}

/// Trait for "update" capability of a store.
#[async_trait]
pub trait Updatable
where
    Self: MutableMeta,
{
    /// Parameters used when updating a row.
    type UpdateStoreParams: HasSeaFields + Send;

    fn meta(&self) -> MutateMeta<Self::Iden> {
        self.mutate_meta()
    }

    /// Update a row by ID and return the updated record.
    async fn update(
        &self,
        ctx: &StoreCtx,
        id: &Self::IdKind,
        data: Self::UpdateStoreParams,
    ) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.meta();
        update(ctx, self, id, data).await
    }

    /// TODO: Docs
    async fn update_opt(
        &self,
        ctx: &StoreCtx,
        id: &Self::IdKind,
        data: Self::UpdateStoreParams,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.update_meta();
        update_opt(ctx, self, id, data).await
    }
}

/// Trait for "delete" capability of a store.
#[async_trait]
pub trait Deletable
where
    Self: MutableMeta,
{
    fn meta(&self) -> MutateMeta<Self::Iden> {
        self.mutate_meta()
    }

    /// Delete a row by its primary key.
    /// By default returns the deleted row (if you want
    /// just an affected count, you can adjust here).
    async fn delete(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.meta();
        delete(ctx, self, id).await
    }

    /// TODO: Docs
    async fn delete_opt(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.meta();
        delete_opt(ctx, self, id).await
    }
}

#[async_trait]
pub trait CreatableMany
where
    Self: Creatable,
{
    fn meta(&self) -> MutateManyMeta<Self::Iden> {
        self.mutate_meta()
    }

    async fn create_many(
        &self,
        ctx: &StoreCtx,
        data: Vec<Self::CreateStoreParams>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.meta();
        create_many(ctx, self, data).await
    }
}

#[async_trait]
pub trait UpdatableMany
where
    Self: MutableMeta,
{
    type UpdateStoreParams: HasSeaFields + Clone + Send + Sync + Sized;

    fn meta(&self) -> MutateManyMeta<Self::Iden> {
        self.mutate_meta()
    }

    async fn update_many(
        &self,
        ctx: &StoreCtx,
        data: Vec<(Self::IdKind, Self::UpdateStoreParams)>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.meta();
        update_many(ctx, self, data).await
    }
}

#[async_trait]
pub trait DeletableMany
where
    Self: Deletable,
{
    fn meta(&self) -> MutateManyMeta<Self::Iden> {
        self.mutate_meta()
    }

    async fn delete_many(&self, ctx: &StoreCtx, ids: Vec<Self::IdKind>) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.meta();
        delete_many(ctx, self, ids).await
    }
}

#[async_trait]
pub trait Firstable
where
    Self: Listable,
{
    fn meta(&self) -> ReadMeta<Self::Iden> {
        self.read_meta()
    }

    async fn first(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.meta();
        first(ctx, self, filter, opts).await
    }

    async fn first_opt(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.meta();
        first_opt(ctx, self, filter, opts).await
    }
}

#[async_trait]
pub trait Countable
where
    Self: Listable,
{
    fn meta(&self) -> CountMeta<Self::Iden> {
        self.read_meta()
    }

    async fn count(&self, ctx: &StoreCtx, filter: Option<Self::FilterStoreParams>) -> Result<i64> {
        let db = self.db();
        let meta = self.meta();
        count(ctx, self, filter).await
    }
}
