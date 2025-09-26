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
    traits::meta::{BaseMetaStore, CrudMetaStore},
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
pub trait CreateStore
where
    Self: BaseMetaStore + CrudMetaStore,
{
    /// Parameters used to insert a new row.
    type CreateStoreParams: HasSeaFields + Send;

    /// Insert a new row and return the created record.
    async fn create(&self, ctx: &StoreCtx, data: Self::CreateStoreParams) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.crud_meta();
        create(&ctx, self, data).await
    }
}

/// Trait for "get by id" capability of a store.
#[async_trait]
pub trait GetStore
where
    Self: BaseMetaStore,
{
    /// Fetch a single row by its primary key.
    async fn get(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::Row> {
        get(&ctx, self, id).await
    }

    /// TODO: Docs
    async fn get_opt(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Option<Self::Row>> {
        get_opt(&ctx, self, id).await
    }
}

/// Trait for "list/filter" capability of a store.
#[async_trait]
pub trait ListStore
where
    Self: BaseMetaStore,
{
    /// Parameters used to filter queries.
    type FilterStoreParams: Into<FilterGroups> + Send;

    /// Return all rows matching the filter and list options.
    async fn list(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Vec<Self::Row>> {
        list(ctx, self, filter, opts).await
    }
}

/// Trait for "update" capability of a store.
#[async_trait]
pub trait UpdateStore
where
    Self: BaseMetaStore,
{
    /// Parameters used when updating a row.
    type UpdateStoreParams: HasSeaFields + Send;

    /// Update a row by ID and return the updated record.
    async fn update(
        &self,
        ctx: &StoreCtx,
        id: &Self::IdKind,
        data: Self::UpdateStoreParams,
    ) -> Result<Self::Row> {
        update(ctx, self, id, data).await
    }

    /// TODO: Docs
    async fn update_opt(
        &self,
        ctx: &StoreCtx,
        id: &Self::IdKind,
        data: Self::UpdateStoreParams,
    ) -> Result<Option<Self::Row>> {
        update_opt(ctx, self, id, data).await
    }
}

/// Trait for "delete" capability of a store.
#[async_trait]
pub trait DeleteStore
where
    Self: BaseMetaStore,
{
    /// Delete a row by its primary key.
    /// By default returns the deleted row (if you want
    /// just an affected count, you can adjust here).
    async fn delete(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::Row> {
        delete(ctx, self, id).await
    }

    /// TODO: Docs
    async fn delete_opt(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Option<Self::Row>> {
        delete_opt(ctx, self, id).await
    }
}

#[async_trait]
pub trait CreateManyStore
where
    Self: BaseMetaStore + CreateStore,
{
    async fn create_many(
        &self,
        ctx: &StoreCtx,
        data: Vec<Self::CreateStoreParams>,
    ) -> Result<Vec<Self::Row>> {
        create_many(ctx, self, data).await
    }
}

#[async_trait]
pub trait UpdateManyStore
where
    Self: BaseMetaStore,
{
    type UpdateStoreParams: HasSeaFields + Clone + Send + Sync + Sized;

    async fn update_many(
        &self,
        ctx: &StoreCtx,
        data: Vec<(Self::IdKind, Self::UpdateStoreParams)>,
    ) -> Result<Vec<Self::Row>> {
        update_many(ctx, self, data).await
    }
}

#[async_trait]
pub trait DeleteManyStore
where
    Self: BaseMetaStore + DeleteStore,
{
    async fn delete_many(&self, ctx: &StoreCtx, ids: Vec<Self::IdKind>) -> Result<Vec<Self::Row>> {
        delete_many(ctx, self, ids).await
    }
}

#[async_trait]
pub trait FirstStore
where
    Self: BaseMetaStore + ListStore,
{
    async fn first(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Self::Row> {
        first(ctx, self, filter, opts).await
    }

    async fn first_opt(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Option<Self::Row>> {
        first_opt(ctx, self, filter, opts).await
    }
}

#[async_trait]
pub trait CountStore
where
    Self: BaseMetaStore + ListStore,
{
    async fn count(&self, ctx: &StoreCtx, filter: Option<Self::FilterStoreParams>) -> Result<i64> {
        count(ctx, self, filter).await
    }
}
