use ironauth_macros::HasId;
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
    ctx::StoreCtx,
    dbx::Dbx,
    error::Result,
    init::DbPool,
    queries::{
        batch::{create_many, delete_many, update_many},
        count::count,
        crud::{create, delete, delete_opt, get, get_opt, list, update, update_opt},
        first::{first, first_opt},
        meta::{MutateQueryMeta, ReadQueryMeta},
    },
    traits::meta::{HasId, MutateStore, ReadStore, Store, StoreRow},
    utils::prepare_audit_fields,
};
use async_trait::async_trait;

// region:    --- CRUD Traits
// ---

/// Trait for the "create" capability of a store.
#[async_trait]
pub trait Create
where
    Self: MutateStore,
{
    /// Inserts a new row and returns the created record.
    async fn create(&self, ctx: &StoreCtx, data: Self::CreateStoreParams) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.mutate_meta();
        create(&ctx, &db, data, &meta).await
    }
}

/// Trait for the "get by id" capability of a store.
#[async_trait]
pub trait Get
where
    Self: ReadStore,
{
    /// Fetches a single row by its primary key.
    /// Returns an error if the row is not found.
    async fn get(&self, ctx: &StoreCtx, id: &<Self::Row as HasId>::Id) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.read_meta();
        get(&ctx, &db, id, &meta).await
    }

    /// Fetches a single row by its primary key.
    /// Returns `Ok(None)` if the row is not found.
    async fn get_opt(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.read_meta();
        get_opt(&ctx, &db, id, &meta).await
    }
}

/// Trait for the "list/filter" capability of a store.
#[async_trait]
pub trait List
where
    Self: ReadStore,
{
    /// Returns all rows matching the filter and list options.
    async fn list(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.read_meta();
        list(ctx, &db, filter, opts, &meta).await
    }
}

/// Trait for the "update" capability of a store.
#[async_trait]
pub trait Update
where
    Self: MutateStore,
{
    /// Updates a row by its ID and returns the updated record.
    /// Returns an error if the row is not found.
    async fn update(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
        data: Self::UpdateStoreParams,
    ) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.mutate_meta();
        update(ctx, &db, id, data, &meta).await
    }

    /// Updates a row by its ID and returns the updated record.
    /// Returns `Ok(None)` if the row was not found.
    async fn update_opt(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
        data: Self::UpdateStoreParams,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.mutate_meta();
        update_opt(ctx, &db, id, data, &meta).await
    }
}

/// Trait for the "delete" capability of a store.
#[async_trait]
pub trait Delete
where
    Self: MutateStore,
{
    /// Deletes a row by its primary key and returns the deleted record.
    /// Returns an error if the row is not found.
    async fn delete(&self, ctx: &StoreCtx, id: &<Self::Row as HasId>::Id) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.mutate_meta();
        delete(ctx, &db, id, &meta).await
    }

    /// Deletes a row by its primary key and returns the deleted record.
    /// Returns `Ok(None)` if the row was not found.
    async fn delete_opt(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.mutate_meta();
        delete_opt(ctx, &db, id, &meta).await
    }
}

// endregion: --- CRUD Traits

// region:    --- Batch Traits
// ---

/// Trait for the bulk "create" capability of a store.
#[async_trait]
pub trait CreateMany
where
    Self: MutateStore,
{
    /// Inserts multiple new rows and returns the created records.
    async fn create_many(
        &self,
        ctx: &StoreCtx,
        data: Vec<Self::CreateStoreParams>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.mutate_meta();
        create_many(ctx, &db, data, &meta).await
    }
}

/// Trait for the bulk "update" capability of a store.
#[async_trait]
pub trait UpdateMany
where
    Self: MutateStore,
{
    /// Updates multiple rows from a vector of (ID, data) tuples
    /// and returns the updated records.
    async fn update_many(
        &self,
        ctx: &StoreCtx,
        data: Vec<(<Self::Row as HasId>::Id, Self::UpdateStoreParams)>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.mutate_meta();
        update_many(ctx, &db, data, &meta).await
    }
}

/// Trait for the bulk "delete" capability of a store.
#[async_trait]
pub trait DeleteMany
where
    Self: MutateStore,
{
    /// Deletes multiple rows by their primary keys and returns the deleted records.
    async fn delete_many(
        &self,
        ctx: &StoreCtx,
        ids: Vec<<Self::Row as HasId>::Id>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.mutate_meta();
        delete_many(ctx, &db, ids, &meta).await
    }
}

// endregion: --- Batch Traits

// region:    --- Query Traits
// ---

/// Trait for fetching the first record matching a filter.
#[async_trait]
pub trait GetFirst
where
    Self: ReadStore,
{
    /// Fetches the first row matching the filter and list options.
    /// Returns an error if no matching row is found.
    async fn first(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.read_meta();
        first(ctx, &db, filter, opts, &meta).await
    }

    /// Fetches the first row matching the filter and list options.
    /// Returns `Ok(None)` if no matching row is found.
    async fn first_opt(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.read_meta();
        first_opt(ctx, &db, filter, opts, &meta).await
    }
}

/// Trait for counting records matching a filter.
#[async_trait]
pub trait GetCount
where
    Self: ReadStore,
{
    /// Returns a count of all rows matching the given filter.
    async fn count(&self, ctx: &StoreCtx, filter: Option<Self::FilterStoreParams>) -> Result<i64> {
        let db = self.db();
        let meta = self.read_meta();
        count(ctx, &db, filter, &meta).await
    }
}

// endregion: --- Query Traits
