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
    dbx::PgDbx,
    error::StoreResult,
    init::PgPool,
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

// region:    --- CRUD Traits
// ---

/// Trait for the "create" capability of a store.
pub trait Create
where
    Self: MutateStore,
{
    /// Inserts a new row and returns the created record.
    async fn create(
        &self,
        ctx: &StoreCtx,
        data: Self::CreateStoreParams,
    ) -> StoreResult<Self::Row> {
        let dbx = self.dbx();
        let meta = self.mutate_meta();
        create(&ctx, &dbx, data, &meta).await
    }
}

/// Trait for the "get by id" capability of a store.
pub trait Get
where
    Self: ReadStore,
{
    /// Fetches a single row by its primary key.
    /// Returns an error if the row is not found.
    async fn get(&self, ctx: &StoreCtx, id: &<Self::Row as HasId>::Id) -> StoreResult<Self::Row> {
        let dbx = self.dbx();
        let meta = self.read_meta();
        get(&ctx, &dbx, id, &meta).await
    }

    /// Fetches a single row by its primary key.
    /// Returns `Ok(None)` if the row is not found.
    async fn get_opt(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
    ) -> StoreResult<Option<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.read_meta();
        get_opt(&ctx, &dbx, id, &meta).await
    }
}

/// Trait for the "list/filter" capability of a store.
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
    ) -> StoreResult<Vec<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.read_meta();
        list(ctx, &dbx, filter, opts, &meta).await
    }
}

/// Trait for the "update" capability of a store.
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
    ) -> StoreResult<Self::Row> {
        let dbx = self.dbx();
        let meta = self.mutate_meta();
        update(ctx, &dbx, id, data, &meta).await
    }

    /// Updates a row by its ID and returns the updated record.
    /// Returns `Ok(None)` if the row was not found.
    async fn update_opt(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
        data: Self::UpdateStoreParams,
    ) -> StoreResult<Option<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.mutate_meta();
        update_opt(ctx, &dbx, id, data, &meta).await
    }
}

/// Trait for the "delete" capability of a store.
pub trait Delete
where
    Self: MutateStore,
{
    /// Deletes a row by its primary key and returns the deleted record.
    /// Returns an error if the row is not found.
    async fn delete(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
    ) -> StoreResult<Self::Row> {
        let dbx = self.dbx();
        let meta = self.mutate_meta();
        delete(ctx, &dbx, id, &meta).await
    }

    /// Deletes a row by its primary key and returns the deleted record.
    /// Returns `Ok(None)` if the row was not found.
    async fn delete_opt(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
    ) -> StoreResult<Option<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.mutate_meta();
        delete_opt(ctx, &dbx, id, &meta).await
    }
}

// endregion: --- CRUD Traits

// region:    --- Batch Traits
// ---

/// Trait for the bulk "create" capability of a store.
pub trait CreateMany
where
    Self: MutateStore,
{
    /// Inserts multiple new rows and returns the created records.
    async fn create_many(
        &self,
        ctx: &StoreCtx,
        data: Vec<Self::CreateStoreParams>,
    ) -> StoreResult<Vec<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.mutate_meta();
        create_many(ctx, &dbx, data, &meta).await
    }
}

/// Trait for the bulk "update" capability of a store.
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
    ) -> StoreResult<Vec<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.mutate_meta();
        update_many(ctx, &dbx, data, &meta).await
    }
}

/// Trait for the bulk "delete" capability of a store.
pub trait DeleteMany
where
    Self: MutateStore,
{
    /// Deletes multiple rows by their primary keys and returns the deleted records.
    async fn delete_many(
        &self,
        ctx: &StoreCtx,
        ids: Vec<<Self::Row as HasId>::Id>,
    ) -> StoreResult<Vec<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.mutate_meta();
        delete_many(ctx, &dbx, ids, &meta).await
    }
}

// endregion: --- Batch Traits

// region:    --- Query Traits
// ---

/// Trait for fetching the first record matching a filter.
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
    ) -> StoreResult<Self::Row> {
        let dbx = self.dbx();
        let meta = self.read_meta();
        first(ctx, &dbx, filter, opts, &meta).await
    }

    /// Fetches the first row matching the filter and list options.
    /// Returns `Ok(None)` if no matching row is found.
    async fn first_opt(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> StoreResult<Option<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.read_meta();
        first_opt(ctx, &dbx, filter, opts, &meta).await
    }
}

/// Trait for counting records matching a filter.
pub trait GetCount
where
    Self: ReadStore,
{
    /// Returns a count of all rows matching the given filter.
    async fn count(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
    ) -> StoreResult<i64> {
        let dbx = self.dbx();
        let meta = self.read_meta();
        count(ctx, &dbx, filter, &meta).await
    }
}

// endregion: --- Query Traits
