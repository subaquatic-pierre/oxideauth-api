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
    error::Result,
    queries::meta::{ListQueryMeta, MutateQueryMeta, ReadQueryMeta},
    queries::{
        batch::{create_many, delete_many, update_many},
        count::count,
        crud::{delete, delete_opt, get_opt, list, update, update_opt},
        first::{self, first, first_opt},
    },
    traits::meta::{MutableMeta, ReadableMeta, Store, StoreRow},
};
use async_trait::async_trait;

use crate::store::{
    ctx::StoreCtx,
    dbx::Dbx,
    init::DbPool,
    queries::crud::{create, get},
    utils::prepare_audit_fields,
};

use crate::store::traits::meta::HasId;

/// Trait for "create" capability of a store.
#[async_trait]
pub trait Creatable
where
    Self: MutableMeta,
{
    /// Parameters used to insert a new row.
    type CreateStoreParams: HasSeaFields + Send;

    fn create_meta(&self) -> MutateQueryMeta<Self::Iden> {
        self.mutate_meta()
    }

    /// Insert a new row and return the created record.
    async fn create(&self, ctx: &StoreCtx, data: Self::CreateStoreParams) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.create_meta();
        create(&ctx, &db, data, &meta).await
    }
}

/// Trait for "get by id" capability of a store.
#[async_trait]
pub trait Readable
where
    Self: ReadableMeta,
{
    fn get_meta(&self) -> ReadQueryMeta<Self::Iden> {
        self.read_meta()
    }

    /// Fetch a single row by its primary key.
    async fn get(&self, ctx: &StoreCtx, id: &<Self::Row as HasId>::Id) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.get_meta();
        get(&ctx, &db, id, &meta).await
    }

    /// TODO: Docs
    async fn get_opt(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.get_meta();
        get_opt(&ctx, &db, id, &meta).await
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

    fn list_meta(&self) -> ReadQueryMeta<Self::Iden> {
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
        let meta = self.list_meta();
        list(ctx, &db, filter, opts, &meta).await
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

    fn update_meta(&self) -> MutateQueryMeta<Self::Iden> {
        self.mutate_meta()
    }

    /// Update a row by ID and return the updated record.
    async fn update(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
        data: Self::UpdateStoreParams,
    ) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.update_meta();
        update(ctx, &db, id, data, &meta).await
    }

    /// TODO: Docs
    async fn update_opt(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
        data: Self::UpdateStoreParams,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.update_meta();
        update_opt(ctx, &db, id, data, &meta).await
    }
}

/// Trait for "delete" capability of a store.
#[async_trait]
pub trait Deletable
where
    Self: MutableMeta,
{
    fn delete_meta(&self) -> MutateQueryMeta<Self::Iden> {
        self.mutate_meta()
    }

    /// Delete a row by its primary key.
    /// By default returns the deleted row (if you want
    /// just an affected count, you can adjust here).
    async fn delete(&self, ctx: &StoreCtx, id: &<Self::Row as HasId>::Id) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.delete_meta();
        delete(ctx, &db, id, &meta).await
    }

    /// TODO: Docs
    async fn delete_opt(
        &self,
        ctx: &StoreCtx,
        id: &<Self::Row as HasId>::Id,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.delete_meta();
        delete_opt(ctx, &db, id, &meta).await
    }
}

#[async_trait]
pub trait CreatableMany
where
    Self: Creatable,
{
    fn create_many_meta(&self) -> MutateQueryMeta<Self::Iden> {
        self.mutate_meta()
    }

    async fn create_many(
        &self,
        ctx: &StoreCtx,
        data: Vec<Self::CreateStoreParams>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.create_many_meta();
        create_many(ctx, &db, data, &meta).await
    }
}

#[async_trait]
pub trait UpdatableMany
where
    Self: MutableMeta,
{
    type UpdateStoreParams: HasSeaFields + Clone + Send + Sync + Sized;

    fn update_many_meta(&self) -> MutateQueryMeta<Self::Iden> {
        self.mutate_meta()
    }

    async fn update_many(
        &self,
        ctx: &StoreCtx,
        data: Vec<(<Self::Row as HasId>::Id, Self::UpdateStoreParams)>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.update_many_meta();
        update_many(ctx, &db, data, &meta).await
    }
}

#[async_trait]
pub trait DeletableMany
where
    Self: Deletable,
{
    fn delete_many_meta(&self) -> MutateQueryMeta<Self::Iden> {
        self.mutate_meta()
    }

    async fn delete_many(
        &self,
        ctx: &StoreCtx,
        ids: Vec<<Self::Row as HasId>::Id>,
    ) -> Result<Vec<Self::Row>> {
        let db = self.db();
        let meta = self.delete_many_meta();
        delete_many(ctx, &db, ids, &meta).await
    }
}

#[async_trait]
pub trait Firstable
where
    Self: Listable,
{
    fn first_meta(&self) -> ReadQueryMeta<Self::Iden> {
        self.read_meta()
    }

    async fn first(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Self::Row> {
        let db = self.db();
        let meta = self.first_meta();
        first(ctx, &db, filter, opts, &meta).await
    }

    async fn first_opt(
        &self,
        ctx: &StoreCtx,
        filter: Option<Self::FilterStoreParams>,
        opts: Option<ListOptions>,
    ) -> Result<Option<Self::Row>> {
        let db = self.db();
        let meta = self.first_meta();
        first_opt(ctx, &db, filter, opts, &meta).await
    }
}

#[async_trait]
pub trait Countable
where
    Self: Listable,
{
    fn count_meta(&self) -> ReadQueryMeta<Self::Iden> {
        self.read_meta()
    }

    async fn count(&self, ctx: &StoreCtx, filter: Option<Self::FilterStoreParams>) -> Result<i64> {
        let db = self.db();
        let meta = self.count_meta();
        count(ctx, &db, filter, &meta).await
    }
}
