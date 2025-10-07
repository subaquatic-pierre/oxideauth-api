use async_trait::async_trait;
use sea_query::Iden;
use sqlx::{postgres::PgRow, FromRow};

use crate::store::ctx::StoreCtx;

use crate::store::error::Result;
use crate::store::queries::join::get_one_to_many;
use crate::store::traits::meta::Store;

#[async_trait]
pub trait GetOneToMany
where
    Self: Store,
{
    // // --- Metadata for the "Many" side of the relationship ---
    // type ManyRow: for<'r> FromRow<'r, PgRow> + Send + Sync;

    // // --- Metadata for the final, combined result ---
    // type JoinedRow: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin;

    // // --- Constants to define the JOIN ---
    // const MANY_TABLE: Self::TableIden;
    // const MANY_FK_COL: Self::TableIden; // The foreign key on the "many" table
    // const MANY_ALIAS_NAME: Self::TableIden; // The name for the JSON_AGG column, e.g., "credentials"

    // /// A generic method that builds and executes the one-to-many join query.
    // async fn get_joined_opt(
    //     &self,
    //     ctx: &StoreCtx,
    //     id: &Self::IdKind,
    // ) -> Result<Option<Self::JoinedRow>> {
    //     get_joined_opt(ctx, self, id).await
    // }
    // async fn get_joined(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::JoinedRow>;
}

#[async_trait]
pub trait GetManyToMany
where
    Self: Store,
{
    // // --- Metadata for the "Many" side of the relationship ---
    // type ManyRow: for<'r> FromRow<'r, PgRow> + Send + Sync;

    // // --- Metadata for the final, combined result ---
    // type JoinedRow: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin;

    // // --- Constants to define the JOIN ---
    // const MANY_TABLE: Self::TableIden;
    // const MANY_FK_COL: Self::TableIden; // The foreign key on the "many" table
    // const MANY_ALIAS_NAME: Self::TableIden; // The name for the JSON_AGG column, e.g., "credentials"

    // /// A generic method that builds and executes the one-to-many join query.
    // async fn get_joined_opt(
    //     &self,
    //     ctx: &StoreCtx,
    //     id: &Self::IdKind,
    // ) -> Result<Option<Self::JoinedRow>> {
    //     get_joined_opt(ctx, self, id).await
    // }
    // async fn get_joined(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::JoinedRow>;
}

#[async_trait]
pub trait ListOneToMany
where
    Self: Store,
{
    // // --- Metadata for the "Many" side of the relationship ---
    // type ManyRow: for<'r> FromRow<'r, PgRow> + Send + Sync;

    // // --- Metadata for the final, combined result ---
    // type JoinedRow: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin;

    // // --- Constants to define the JOIN ---
    // const MANY_TABLE: Self::TableIden;
    // const MANY_FK_COL: Self::TableIden; // The foreign key on the "many" table
    // const MANY_ALIAS_NAME: Self::TableIden; // The name for the JSON_AGG column, e.g., "credentials"

    // /// A generic method that builds and executes the one-to-many join query.
    // async fn get_joined_opt(
    //     &self,
    //     ctx: &StoreCtx,
    //     id: &Self::IdKind,
    // ) -> Result<Option<Self::JoinedRow>> {
    //     get_joined_opt(ctx, self, id).await
    // }
    // async fn get_joined(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::JoinedRow>;
}

#[async_trait]
pub trait ListManyToMany
where
    Self: Store,
{
    // // --- Metadata for the "Many" side of the relationship ---
    // type ManyRow: for<'r> FromRow<'r, PgRow> + Send + Sync;

    // // --- Metadata for the final, combined result ---
    // type JoinedRow: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin;

    // // --- Constants to define the JOIN ---
    // const MANY_TABLE: Self::TableIden;
    // const MANY_FK_COL: Self::TableIden; // The foreign key on the "many" table
    // const MANY_ALIAS_NAME: Self::TableIden; // The name for the JSON_AGG column, e.g., "credentials"

    // /// A generic method that builds and executes the one-to-many join query.
    // async fn get_joined_opt(
    //     &self,
    //     ctx: &StoreCtx,
    //     id: &Self::IdKind,
    // ) -> Result<Option<Self::JoinedRow>> {
    //     get_joined_opt(ctx, self, id).await
    // }
    // async fn get_joined(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::JoinedRow>;
}

#[async_trait]
pub trait LinkManyToMany
where
    Self: Store,
{
    // // --- Metadata for the "Many" side of the relationship ---
    // type ManyRow: for<'r> FromRow<'r, PgRow> + Send + Sync;

    // // --- Metadata for the final, combined result ---
    // type JoinedRow: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin;

    // // --- Constants to define the JOIN ---
    // const MANY_TABLE: Self::TableIden;
    // const MANY_FK_COL: Self::TableIden; // The foreign key on the "many" table
    // const MANY_ALIAS_NAME: Self::TableIden; // The name for the JSON_AGG column, e.g., "credentials"

    // /// A generic method that builds and executes the one-to-many join query.
    // async fn get_joined_opt(
    //     &self,
    //     ctx: &StoreCtx,
    //     id: &Self::IdKind,
    // ) -> Result<Option<Self::JoinedRow>> {
    //     get_joined_opt(ctx, self, id).await
    // }
    // async fn get_joined(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::JoinedRow>;
}
