use async_trait::async_trait;
use sea_query::Iden;
use sqlx::{postgres::PgRow, FromRow};

use crate::store::ctx::StoreCtx;

use crate::store::error::Result;
use crate::store::queries::join::get_joined_opt;
use crate::store::traits::meta::BaseMetaStore;

#[async_trait]
pub trait JoinOneToManyStore
where
    Self: BaseMetaStore,
{
    // --- Metadata for the "Many" side of the relationship ---
    type ManyRow: for<'r> FromRow<'r, PgRow> + Send + Sync;

    // --- Metadata for the final, combined result ---
    type JoinedRow: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin;

    // --- Constants to define the JOIN ---
    const MANY_TABLE: Self::TableIden;
    const MANY_FK_COL: Self::TableIden; // The foreign key on the "many" table
    const MANY_ALIAS_NAME: Self::TableIden; // The name for the JSON_AGG column, e.g., "credentials"

    /// A generic method that builds and executes the one-to-many join query.
    async fn get_joined_opt(
        &self,
        ctx: &StoreCtx,
        id: &Self::IdKind,
    ) -> Result<Option<Self::JoinedRow>> {
        get_joined_opt(ctx, self, id).await
    }
    async fn get_joined(&self, ctx: &StoreCtx, id: &Self::IdKind) -> Result<Self::JoinedRow>;
}

// use sea_query::{Iden, IntoIden, SelectStatement};
// use std::fmt::Debug;

// // The generic trait
// #[async_trait]
// pub trait JoinOneToMany
// where
//     Self: BaseMetaStore, // Depends on the base BaseMetaStore
// {
//     /// The Iden of the "many" table (e.g., Credential).
//     type ManyIden: Iden + Copy + Debug;
//     /// The struct for a single row of the "many" table (e.g., CredentialRow).
//     type ManyRow: for<'r> FromRow<'r, PgRow> + Send + Sync;
//     /// The final combined struct (e.g., AccountWithCredentials).
//     type Joined: for<'r> FromRow<'r, PgRow> + Send + Sync;

//     /// The name of the resulting JSON field (e.g., "credentials").
//     const MANY_ALIAS: &'static str;

//     /// The foreign key column on the "many" table (e.g., Credential::AccountId).
//     fn many_foreign_key() -> Self::ManyIden;

//     /// The primary key column on the "one" table (e.g., Account::Id).
//     fn one_primary_key() -> impl Iden + Copy;

//     /// Generic method to build the JSON_AGG query.
// fn get_joined(&self, id: Self::IdKind) -> SelectStatement {
// --- STEP 1: Perform the count check first ---
// let mut count_query = Query::select();
// count_query
//     .expr(Expr::col(Asterisk).count())
//     .from(Self::MANY_TABLE)
//     .and_where(Expr::col(Self::MANY_FK_COL).eq(id.clone())); // clone might be needed

// let (sql, values) = count_query.build_sqlx(PostgresQueryBuilder);
// let count: (i64,) = sqlx::query_as_with(&sql, values)
//     .fetch_one(self.db().pool())
//     .await?;
// let count = count.0;

// // --- STEP 2: Check against the limit ---
// if count > Self::JOIN_LIMIT {
//     return Err(StoreError::LimitExceeded {
//         entity: std::any::type_name::<Self::ManyRow>(),
//         count,
//         limit: Self::JOIN_LIMIT,
//     });
// }
//     // Custom Iden for the JSON_AGG function
//     #[derive(Iden)]
//     struct JsonAgg;

//     // The two arguments for COALESCE
//     let json_agg_expr = Expr::expr(
//         Func::cust(JsonAgg).arg(Expr::col((Self::MANY_TABLE, Asterisk)))
//     )
//     .filter(Expr::col((Self::MANY_TABLE, Self::MANY_FK_COL)).is_not_null());

//     let default_value = Expr::val("[]"); // The literal '[]'

//     let mut query = Query::select();
//     query
//         .from(Self::TABLE_NAME)
//         .expr(Expr::col((Self::TABLE_NAME, Asterisk)))
//         // Use expr_as to create `COALESCE(...) AS alias_name`
//         .expr_as(
//             Expr::func(Func::coalesce([json_agg_expr, default_value])),
//             Alias::new(Self::ALIAS_NAME),
//         )
//         .left_join(
//             Self::MANY_TABLE,
//             Expr::col((Self::TABLE_NAME, Self::TABLE_PK)).equals(
//                 Self::MANY_TABLE,
//                 Self::MANY_FK_COL,
//             ),
//         )
//         .and_where(Expr::col((Self::TABLE_NAME, Self::TABLE_PK)).eq(id))
//         .group_by_col((Self::TABLE_NAME, Self::TABLE_PK));

// let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
//         let sqlx_query = sqlx::query_as_with::<_, Self::Joined, _>(&sql, values);

//         let result = self.db().fetch_one(sqlx_query).await?;
//         Ok(result)
// }

// }

// In your account store implementation file
// #[async_trait]
// impl JoinOneToMany for AccountStore {
//     type ManyIden = Credential; // The Iden for the 'credential' table
//     type ManyRow = CredentialRow;
//     type Joined = AccountWithCredentials;

//     const MANY_ALIAS: &'static str = "credentials";

//     fn many_foreign_key() -> Self::ManyIden {
//         Credential::AccountId
//     }

//     fn one_primary_key() -> impl Iden + Copy {
//         Account::Id
//     }
// }
