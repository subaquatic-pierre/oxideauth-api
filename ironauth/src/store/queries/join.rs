use sea_query::Iden;
use sqlx::{postgres::PgRow, FromRow};

use crate::store::{
    ctx::StoreCtx,
    dbx::Dbx,
    error::{Result, StoreError},
    queries::meta::GetJoinedQueryMeta,
    traits::{
        join::JoinOneToManyStore,
        meta::{HasId, StoreId, StoreRow, TableIden},
    },
};

pub async fn get_joined_opt<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &GetJoinedQueryMeta<I>,
) -> Result<Option<T>> {
    todo!()
}

pub async fn get_joined<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &GetJoinedQueryMeta<I>,
) -> Result<T> {
    match get_joined_opt(ctx, dbx, id, meta).await? {
        Some(t) => Ok(t),
        None => Err(StoreError::EntityNotFound {
            entity: meta.table.to_string(),
            id: id.to_string(),
        }),
    }
}

//     /// Generic method to build the JSON_AGG query.
// fn get_joined(&self, id: Self::IdKind) -> SelectStatement {
// let meta = CountQueryMeta {
//     table: meta.many_table
// }
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

// Counts the number of related items for a given parent ID.
// async fn count_many(&self, _ctx: &StoreCtx, id: Self::IdKind) -> Result<i64> {
//     let mut query = Query::select();

//     // SELECT COUNT(*) FROM {many_table}
//     query
//         .expr(Func::count(Expr::col(Asterisk)))
//         .from(Self::MANY_TABLE)
//         .and_where(Expr::col(Self::MANY_FK_COL).eq(id)); // WHERE foreign_key = ?

//     let (sql, values) = query.build_sqlx(PostgresQueryBuilder);

//     // Here we can't use `try_get("count")` as easily without an alias,
//     // so we fetch into a tuple, which is very efficient.
//     let count: (i64,) = sqlx::query_as_with(&sql, values)
//         .fetch_one(self.db().pool())
//         .await?;

//     Ok(count.0)
// }
