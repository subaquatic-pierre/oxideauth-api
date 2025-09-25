use sea_query::Iden;
use sqlx::{postgres::PgRow, FromRow};

use crate::store::{
    ctx::StoreCtx,
    error::{Result, StoreError},
    traits::join::JoinOneToManyStore,
};

pub async fn get_joined_opt<T, DB>(ctx: &StoreCtx, store: &DB, id: &DB::IdKind) -> Result<Option<T>>
where
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    DB: JoinOneToManyStore,
{
    todo!()
}

pub async fn get_joined<T, DB>(ctx: &StoreCtx, store: &DB, id: &DB::IdKind) -> Result<T>
where
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    DB: JoinOneToManyStore,
{
    match get_joined_opt(ctx, store, id).await? {
        Some(t) => Ok(t),
        None => Err(StoreError::EntityNotFound {
            entity: DB::TABLE_NAME.to_string(),
            id: id.to_string(),
        }),
    }
}

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
