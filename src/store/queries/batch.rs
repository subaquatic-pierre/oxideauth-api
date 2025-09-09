use modql::field::HasSeaFields;
use modql::filter::{FilterGroups, ListOptions};
use sea_query::{
    Alias, Asterisk, Condition, Expr, IdenList, IntoValueTuple, PostgresQueryBuilder, Query,
    WithQuery,
};
use sea_query_binder::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow};
use sqlx::{query_as_with, Postgres, QueryBuilder, Value};
use uuid::Uuid;

use crate::store::dbx::Dbx;
use crate::store::error::{Error, Result};
use crate::store::opts::ListOptionsValidator;
use crate::store::schema::iden::CommonIden;
use crate::store::stores::base::MetaStore;
use crate::store::utils::{pg_type_of, prepare_audit_fields, push_sq_value};
use crate::store::{ctx::Ctx, manager::StoreManager};
use sea_query::{Iden, IntoIden, TableRef};

pub async fn create_many<T, C, DB>(ctx: &Ctx, store: &DB, data: Vec<C>) -> Result<Vec<T>>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    C: HasSeaFields,
{
    // --- Early exit: nothing to do, return empty result.
    if data.is_empty() {
        return Ok(vec![]);
    }

    ListOptionsValidator::validate_limit(data.len() as i64)?;

    let user_id = ctx.user_id();
    let mut query = Query::insert();

    query.into_table(DB::TABLE);

    // flag to only set columns for the first item
    // do not add columns again for any more items
    let mut is_first = true;

    for el in data {
        let mut fields = el.not_none_sea_fields();

        if DB::HAS_AUDIT_FIELDS {
            prepare_audit_fields(&mut fields, user_id, true);
        }

        let (cols, vals) = fields.for_sea_insert();

        // add columns if not already added, .ie first iteration
        if is_first {
            query.columns(cols);
            // update is_first to skip for all next iterations
            is_first = true;
        }

        query.values(vals)?;
    }

    query.returning_all();

    let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
    let sqlx_query = query_as_with::<_, T, _>(&sql, values);

    let ret = store.db().fetch_all(sqlx_query).await?;

    Ok(ret)
}

pub async fn update_many<T, DB, U>(ctx: &Ctx, store: &DB, data: Vec<(DB::Id, U)>) -> Result<Vec<T>>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
    U: HasSeaFields + Clone,
{
    // exit: nothing to do, return empty result.
    if data.is_empty() {
        return Ok(vec![]);
    }

    // validate list options, ie. max limit
    ListOptionsValidator::validate_limit(data.len() as i64)?;

    // build list of column names as strings once (for SET clause and v alias).
    let mut col_names: Vec<String> = vec![];

    // construct the initial statement
    let update_statement = format!("UPDATE {} AS t SET ", DB::TABLE.to_string());

    // initialize the query builder with the initial statement
    let mut qb = QueryBuilder::<Postgres>::new(update_statement);

    for (i, (id, el)) in data.into_iter().enumerate() {
        // get type of element ID
        // all IDs should be of type UUID
        let id_type = match Uuid::parse_str(&id.to_string()) {
            Ok(id) => "::uuid".to_string(),
            Err(e) => "::text".to_string(),
        };

        // get all fields from each element in data array
        let mut fields = el.all_sea_fields();

        // prepare audit fields if model HAS_AUDIT_FIELDS
        if DB::HAS_AUDIT_FIELDS {
            prepare_audit_fields(&mut fields, ctx.user_id(), false);
        }

        // determine the update columns (and order) from the first payload.
        if i == 0 {
            let (cols, vals) = fields.clone().for_sea_insert();

            // build columns names, this is used later in the query string too
            cols.iter().for_each(|el| col_names.push(el.to_string()));

            // SET t.col = v.col, ...
            let set_statement = col_names
                .iter()
                .map(|col| format!("{col} = COALESCE(v.{col}, t.{col})"))
                .collect::<Vec<String>>()
                .join(", ");
            qb.push(set_statement);

            // FROM (VALUES ...)
            // open value statement
            qb.push(" FROM (VALUES ");
        } else {
            // add comma after each row, skip first row
            qb.push(", ");
        }

        // open value row
        qb.push("(");

        // this is row for element, (id, name, email, ...)
        // always start id
        qb.push_bind(id.to_string());
        qb.push(id_type);
        for field in fields {
            qb.push(", ");

            match field.sea_value() {
                Some(v) => {
                    push_sq_value(&mut qb, v);
                    let pg_type = format!("::{}", pg_type_of(v));
                    qb.push(pg_type);
                }
                // should never reach this value
                None => {
                    qb.push("NULL");
                }
            }
        }

        // close value row
        qb.push(")");
    }
    // close value statement
    qb.push(")");

    // ) AS v(id, col1, col2, ...)
    let id_name = CommonIden::Id.to_string();
    let as_statement = format!(" AS v({}, {})", id_name, col_names.join(", "));
    qb.push(as_statement);

    // WHERE t.id = v.id RETURNING t.*
    qb.push("WHERE t.id = v.id RETURNING t.*");

    // execute and return updated rows
    let query = qb.build_query_as::<T>();
    let ret = store.db().fetch_all(query).await?;

    Ok(ret)
}

pub async fn delete_many<T, DB>(ctx: &Ctx, store: &DB, ids: Vec<DB::Id>) -> Result<Vec<T>>
where
    DB: MetaStore,
    T: for<'r> FromRow<'r, PgRow> + Send + Sync + Unpin,
{
    // --- Early exit: nothing to do, return empty result.
    if ids.is_empty() {
        return Ok(vec![]);
    }

    ListOptionsValidator::validate_limit(ids.len() as i64)?;

    let mut query = Query::delete();

    query
        .from_table(DB::TABLE)
        .and_where(Expr::col(CommonIden::Id).is_in(ids))
        .returning_all();

    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    let sqlx = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let ret = store.db().fetch_all(sqlx).await?;

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serial_test::serial;
    use sqlx::{query_as, Postgres};

    use crate::{
        dev::init::init_test,
        store::{
            queries::crud::create,
            schema::account::{AccountCreate, AccountRow, AccountUpdate},
            stores::account::AccountStore,
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_update_many() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();

        let acc_store = AccountStore::new(dbx);

        let ctx = Ctx::new_root();

        let data = AccountCreate::default();
        // println!("DATA 1: {:#?}", data);
        let ret1: AccountRow = create(&ctx, &acc_store, data).await?;

        let mut data = AccountCreate::default();
        // println!("DATA 2: {:#?}", data);
        data.email = "change".to_string();
        let ret2: AccountRow = create(&ctx, &acc_store, data).await?;

        let c1 = AccountUpdate::default();
        let mut c2 = AccountUpdate::default();
        c2.name = None;

        let data = vec![(ret1.id, c1), (ret2.id, c2)];

        let r: Vec<AccountRow> = update_many(&ctx, &acc_store, data).await?;

        // println!("RETURNED {:#?}", r);

        Ok(())
    }
}

// UPDATE account AS t
// SET
//   name        = COALESCE(v.name,        t.name),
//   acc_type    = COALESCE(v.acc_type,    t.acc_type),
//   provider    = COALESCE(v.provider,    t.provider),
//   description = COALESCE(v.description, t.description),
//   verified    = COALESCE(v.verified,    t.verified),
//   enabled     = COALESCE(v.enabled,     t.enabled),
//   meta        = COALESCE(v.meta,        t.meta),
//   updated_by  = v.updated_by,                 -- or a single $param / CURRENT_USER
//   updated_at  = v.updated_at                  -- or NOW()
// FROM (
//   VALUES
//     -- row 1: (id, name, acc_type, provider, description, verified, enabled, meta, updated_by, updated_at)
//     ($1, $2,  $3,       $4,       $5,          $6,       $7,      $8,   $9,         $10),
//     -- row 2:
//     ($11,$12, $13,      $14,      $15,         $16,      $17,     $18,  $19,        $20)
// ) AS v (
//   id,
//   name,
//   acc_type,
//   provider,
//   description,
//   verified,
//   enabled,
//   meta,
//   updated_by,
//   updated_at
// )
// WHERE t.id = v.id
// RETURNING t.*;
