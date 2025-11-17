use modql::filter::{FilterGroups, ListOptions};
use sea_query::{Asterisk, Condition, PostgresQueryBuilder, Query};
use sea_query::{Expr, Func, Iden};
use sea_query_binder::SqlxBinder;
use sqlx::Row;
use sqlx::{postgres::PgRow, FromRow};
use sqlx::{query_as_with, query_scalar_with, query_with, Value};

use crate::store::dbx::PgDbx;
use crate::store::error::{StoreError, StoreResult};
use crate::store::queries::meta::{
    ContainsFilter, ContainsFilterQueryMeta, CountManyQueryMeta, ReadQueryMeta,
};
use crate::store::traits::dbx::DbExecutor;
use crate::store::traits::meta::{StoreId, TableIden};
use crate::store::{ctx::StoreCtx, manager::StoreManager};
use crate::store::{traits::meta::Store, utils::ListOptionsValidator};

/// Counts the total number of entities (rows) in a table that match an
/// optional set of filters.
///
/// This is a generic function used to determine the size of a filtered result
/// set without fetching all the data.
///
/// # Type Parameters
///
/// * `E`: The database executor trait implementation (`DbExecutor`).
/// * `F`: A type that can be converted into `FilterGroups` (e.g., your `AccountFilter` struct).
/// * `I`: The identifier for the table being queried (`TableIden`).
///
/// # Arguments
///
/// * `_ctx`: The store context (currently unused, denoted by `_`).
/// * `dbx`: The database executor used to run the query.
/// * `filter`: An optional set of filters (`F`) to apply to the count. If `None`,
///   all rows in the table will be counted.
/// * `meta`: Metadata about the read query, containing the target table identifier (`I`).
///
/// # Query Performed (Example)
///
/// If `table` is `account` and a filter for `email` is provided, the SQL generated is:
///
/// ```sql
/// SELECT COUNT(*) AS count FROM account WHERE email = $1
/// ```
///
/// # Returns
///
/// A `StoreResult<i64>` containing:
/// * `Ok(count)`: The total number of rows matching the optional filters.
/// * `Err(StoreError)`: If there is an issue converting the filters or executing the query.
pub async fn count<E: DbExecutor, F: Into<FilterGroups>, I: TableIden>(
    _ctx: &StoreCtx,
    dbx: &E,
    filter: Option<F>,
    meta: &ReadQueryMeta<I>,
) -> StoreResult<i64> {
    let mut query = Query::select();

    // SELECT COUNT(*)
    query
        .expr_as(Func::count(Expr::col(Asterisk)), "count")
        .from(meta.table);

    // apply filter
    if let Some(filter) = filter {
        let filters: FilterGroups = filter.into();
        let cond: Condition = filters.try_into()?;
        query.cond_where(cond);
    }

    // build SQL and values
    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    let query = sqlx::query_as_with(&sql, vals);
    let count: (i64,) = dbx.fetch_one(query).await?;

    Ok(count.0)
}

/// Counts the number of related entities in a "many" (or child) table
/// based on a foreign key relationship to a single "one" (or parent) entity ID.
///
/// This is typically used for calculating the number of child records associated
/// with a parent record (e.g., counting the number of comments for a single post).
///
/// # Type Parameters
///
/// * `E`: The database executor trait implementation (`DbExecutor`).
/// * `I`: The identifier for the table being counted (`TableIden`).
///
/// # Arguments
///
/// * `ctx`: The store context, often used for authorization or transaction handling.
/// * `dbx`: The database executor used to run the query.
/// * `id`: The unique identifier (`StoreId`) of the parent entity. This value
///   is used to filter the child table on the foreign key column.
/// * `meta`: Metadata about the count query, including:
///     * `table`: The identifier of the many (child) table being counted.
///     * `fk`: The name of the foreign key column in the child table that links
///       back to the parent entity.
///
/// # Query Performed (Example)
///
/// If `table` is `comments` and `fk` is `post_id`, the SQL generated is:
///
/// ```sql
/// SELECT COUNT(*) FROM comments WHERE post_id = $1
/// ```
///
/// # Returns
///
/// A `StoreResult<i64>` containing:
/// * `Ok(count)`: The total number of rows in the child table matching the
///   provided foreign key `id`.
/// * `Err(StoreError)`: If the query fails to execute.
pub async fn count_many<E: DbExecutor, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &E,
    id: &impl StoreId,
    meta: &CountManyQueryMeta<I>,
) -> StoreResult<i64> {
    let mut query = Query::select();

    // SELECT COUNT(*) FROM {many_table}
    query
        .expr(Func::count(Expr::col(Asterisk)))
        .from(meta.table)
        .and_where(Expr::col(meta.fk).eq(id.clone())); // WHERE foreign_key = ?

    let (sql, values) = query.build_sqlx(PostgresQueryBuilder);

    // Here we can't use `try_get("count")` as easily without an alias,
    // so we fetch into a tuple, which is very efficient.
    let query = sqlx::query_as_with(&sql, values);
    let count: (i64,) = dbx.fetch_one(query).await?;

    Ok(count.0)
}

/// Counts the number of entities that satisfy a 'contains' condition on a column.
///
/// This function is generic over the DbExecutor and the TableIden.
///
/// # Arguments
/// * `_ctx` - The store context (ignored for simplicity here).
/// * `dbx` - The database executor.
/// * `value` - The value to check for containment (Array of Strings or JSON).
/// * `meta` - Metadata including the table and the target column name.
///
/// # Returns
/// A StoreResult containing the count (i64).
pub async fn count_contains<E, I>(
    _ctx: &StoreCtx,
    dbx: &E,
    value: ContainsFilter,
    meta: &ContainsFilterQueryMeta<I>,
) -> StoreResult<i64>
where
    E: DbExecutor,
    I: TableIden,
{
    let mut query = Query::select();

    // SELECT COUNT(*)
    query
        .expr_as(Func::count(Expr::col(Asterisk)), "count")
        .from(meta.table);

    // Build the expression for the containment check (@>)
    let expr = match value {
        // For Array: "col_name" @> $1
        ContainsFilter::Array(tags) => {
            Expr::cust_with_values(format!(r#""{}" @> $"#, meta.col.to_string()), [tags])
        }
        // For JSON: "col_name" @> $1 (checks for key/value containment in JSONB)
        ContainsFilter::Json(json) => {
            Expr::cust_with_values(format!(r#""{}" @> $"#, meta.col.to_string()), [json])
        }
    };

    // Apply the containment expression as a WHERE clause
    query.cond_where(expr);

    // build SQL and values
    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    // Execute query
    let sqlx_query = sqlx::query_as_with(&sql, vals);

    // fetch_one returns a tuple (i64,) for COUNT(*)
    let count: (i64,) = dbx.fetch_one(sqlx_query).await?;

    Ok(count.0)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::{from_value, json};
    use serial_test::serial;

    use crate::{
        dev::init::init_test,
        store::{
            contains::FilterByContains,
            ctx::StoreCtx,
            entities::account::{AccountFilter, AccountForCreate, AccountRow},
            meta::ContainsFilterStore,
            queries::crud::create,
            stores::account::AccountStore,
            traits::{
                crud::{Create, Get},
                meta::ReadStore,
            },
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_count_after_inserts_matches_number_of_rows() -> StoreResult<()> {
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let acc_store = AccountStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        let mut ac = |i: usize| {
            let mut data = AccountForCreate::default();
            data.email = format!("user{i}{i}{i}@example.com");
            data.avatar_url = Some(format!("TEST_FILTER"));
            data
        };

        // Create N accounts
        let n = 3usize;
        let mut created: Vec<AccountRow> = Vec::with_capacity(n);
        for i in 0..n {
            let row = ac(i);
            created.push(acc_store.create(&ctx, row).await?);
        }

        // Verify via get()
        for r in &created {
            let found = acc_store.get(&ctx, &r.id).await?;
            assert_eq!(found.id, r.id);
        }

        let filter: AccountFilter =
            from_value(json!({"avatar_url":{"$contains":"TEST_FILTER"}})).unwrap();

        // Generate meta and call count with the correct arguments
        let meta = acc_store.read_meta();
        let total = count(&ctx, &dbx, Some(filter), &meta).await?;
        assert_eq!(total as usize, n);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_count_contains_matches_array_count() -> StoreResult<()> {
        // 1. Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        // Assuming a store that manages entities with a 'tags' array column
        let acc_store = AccountStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        // Define the common array of tags to check for containment
        let test_tags = vec!["premium".to_string(), "active".to_string()];
        let unique_tag = "test_tag_contains".to_string(); // Used for uniqueness

        let mut ac = |i: usize| {
            let mut data = AccountForCreate::default();
            // Ensure unique email
            data.email = format!("contains_user{i}@example.com");
            data.tags = vec![
                test_tags[0].clone(),
                test_tags[1].clone(),
                unique_tag.clone(),
            ];
            data
        };

        // 2. Create N accounts, all containing the 'test_tags'
        let n = 4usize;
        let mut created: Vec<AccountRow> = Vec::with_capacity(n);
        for i in 0..n {
            let row = ac(i);
            created.push(acc_store.create(&ctx, row).await?);
        }

        // 3. Prepare the ContainsFilter and Query Meta

        // Create the filter for array containment
        let contains_filter = ContainsFilter::Array(test_tags);

        let meta = acc_store.contains_tags_meta();

        let total = count_contains(&ctx, &dbx, contains_filter, &meta).await?;

        // All 4 created accounts should contain the tags, so the count must be 4
        assert_eq!(
            total as usize, n,
            "The count_contains result should match the number of inserted rows."
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_count_contains_partial_and_missing_tags() -> StoreResult<()> {
        // 1. Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let acc_store = AccountStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        // Define the required tags for the count check (the subset we are looking for)
        let required_tags = vec!["test_here".to_string(), "test_again".to_string()];

        // --- Create Test Data ---

        // A. Fully Contained Accounts (EXPECTED COUNT = 2)
        // These accounts contain ALL required_tags plus others.
        let fully_contained_count = 2usize;
        for i in 0..fully_contained_count {
            let mut data = AccountForCreate::default();
            data.email = format!("contained_user_{}@example.com", i);
            // Includes BOTH "premium" and "active"
            data.tags = vec![
                required_tags[0].clone(),
                required_tags[1].clone(),
                "extra".to_string(),
            ];
            acc_store.create(&ctx, data).await?;
        }

        // B. Partially Contained Account (EXCLUDED)
        // Missing "active" tag. Should NOT be counted.
        let mut data_partial = AccountForCreate::default();
        data_partial.email = "partial_user@example.com".to_string();
        data_partial.tags = vec![required_tags[0].clone(), "basic".to_string()]; // Only has "premium"
        acc_store.create(&ctx, data_partial).await?;

        // C. Empty or Irrelevant Tags Account (EXCLUDED)
        // Has none of the required tags. Should NOT be counted.
        let mut data_irrelevant = AccountForCreate::default();
        data_irrelevant.email = "irrelevant_user@example.com".to_string();
        data_irrelevant.tags = vec!["unrelated".to_string()];
        acc_store.create(&ctx, data_irrelevant).await?;

        // 2. Prepare the ContainsFilter and Query Meta

        // The filter looks for the full set of required tags
        let contains_filter = ContainsFilter::Array(required_tags);

        let meta = acc_store.contains_tags_meta();

        // 3. Call count_contains and Verify
        let total = count_contains(&ctx, &dbx, contains_filter, &meta).await?;

        // Only the 2 fully contained accounts should be counted.
        assert_eq!(
            total as usize, fully_contained_count,
            "The count_contains result should match ONLY the fully contained rows (Expected: 2)."
        );

        let contains_filter = ContainsFilter::Array(vec!["test_here".to_string()]);

        let total = count_contains(&ctx, &dbx, contains_filter, &meta).await?;
        assert_eq!(total as usize, 3, "Should include 3");

        Ok(())
    }
}
