use sea_query::{Asterisk, Condition, Expr, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use serde_json::Value as JsonValue;

use crate::store::{
    ctx::StoreCtx,
    dbx::{DbExecutor, PgDbx},
    error::{StoreError, StoreResult},
    queries::meta::{ContainsFilter, ContainsFilterQueryMeta},
    traits::meta::{StoreRow, TableIden},
};

/// Fetches all entities (rows) from a table where a specified column contains
/// the provided value. This function utilizes PostgreSQL's containment operator (`@>`),
/// which is typically used for querying array or JSONB columns.
///
/// # Note on Limit Checking
///
/// The comment `// count ensure list limit not exceeded` suggests an upstream requirement
/// to check limits before fetching. This method focuses on executing the filtered
/// selection query itself.
///
/// # Type Parameters
///
/// * `E`: The database executor trait implementation (`DbExecutor`).
/// * `T`: The type representing the fetched row (must implement `StoreRow`).
/// * `I`: The identifier for the table being queried (`TableIden`).
///
/// # Arguments
///
/// * `ctx`: The store context (currently unused in the provided implementation).
/// * `dbx`: The database executor used to run the query.
/// * `value`: The containment value, wrapped in `ContainsFilter`:
///     * `ContainsFilter::Array(Vec<String>)`: Used for array containment checks (e.g., checking if an array column contains all given strings).
///     * `ContainsFilter::Json(Value)`: Used for JSONB containment checks (e.g., checking if a JSONB column contains a specific key/value subset).
/// * `meta`: Metadata about the containment query, including:
///     * `table`: The identifier of the table being queried.
///     * `col`: The name of the column on which the containment check is performed.
///
/// # Query Performed (Example)
///
/// If `table` is `post`, `col` is `tags`, and `value` is `ContainsFilter::Array(["rust", "async"])`,
/// the core SQL condition generated is:
///
/// ```sql
/// ... WHERE "tags" @> $1
/// ```
///
/// # Returns
///
/// A `StoreResult<Vec<T>>` containing:
/// * `Ok(Vec<T>)`: A vector of entities (rows) that satisfy the containment condition.
/// * `Err(StoreError)`: If the query fails to execute.
pub async fn filter_by_value_contains<E: DbExecutor, T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &E,
    value: ContainsFilter,
    meta: &ContainsFilterQueryMeta<I>,
) -> StoreResult<Vec<T>> {
    // count ensure list limit not exceeded

    let mut query = Query::select();
    query.from(meta.table).column((meta.table, Asterisk));

    let expr = match value {
        ContainsFilter::Array(tags) => {
            Expr::cust_with_values(format!(r#""{}" @> $"#, meta.col.to_string()), [tags])
        }
        ContainsFilter::Json(json) => {
            Expr::cust_with_values(format!(r#""{}" @> $"#, meta.col.to_string()), [json])
        }
    };

    query.and_where(expr);

    let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);

    let query = sqlx::query_as_with(&sql, vals);

    let res = dbx.fetch_all(query).await?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use env_logger::filter;
    use serde_json::{from_value, json};
    use serial_test::serial;

    use crate::{
        dev::init::init_test,
        store::{
            ctx::StoreCtx,
            entities::permission::{
                PermissionFilter, PermissionForCreate, PermissionIden, PermissionMeta,
                PermissionRow,
            },
            queries::crud::create,
            stores::permission::PermissionStore,
            traits::{
                crud::{Create, Get, List},
                meta::ReadStore,
            },
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_filter_by_contains_meta() -> StoreResult<()> {
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = PermissionStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        let c_perm = |i| {
            let mut perm = PermissionForCreate::default();
            perm.workspace_id = ctx.ns_id;
            perm.name = format!("PERMISSION_GET_MANY_TEST_{i}_i_{i}_i_{i}");
            if (i < 2) {
                perm.meta = PermissionMeta {
                    schema_version: "1".to_string(),
                };
            } else {
                perm.meta = PermissionMeta {
                    schema_version: "2".to_string(),
                };
            }
            perm
        };

        let perm_count = 5;
        let mut perms = vec![];

        for i in 0..perm_count {
            let n = c_perm(i);

            perms.push(store.create(&ctx, n).await?);
        }

        let meta = ContainsFilterQueryMeta {
            table: PermissionIden::Table,
            col: PermissionIden::Meta,
        };

        let schema_1: Vec<PermissionRow> = filter_by_value_contains(
            &ctx,
            &dbx,
            ContainsFilter::Json(json!({"schema_version":"1"})),
            &meta,
        )
        .await?;

        let schema_2: Vec<PermissionRow> = filter_by_value_contains(
            &ctx,
            &dbx,
            ContainsFilter::Json(json!({"schema_version":"2"})),
            &meta,
        )
        .await?;

        assert_eq!(2, schema_1.len());
        assert_eq!(3, schema_2.len());

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_filter_by_contains_tags() -> StoreResult<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = PermissionStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        // -- Create test data with different tags
        let c_perm = |i| {
            let mut perm = PermissionForCreate::default();
            perm.workspace_id = ctx.ns_id;
            perm.name = format!("PERMISSION_TAGS_TEST_{i}");
            // Assign different tags to two distinct groups
            if i < 2 {
                perm.tags = vec!["system".to_string(), "critical".to_string()];
            } else {
                perm.tags = vec!["user".to_string(), "general".to_string()];
            }
            perm
        };

        let perm_count = 5;
        for i in 0..perm_count {
            let n = c_perm(i);
            store.create(&ctx, n).await?;
        }

        // -- Define query metadata for the 'tags' column
        let meta = ContainsFilterQueryMeta {
            table: PermissionIden::Table,
            col: PermissionIden::Tags, // Assumes 'Tags' is a variant on your Iden
        };

        // -- Run Filters and Assertions
        // Test 1: Filter by a single tag present in the first group of 2 permissions
        let system_perms: Vec<PermissionRow> = filter_by_value_contains(
            &ctx,
            &dbx,
            ContainsFilter::Array(vec!["system".to_string()]),
            &meta,
        )
        .await?;
        assert_eq!(
            2,
            system_perms.len(),
            "Should find 2 permissions with 'system' tag"
        );

        // Test 2: Filter by a single tag present in the second group of 3 permissions
        let user_perms: Vec<PermissionRow> = filter_by_value_contains(
            &ctx,
            &dbx,
            ContainsFilter::Array(vec!["user".to_string()]),
            &meta,
        )
        .await?;
        assert_eq!(
            3,
            user_perms.len(),
            "Should find 3 permissions with 'user' tag"
        );

        // Test 3: Filter for all tags in the first group to test '@>' functionality
        let critical_system_perms: Vec<PermissionRow> = filter_by_value_contains(
            &ctx,
            &dbx,
            ContainsFilter::Array(vec!["critical".to_string(), "system".to_string()]),
            &meta,
        )
        .await?;
        assert_eq!(
            2,
            critical_system_perms.len(),
            "Should find 2 permissions with both 'critical' and 'system' tags"
        );

        // Test 4: Filter by tags that do not coexist in any single record
        let no_match_perms: Vec<PermissionRow> = filter_by_value_contains(
            &ctx,
            &dbx,
            ContainsFilter::Array(vec!["system".to_string(), "general".to_string()]),
            &meta,
        )
        .await?;
        assert_eq!(
            0,
            no_match_perms.len(),
            "Should find 0 permissions with both 'system' and 'general' tags"
        );

        Ok(())
    }
}
