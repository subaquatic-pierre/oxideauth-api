use modql::filter::{FilterGroups, ListOptions};
use sea_query::{
    Alias, Asterisk, CommonTableExpression, Condition, Expr, Func, Iden, JoinType, OnConflict,
    PostgresQueryBuilder, Query, SelectStatement, SimpleExpr, Value,
};
use sea_query_binder::SqlxBinder;
use serde_json::json;
use sqlx::{postgres::PgRow, FromRow};

use crate::store::{
    ctx::StoreCtx,
    dbx::Dbx,
    error::{Result, StoreError},
    queries::{
        count::{count, count_many},
        meta::{CountManyQueryMeta, ManyToManyQueryMeta, OneToManyQueryMeta, ReadQueryMeta},
    },
    traits::meta::{HasId, StoreId, StoreRow, TableIden},
    utils::{pg_type_of, ListOptionsValidator, LIST_LIMIT_MAX},
};

#[derive(Iden)]
pub struct ManyCte;

pub async fn get_one_to_many_opt<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &OneToManyQueryMeta<I>,
) -> Result<Option<T>> {
    // Guard: count rows on the many side via its FK -> single PK
    let count_meta = CountManyQueryMeta {
        table: meta.many_table,
        fk: meta.many_fk,
    };
    let count = count_many(ctx, dbx, id, &count_meta).await?;
    if count > LIST_LIMIT_MAX {
        return Err(StoreError::ListLimitExceeded {
            max: LIST_LIMIT_MAX,
            actual: count,
        });
    }

    // Define the query for the Common Table Expression (CTE)
    let cte_query = Query::select()
        .from(meta.many_table)
        .column(Asterisk)
        .to_owned();

    // Create the CTE object
    let common_table_expr = CommonTableExpression::new()
        .table_name(ManyCte) // Name our CTE `CredentialCte`
        .query(cte_query) // Use the query defined above
        .to_owned();

    // Create custom aggregate and coalesce expression
    let cust = format!(
        r#"COALESCE(jsonb_agg("{many_cte}") FILTER (WHERE "{many_cte}"."{many_pk}" IS NOT NULL), '[]'::jsonb)"#,
        many_cte = ManyCte.to_string(),
        many_pk = meta.many_pk.to_string()
    );
    let join_agg = Expr::cust(cust);

    // Build the main query
    let mut main_query = Query::select();
    main_query
        .from(meta.single_table)
        .column((meta.single_table, Asterisk))
        // we need to use meta.agg_alias in order to deserialize to the correct field on the type T which is `single_table_row.collection`, ie. account.credentials
        .expr_as(join_agg, meta.agg_alias)
        .join(
            JoinType::LeftJoin,
            ManyCte, // Join to the CTE, not the original table
            Expr::col((meta.single_table, meta.single_pk)).equals((ManyCte, meta.many_fk)),
        )
        .and_where(Expr::col((meta.single_table, meta.single_pk)).eq(id.clone()))
        .group_by_col((meta.single_table, meta.single_pk));

    // Attach the WithClause to the main query
    let final_query = main_query.with(common_table_expr.into());

    let (sql, vals) = final_query.build_sqlx(PostgresQueryBuilder);

    let query = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let res: Option<T> = dbx.fetch_optional(query).await?;

    Ok(res)
}

pub async fn get_one_to_many<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &OneToManyQueryMeta<I>,
) -> Result<T> {
    match get_one_to_many_opt(ctx, dbx, id, meta).await? {
        Some(t) => Ok(t),
        None => Err(StoreError::EntityNotFound {
            entity: meta.single_table.to_string(),
            id: id.to_string(),
        }),
    }
}

pub async fn list_one_to_many<T: StoreRow, F: Into<FilterGroups> + Clone, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    filter: Option<F>,
    opts: Option<ListOptions>,
    meta: &OneToManyQueryMeta<I>,
) -> Result<Vec<T>> {
    let count_meta = ReadQueryMeta {
        table: meta.single_table,
        pk: meta.single_pk,
        has_audit: meta.has_audit,
    };
    let count = count(ctx, dbx, filter.clone(), &count_meta).await?;
    if count > LIST_LIMIT_MAX {
        return Err(StoreError::ListLimitExceeded {
            max: LIST_LIMIT_MAX,
            actual: count,
        });
    }

    // Define the query for the Common Table Expression (CTE)
    let cte_query = Query::select()
        .from(meta.many_table)
        .column(Asterisk)
        .to_owned();

    // Create the CTE object
    let common_table_expr = CommonTableExpression::new()
        .table_name(ManyCte) // Name our CTE `CredentialCte`
        .query(cte_query) // Use the query defined above
        .to_owned();

    let cust = format!(
        r#"COALESCE(jsonb_agg("{many_cte}") FILTER (WHERE "{many_cte}"."{many_pk}" IS NOT NULL), '[]'::jsonb)"#,
        many_cte = ManyCte.to_string(),
        many_pk = meta.many_pk.to_string()
    );
    let join_agg = Expr::cust(cust);

    // 4. Build the main query
    let mut main_query = Query::select();
    main_query
        .from(meta.single_table)
        .column((meta.single_table, Asterisk))
        .expr_as(join_agg, meta.agg_alias)
        .join(
            JoinType::LeftJoin,
            ManyCte, // Join to the CTE, not the original table
            Expr::col((meta.single_table, meta.single_pk)).equals((ManyCte, meta.many_fk)),
        )
        .group_by_col((meta.single_table, meta.single_pk));

    // TODO: ensure joined list row count does not exceed list limits
    // apply filter to query

    if let Some(filter) = filter {
        let filters: FilterGroups = filter.into();
        let cond: Condition = filters.try_into()?;
        main_query.cond_where(cond);
    }

    // validate list options
    let list_options = ListOptionsValidator::validate_list_opts(opts, meta.has_audit)?;
    // add list options to query, there will always at least be maximum limit
    list_options.apply_to_sea_query(&mut main_query);

    // Attach the WithClause to the main query
    let final_query = main_query.with(common_table_expr.into());

    let (sql, vals) = final_query.build_sqlx(PostgresQueryBuilder);

    let query = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let res: Vec<T> = dbx.fetch_all(query).await?;

    Ok(res)
}

pub async fn get_many_to_many_opt<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &ManyToManyQueryMeta<I>,
) -> Result<Option<T>> {
    // Guard: count rows on the many side via its FK -> single PK
    let count_meta = CountManyQueryMeta {
        table: meta.join_table,
        fk: meta.join_fk,
    };
    let count = count_many(ctx, dbx, id, &count_meta).await?;
    if count > LIST_LIMIT_MAX {
        return Err(StoreError::ListLimitExceeded {
            max: LIST_LIMIT_MAX,
            actual: count,
        });
    }

    // Define the query for the Common Table Expression (CTE)
    let cte_query = Query::select()
        .from(meta.many_table)
        .column(Asterisk)
        .to_owned();

    // Create the CTE object
    let common_table_expr = CommonTableExpression::new()
        .table_name(ManyCte) // Name our CTE `CredentialCte`
        .query(cte_query) // Use the query defined above
        .to_owned();

    // Create custom aggregate and coalesce expression
    let cust = format!(
        r#"COALESCE(jsonb_agg("{many_cte}") FILTER (WHERE "{many_cte}"."{many_pk}" IS NOT NULL), '[]'::jsonb)"#,
        many_cte = ManyCte.to_string(),
        many_pk = meta.many_pk.to_string()
    );
    let join_agg = Expr::cust(cust);

    // Build the main query
    let mut main_query = Query::select();
    main_query
        .from(meta.single_table)
        .column((meta.single_table, Asterisk))
        // we need to use meta.agg_alias in order to deserialize to the correct field on the type T which is `single_table_row.collection`, ie. account.credentials
        .expr_as(join_agg, meta.agg_alias)
        .join(
            JoinType::LeftJoin,
            meta.join_table,
            // meta.join_fk: correlates to single table "primary key", ie. role_permission.role_id
            Expr::col((meta.join_table, meta.join_fk)).equals((meta.single_table, meta.single_pk)),
        )
        .join(
            JoinType::LeftJoin,
            ManyCte, // Join to the CTE, not the original table to avoid column collisions
            // meta.many_fk: correlates to CTE "primary_key", ie. role_permission.permission_id
            Expr::col((meta.join_table, meta.many_fk)).equals((ManyCte, meta.many_pk)),
        )
        .and_where(Expr::col((meta.single_table, meta.single_pk)).eq(id.clone()))
        .group_by_col((meta.single_table, meta.single_pk));

    // Attach the WithClause to the main query
    let final_query = main_query.with(common_table_expr.into());

    let (sql, vals) = final_query.build_sqlx(PostgresQueryBuilder);

    let query = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let res: Option<T> = dbx.fetch_optional(query).await?;

    Ok(res)
}

pub async fn get_many_to_many<T: StoreRow, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    id: &impl StoreId,
    meta: &ManyToManyQueryMeta<I>,
) -> Result<T> {
    match get_many_to_many_opt(ctx, dbx, id, meta).await? {
        Some(t) => Ok(t),
        None => Err(StoreError::EntityNotFound {
            entity: meta.single_table.to_string(),
            id: id.to_string(),
        }),
    }
}

pub async fn list_many_to_many<T: StoreRow, F: Into<FilterGroups> + Clone, I: TableIden>(
    ctx: &StoreCtx,
    dbx: &Dbx,
    filter: Option<F>,
    opts: Option<ListOptions>,
    meta: &ManyToManyQueryMeta<I>,
) -> Result<Vec<T>> {
    let count_meta = ReadQueryMeta {
        table: meta.single_table,
        pk: meta.join_fk,
        has_audit: false,
    };
    let count = count(ctx, dbx, filter.clone(), &count_meta).await?;
    if count > LIST_LIMIT_MAX {
        return Err(StoreError::ListLimitExceeded {
            max: LIST_LIMIT_MAX,
            actual: count,
        });
    }

    // Define the query for the Common Table Expression (CTE)
    let cte_query = Query::select()
        .from(meta.many_table)
        .column(Asterisk)
        .to_owned();

    // Create the CTE object
    let common_table_expr = CommonTableExpression::new()
        .table_name(ManyCte) // Name our CTE `CredentialCte`
        .query(cte_query) // Use the query defined above
        .to_owned();

    // Create custom aggregate and coalesce expression
    let cust = format!(
        r#"COALESCE(jsonb_agg("{many_cte}") FILTER (WHERE "{many_cte}"."{many_pk}" IS NOT NULL), '[]'::jsonb)"#,
        many_cte = ManyCte.to_string(),
        many_pk = meta.many_pk.to_string()
    );
    let join_agg = Expr::cust(cust);

    // Build the main query
    let mut main_query = Query::select();
    main_query
        .from(meta.single_table)
        .column((meta.single_table, Asterisk))
        // we need to use meta.agg_alias in order to deserialize to the correct field on the type T which is `single_table_row.collection`, ie. account.credentials
        .expr_as(join_agg, meta.agg_alias)
        .join(
            JoinType::LeftJoin,
            meta.join_table,
            // meta.join_fk: correlates to single table "primary key", ie. role_permission.role_id
            Expr::col((meta.join_table, meta.join_fk)).equals((meta.single_table, meta.single_pk)),
        )
        .join(
            JoinType::LeftJoin,
            ManyCte, // Join to the CTE, not the original table to avoid column collisions
            // meta.many_fk: correlates to CTE "primary_key", ie. role_permission.permission_id
            Expr::col((meta.join_table, meta.many_fk)).equals((ManyCte, meta.many_pk)),
        )
        .group_by_col((meta.single_table, meta.single_pk));

    if let Some(filter) = filter {
        let filters: FilterGroups = filter.into();
        let cond: Condition = filters.try_into()?;
        main_query.cond_where(cond);
    }

    // validate list options
    let list_options = ListOptionsValidator::validate_list_opts(opts, meta.has_audit)?;
    // add list options to query, there will always at least be maximum limit
    list_options.apply_to_sea_query(&mut main_query);

    // Attach the WithClause to the main query
    let final_query = main_query.with(common_table_expr.into());

    let (sql, vals) = final_query.build_sqlx(PostgresQueryBuilder);

    let query = sqlx::query_as_with::<_, T, _>(&sql, vals);

    let res: Vec<T> = dbx.fetch_all(query).await?;

    Ok(res)
}

pub async fn set_many_to_many_links<I: TableIden, ID: StoreId + Clone>(
    ctx: &StoreCtx, // Ctx might be used for auditing in the future
    dbx: &Dbx,
    self_id: &ID,
    other_ids: Vec<ID>,
    meta: &ManyToManyQueryMeta<I>,
) -> Result<()> {
    let mut tx = dbx.begin().await?;

    // // Delete all existing associations for self_id
    let (sql, vals) = Query::delete()
        .from_table(meta.join_table)
        .and_where(Expr::col(meta.join_fk).eq(self_id.clone()))
        .build_sqlx(PostgresQueryBuilder);

    sqlx::query_with(&sql, vals).execute(&mut *tx).await?;

    // If there are new IDs to link, insert them
    if !other_ids.is_empty() {
        let mut query = Query::insert();
        query
            .into_table(meta.join_table)
            .columns([meta.join_fk, meta.many_fk]);

        // Add a row for each new association
        for other_id in other_ids {
            // Convert each ID directly into a SimpleExpr using .into()
            let row = vec![
                Expr::value(self_id.clone().into()),
                Expr::value(other_id.into()),
            ];
            query.values_panic(row);
        }

        let (sql, vals) = query.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(&sql, vals).execute(&mut *tx).await?;
    }

    tx.commit().await?;

    Ok(())
}

pub async fn attach_link<I: TableIden, ID: StoreId>(
    _ctx: &StoreCtx,
    dbx: &Dbx,
    self_id: &ID,
    other_id: &ID,
    meta: &ManyToManyQueryMeta<I>,
) -> Result<()> {
    // Build an INSERT statement for a single row.
    let (sql, vals) = Query::insert()
        .into_table(meta.join_table)
        .columns([meta.join_fk, meta.many_fk])
        .values_panic(vec![
            Expr::value(self_id.clone().into()),
            Expr::value(other_id.clone().into()),
        ])
        // Optional: Add an "ON CONFLICT DO NOTHING" to prevent errors
        // if the link already exists. This makes the operation idempotent.
        .on_conflict(
            OnConflict::columns([meta.join_fk, meta.many_fk])
                .do_nothing()
                .to_owned(),
        )
        .build_sqlx(PostgresQueryBuilder);

    sqlx::query_with(&sql, vals).execute(dbx.db()).await?;

    Ok(())
}

pub async fn detach_link<I: TableIden, ID: StoreId>(
    _ctx: &StoreCtx,
    dbx: &Dbx,
    self_id: &ID,
    other_id: &ID,
    meta: &ManyToManyQueryMeta<I>,
) -> Result<()> {
    // Build a DELETE statement targeting the specific link.
    let (sql, vals) = Query::delete()
        .from_table(meta.join_table)
        // WHERE self_fk = 'self_id'
        .and_where(Expr::col(meta.join_fk).eq(self_id.clone()))
        // AND other_fk = 'other_id'
        .and_where(Expr::col(meta.many_fk).eq(other_id.clone()))
        .build_sqlx(PostgresQueryBuilder);

    sqlx::query_with(&sql, vals).execute(dbx.db()).await?;

    Ok(())
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
            entities::{
                account::{
                    AccountFilter, AccountForCreate, AccountIden, AccountRow,
                    AccountWithCredentials,
                },
                credential::{
                    CredentialFilter, CredentialForCreate, CredentialIden, CredentialKind,
                },
                permission::{PermissionFilter, PermissionForCreate, PermissionIden},
                role::{RoleFilter, RoleForCreate, RoleIden, RoleWithPermissions},
            },
            queries::crud::create,
            stores::{
                account::AccountStore, credential::CredentialStore, permission::PermissionStore,
                role::RoleStore,
            },
            traits::{
                crud::{Create, Get, List},
                meta::ReadStoreMeta,
            },
        },
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_get_joined() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = CredentialStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        let filter: CredentialFilter = json!({"account_id": ctx.user_id()}).try_into()?;

        let existing_cred = store.list(&ctx, Some(filter), None).await?;

        let c = |i| {
            let mut cred = CredentialForCreate::default();
            cred.account_id = ctx.user_id();
            cred.namespace_id = ctx.namespace_id();
            cred.provider_id = Some("TEST".to_string());

            cred
        };

        let create_count = 2;

        for i in 0..create_count {
            let cred = c(i);
            store.create(&ctx, cred).await?;
        }

        let meta = OneToManyQueryMeta {
            single_table: AccountIden::Table,
            many_table: AccountIden::Credential,
            single_pk: AccountIden::Id,
            many_pk: AccountIden::Id,
            many_fk: AccountIden::AccountId,
            agg_alias: AccountIden::Credentials,
            has_audit: true,
        };

        let res: AccountWithCredentials =
            get_one_to_many(&ctx, &dbx, &ctx.user_id(), &meta).await?;

        let all_cred = res.credentials;

        assert_eq!(all_cred.len(), existing_cred.len() + create_count);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_joined() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let store = CredentialStore::new(dbx.clone());
        let acc_store = AccountStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        let c = |i| {
            let mut acc = AccountForCreate::default();
            acc.email = format!("test{i}{i}@LIST_JOIN");
            acc.description = Some("TEST DESCRIPTION".to_string());
            acc
        };

        let mut acc = vec![];

        let acc_count = 2;

        for i in 0..acc_count {
            let n = c(i);

            acc.push(acc_store.create(&ctx, n).await?);
        }

        let c = |acc_id| {
            let mut cred = CredentialForCreate::default();
            cred.account_id = acc_id;
            cred.namespace_id = ctx.namespace_id();
            cred
        };

        let cred_count = 3;

        for ac in acc {
            for i in 0..cred_count {
                let cred = c(ac.id.into());
                store.create(&ctx, cred).await?;
            }
        }

        let meta = OneToManyQueryMeta {
            single_table: AccountIden::Table,
            many_table: AccountIden::Credential,
            single_pk: AccountIden::Id,
            many_pk: AccountIden::Id,
            many_fk: AccountIden::AccountId,
            agg_alias: AccountIden::Credentials,
            has_audit: true,
        };

        // let filter: AccountFilter = json!({"description":"TEST DESCRIPTION"}).try_into()?;
        let filter: AccountFilter = json!({"email": { "$contains" : "LIST_JOIN"}}).try_into()?;

        let res: Vec<AccountWithCredentials> =
            list_one_to_many::<_, AccountFilter, _>(&ctx, &dbx, Some(filter), None, &meta).await?;

        let mut total_count = 0;
        res.iter()
            .for_each(|el| total_count += el.credentials.len());

        assert_eq!(total_count, acc_count * cred_count);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_get_many_to_many() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let perm_store = PermissionStore::new(dbx.clone());
        let role_store = RoleStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        let c_perm = |i| {
            let mut perm = PermissionForCreate::default();
            perm.namespace_id = ctx.namespace_id();
            perm.name = format!("PERMISSION_GET_MANY_TEST_{i}");
            perm
        };

        let c_role = |i| {
            let mut role = RoleForCreate::default();
            role.namespace_id = ctx.namespace_id();
            role.name = format!("ROLE_GET_MANY_TEST_{i}");
            role
        };

        let mut roles = vec![];
        let mut perms = vec![];

        let role_count = 2;
        let perm_count = 2;

        for i in 0..role_count {
            let n = c_role(i);

            roles.push(role_store.create(&ctx, n).await?);
        }

        for i in 0..perm_count {
            let n = c_perm(i);

            perms.push(perm_store.create(&ctx, n).await?);
        }

        let perm_filter: PermissionFilter = json!({"name":{"$contains":"MANY_TEST"}}).try_into()?;
        let role_filter: RoleFilter = json!({"name":{"$contains":"MANY_TEST"}}).try_into()?;

        let filtered_perms = perm_store.list(&ctx, Some(perm_filter), None).await?;
        let filtered_roles = role_store.list(&ctx, Some(role_filter), None).await?;

        assert_eq!(role_count, filtered_roles.len());
        assert_eq!(perm_count, filtered_perms.len());

        println!("{:#?}", filtered_perms);
        println!("{:#?}", filtered_roles);

        let role = filtered_roles
            .into_iter()
            .next()
            .take()
            .expect("should be at least on role returns in filter");

        // link all perms

        let mutate_meta = ManyToManyQueryMeta {
            single_table: RoleIden::Table,
            many_table: RoleIden::Permission,
            join_table: RoleIden::RolePermission,
            single_pk: RoleIden::Id,
            many_pk: RoleIden::PermissionPk,
            many_fk: RoleIden::PermissionId,
            join_fk: RoleIden::RoleId,
            agg_alias: RoleIden::Permissions,
            has_audit: true,
        };

        let perm_ids = filtered_perms.iter().map(|el| el.id.clone()).collect();

        let _ =
            set_many_to_many_links(&ctx, &dbx, &role.id.clone(), perm_ids, &mutate_meta).await?;

        let meta = ManyToManyQueryMeta {
            single_table: RoleIden::Table,
            many_table: RoleIden::Permission,
            join_table: RoleIden::RolePermission,
            single_pk: RoleIden::Id,
            many_pk: RoleIden::PermissionPk,
            many_fk: RoleIden::PermissionId,
            join_fk: RoleIden::RoleId,
            agg_alias: RoleIden::Permissions,
            has_audit: true,
        };

        let joined_role: RoleWithPermissions =
            get_many_to_many(&ctx, &dbx, &role.id.clone(), &meta).await?;

        assert_eq!(perm_count, joined_role.permissions.len());

        let _ = set_many_to_many_links(&ctx, &dbx, &role.id.clone(), vec![], &mutate_meta).await?;

        let joined_role: RoleWithPermissions =
            get_many_to_many(&ctx, &dbx, &role.id.clone(), &meta).await?;
        assert!(joined_role.permissions.is_empty());

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_many_to_many() -> Result<()> {
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let perm_store = PermissionStore::new(dbx.clone());
        let role_store = RoleStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        let c_perm = |i, name: String| {
            let mut perm = PermissionForCreate::default();
            perm.namespace_id = ctx.namespace_id();
            perm.name = format!("PERMISSION_GET_MANY_TEST_{i}_{name}");
            perm
        };

        let c_role = |i| {
            let mut role = RoleForCreate::default();
            role.namespace_id = ctx.namespace_id();
            role.name = format!("ROLE_GET_MANY_TEST_{i}");
            role
        };

        let mut roles = vec![];

        let role_count = 2;
        let perm_count = 2;

        for i in 0..role_count {
            let n = c_role(i);

            roles.push(role_store.create(&ctx, n).await?);
        }

        let mutate_meta = ManyToManyQueryMeta {
            single_table: RoleIden::Table,
            many_table: RoleIden::Permission,
            join_table: RoleIden::RolePermission,
            single_pk: RoleIden::Id,
            many_pk: RoleIden::PermissionPk,
            many_fk: RoleIden::PermissionId,
            join_fk: RoleIden::RoleId,
            agg_alias: RoleIden::Permissions,
            has_audit: true,
        };

        for role in roles {
            let mut perms = vec![];

            // create new permissions for each role
            for i in 0..perm_count {
                let n = c_perm(i, role.name.clone());

                perms.push(perm_store.create(&ctx, n).await?);
            }

            // attach perms to role
            let perm_ids = perms.iter().map(|el| el.id.clone()).collect();

            let _ = set_many_to_many_links(&ctx, &dbx, &role.id.clone(), perm_ids, &mutate_meta)
                .await?;
        }

        let meta = ManyToManyQueryMeta {
            single_table: RoleIden::Table,
            many_table: RoleIden::Permission,
            join_table: RoleIden::RolePermission,
            single_pk: RoleIden::Id,
            many_pk: RoleIden::PermissionPk,
            many_fk: RoleIden::PermissionId,
            join_fk: RoleIden::RoleId,
            agg_alias: RoleIden::Permissions,
            has_audit: true,
        };

        let role_filter: RoleFilter = json!({"name":{"$contains":"MANY_TEST"}}).try_into()?;

        let filtered_roles = list_many_to_many::<RoleWithPermissions, RoleFilter, _>(
            &ctx,
            &dbx,
            Some(role_filter),
            None,
            &meta,
        )
        .await?;

        let mut total_perm_count = 0;

        filtered_roles
            .iter()
            .for_each(|el| total_perm_count += el.permissions.len());

        assert_eq!(role_count * perm_count, total_perm_count);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_attach_detach_many_to_many() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.db().clone();
        let perm_store = PermissionStore::new(dbx.clone());
        let role_store = RoleStore::new(dbx.clone());
        let ctx = StoreCtx::new_root();

        // -- Create test entities
        let role = role_store
            .create(
                &ctx,
                RoleForCreate {
                    namespace_id: ctx.namespace_id(),
                    name: "ROLE_FOR_ATTACH_DETACH".to_string(),
                    ..Default::default()
                },
            )
            .await?;

        let perm1 = perm_store
            .create(
                &ctx,
                PermissionForCreate {
                    namespace_id: ctx.namespace_id(),
                    name: "PERMISSION_1_FOR_ATTACH_DETACH".to_string(),
                    ..Default::default()
                },
            )
            .await?;

        let perm2 = perm_store
            .create(
                &ctx,
                PermissionForCreate {
                    namespace_id: ctx.namespace_id(),
                    name: "PERMISSION_2_FOR_ATTACH_DETACH".to_string(),
                    ..Default::default()
                },
            )
            .await?;

        // -- Define metadata for read and mutate operations
        let mutate_meta = ManyToManyQueryMeta {
            single_table: RoleIden::Table,
            many_table: RoleIden::Permission,
            join_table: RoleIden::RolePermission,
            single_pk: RoleIden::Id,
            many_pk: RoleIden::PermissionPk,
            many_fk: RoleIden::PermissionId,
            join_fk: RoleIden::RoleId,
            agg_alias: RoleIden::Permissions,
            has_audit: true,
        };

        let read_meta = ManyToManyQueryMeta {
            single_table: RoleIden::Table,
            many_table: RoleIden::Permission,
            join_table: RoleIden::RolePermission,
            single_pk: RoleIden::Id,
            many_pk: RoleIden::PermissionPk,
            many_fk: RoleIden::PermissionId,
            join_fk: RoleIden::RoleId,
            agg_alias: RoleIden::Permissions,
            has_audit: true,
        };

        // -- Initial State Verification
        let role_with_perms: RoleWithPermissions =
            get_many_to_many(&ctx, &dbx, &role.id, &read_meta).await?;
        assert!(
            role_with_perms.permissions.is_empty(),
            "Initially, the role should have no permissions."
        );

        // -- Test Attach
        // Attach the first permission
        attach_link(&ctx, &dbx, &role.id, &perm1.id, &mutate_meta).await?;
        let role_with_perms: RoleWithPermissions =
            get_many_to_many(&ctx, &dbx, &role.id, &read_meta).await?;
        assert_eq!(
            role_with_perms.permissions.len(),
            1,
            "Should have one permission after attaching."
        );
        assert_eq!(
            role_with_perms.permissions[0].id, perm1.id,
            "The correct permission should be attached."
        );

        // Attach the same permission again to test idempotency
        attach_link(&ctx, &dbx, &role.id, &perm1.id, &mutate_meta).await?;
        let role_with_perms: RoleWithPermissions =
            get_many_to_many(&ctx, &dbx, &role.id, &read_meta).await?;
        assert_eq!(
            role_with_perms.permissions.len(),
            1,
            "Attaching an existing link should be idempotent."
        );

        // Attach the second permission
        attach_link(&ctx, &dbx, &role.id, &perm2.id, &mutate_meta).await?;
        let role_with_perms: RoleWithPermissions =
            get_many_to_many(&ctx, &dbx, &role.id, &read_meta).await?;
        assert_eq!(
            role_with_perms.permissions.len(),
            2,
            "Should have two permissions after attaching the second one."
        );

        // -- Test Detach
        // Detach the first permission
        detach_link(&ctx, &dbx, &role.id, &perm1.id, &mutate_meta).await?;
        let role_with_perms: RoleWithPermissions =
            get_many_to_many(&ctx, &dbx, &role.id, &read_meta).await?;
        assert_eq!(
            role_with_perms.permissions.len(),
            1,
            "Should have one permission remaining after detaching the first."
        );
        assert_eq!(
            role_with_perms.permissions[0].id, perm2.id,
            "The remaining permission should be the second one."
        );

        // Detach a non-existent link (perm1 again)
        detach_link(&ctx, &dbx, &role.id, &perm1.id, &mutate_meta).await?;
        let role_with_perms: RoleWithPermissions =
            get_many_to_many(&ctx, &dbx, &role.id, &read_meta).await?;
        assert_eq!(
            role_with_perms.permissions.len(),
            1,
            "Detaching a non-existent link should not change anything."
        );

        // Detach the second permission
        detach_link(&ctx, &dbx, &role.id, &perm2.id, &mutate_meta).await?;
        let role_with_perms: RoleWithPermissions =
            get_many_to_many(&ctx, &dbx, &role.id, &read_meta).await?;
        assert!(
            role_with_perms.permissions.is_empty(),
            "Should have no permissions after detaching the last one."
        );

        Ok(())
    }
}
