use std::iter::Map;

use sqlx::PgPool;

use crate::models::{
    account::Account,
    role::{Permission, Role},
};

use super::{
    account::create_account_db,
    role::{bind_role_to_account_db, create_permissions_db, create_role_db},
};

pub async fn drop_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query!("DROP TABLE IF EXISTS role_bindings;")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("DROP TABLE IF EXISTS permission_bindings;")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("DROP TABLE IF EXISTS roles;")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("DROP TABLE IF EXISTS permissions;")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("DROP TABLE IF EXISTS accounts;")
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn create_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            id UUID PRIMARY KEY,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            acc_type TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS roles (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permissions (
            id UUID,
            name TEXT PRIMARY KEY
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permission_bindings (
            role_id UUID NOT NULL,
            permission_name TEXT NOT NULL,
            PRIMARY KEY (role_id, permission_name),
            FOREIGN KEY (role_id) REFERENCES roles(id),
            FOREIGN KEY (permission_name) REFERENCES permissions(name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS role_bindings (
            account_id UUID NOT NULL,
            role_id UUID NOT NULL,
            PRIMARY KEY (account_id, role_id),
            FOREIGN KEY (account_id) REFERENCES accounts(id),
            FOREIGN KEY (role_id) REFERENCES roles(id)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

const ALL_DEFAULT_PERMISSIONS: &'static [&str] = &[
    "auth.users.create",
    "auth.users.get",
    "auth.users.getSelf",
    "auth.users.list",
    "auth.users.update",
    "auth.services.create",
    "auth.services.get",
    "auth.services.list",
    "auth.services.update",
    "auth.roles.create",
    "auth.roles.get",
    "auth.roles.list",
    "auth.roles.update",
    "auth.roles.bind",
    "auth.permissions.create",
    "auth.permissions.get",
    "auth.permissions.list",
    "auth.permissions.update",
    "auth.permissions.bind",
];

const DEFAULT_ADMIN_PERMISSIONS: &'static [&str] = &[
    "auth.users.create",
    "auth.users.get",
    "auth.users.getSelf",
    "auth.users.list",
    "auth.users.update",
    "auth.services.create",
    "auth.services.get",
    "auth.services.list",
    "auth.services.update",
    "auth.roles.create",
    "auth.roles.get",
    "auth.roles.list",
    "auth.roles.update",
    "auth.roles.bind",
    "auth.permissions.create",
    "auth.permissions.get",
    "auth.permissions.list",
    "auth.permissions.update",
    "auth.permissions.bind",
];

const DEFAULT_AUDITOR_PERMISSIONS: &'static [&str] = &[
    "auth.users.get",
    "auth.users.getSelf",
    "auth.users.list",
    "auth.services.get",
    "auth.services.list",
    "auth.roles.get",
    "auth.roles.list",
    "auth.permissions.get",
    "auth.permissions.list",
];

const DEFAULT_VIEWER_PERMISSIONS: &'static [&str] = &["auth.users.getSelf"];

pub async fn create_defaults(pool: &PgPool, owner_acc: &Account) -> Result<(), sqlx::Error> {
    let perms = ALL_DEFAULT_PERMISSIONS
        .iter()
        .map(|el| Permission::new(el))
        .collect();

    create_permissions_db(pool, perms).await?;

    // create owner role
    let owner_role = Role::new(
        "owner",
        ALL_DEFAULT_PERMISSIONS
            .iter()
            .map(|el| el.to_string())
            .collect(),
    );
    create_role_db(pool, &owner_role).await?;

    // create admin role
    let admin_role = Role::new(
        "admin",
        DEFAULT_ADMIN_PERMISSIONS
            .iter()
            .map(|el| el.to_string())
            .collect(),
    );
    create_role_db(pool, &admin_role).await?;

    // create auditor role
    let auditor_role = Role::new(
        "auditor",
        DEFAULT_AUDITOR_PERMISSIONS
            .iter()
            .map(|el| el.to_string())
            .collect(),
    );
    create_role_db(pool, &auditor_role).await?;

    // create viewer role
    let viewer_role = Role::new(
        "viewer",
        DEFAULT_VIEWER_PERMISSIONS
            .iter()
            .map(|el| el.to_string())
            .collect(),
    );
    create_role_db(pool, &viewer_role).await?;

    create_account_db(pool, owner_acc).await?;
    bind_role_to_account_db(pool, owner_acc, &owner_role).await?;

    Ok(())
}
