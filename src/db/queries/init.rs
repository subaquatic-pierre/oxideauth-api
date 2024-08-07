use std::iter::Map;

use sqlx::PgPool;

use crate::{
    app::AppConfig,
    models::{
        account::{Account, AccountProvider, AccountType},
        role::{Permission, Role},
        service::Service,
    },
    utils::crypt::hash_password,
};

use super::{
    account::create_account_db,
    role::{bind_role_to_account_db, create_permissions_db, create_role_db},
    service::create_service_db,
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
    sqlx::query!("DROP TABLE IF EXISTS services;")
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn create_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            id UUID PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            acc_type TEXT NOT NULL,
            provider TEXT NOT NULL,
            provider_id TEXT,
            description TEXT,
            image_url TEXT,
            verified BOOLEAN DEFAULT FALSE NOT NULL,
            enabled BOOLEAN DEFAULT TRUE NOT NULL
        )
        "#,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS roles (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT
        )
        "#,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permissions (
            id UUID,
            name TEXT PRIMARY KEY,
            description TEXT
        )
        "#,
    )
    .execute(&mut *tx)
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
    .execute(&mut *tx)
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
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS services (
            id UUID PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            endpoint TEXT,
            description TEXT
        )
        "#,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(())
}

// const ALL_DEFAULT_PERMISSIONS: &'static [&str] = &[
//     // accounts
//     "auth.accounts.create",
//     "auth.accounts.describe",
//     "auth.accounts.describeSelf",
//     "auth.accounts.updateSelf",
//     "auth.accounts.list",
//     "auth.accounts.update",
//     // services
//     "auth.services.create",
//     "auth.services.describe",
//     "auth.services.list",
//     "auth.services.update",
//     // roles
//     "auth.roles.create",
//     "auth.roles.describe",
//     "auth.roles.list",
//     "auth.roles.update",
//     "auth.roles.bind",
//     // permissions
//     "auth.permissions.create",
//     "auth.permissions.describe",
//     "auth.permissions.list",
//     "auth.permissions.update",
//     "auth.permissions.bind",
// ];

const DEFAULT_ALL_PERMISSIONS: &'static [&str] = &[
    // accounts
    "auth.accounts.create",
    "auth.accounts.delete",
    "auth.accounts.describe",
    "auth.accounts.describeSelf",
    "auth.accounts.updateSelf",
    "auth.accounts.deleteSelf",
    "auth.accounts.list",
    "auth.accounts.update",
    "auth.accounts.createServiceAccountSecretKey",
    // services
    "auth.services.create",
    "auth.services.delete",
    "auth.services.describe",
    "auth.services.list",
    "auth.services.update",
    "auth.services.validatePermissions",
    //roles
    "auth.roles.create",
    "auth.roles.delete",
    "auth.roles.describe",
    "auth.roles.list",
    "auth.roles.update",
    "auth.roles.assign",
    "auth.roles.remove",
    // permissions
    "auth.permissions.delete",
    "auth.permissions.create",
    "auth.permissions.describe",
    "auth.permissions.list",
    "auth.permissions.update",
    "auth.permissions.assign",
    "auth.permissions.remove",
    // utils
    "auth.utils.sendEmail",
];

const DEFAULT_AUDITOR_PERMISSIONS: &'static [&str] = &[
    // accounts
    "auth.accounts.list",
    "auth.accounts.describe",
    "auth.accounts.describeSelf",
    "auth.accounts.updateSelf",
    "auth.accounts.deleteSelf",
    // services
    "auth.services.describe",
    "auth.services.list",
    // roles
    "auth.roles.describe",
    "auth.roles.list",
    // permissions
    "auth.permissions.describe",
    "auth.permissions.list",
];

const DEFAULT_VIEWER_PERMISSIONS: &'static [&str] = &[
    // accounts
    "auth.accounts.describeSelf",
    "auth.accounts.updateSelf",
    "auth.accounts.deleteSelf",
    // services
    "auth.services.describe",
    "auth.services.list",
];

const DEFAULT_SA_PERMISSIONS: &'static [&str] = &[
    // services
    "auth.services.describe",
    "auth.services.list",
    "auth.services.validatePermissions",
];

pub async fn create_defaults(
    pool: &PgPool,
    owner_acc: &Account,
    config: &AppConfig,
) -> Result<(), sqlx::Error> {
    let perms = DEFAULT_ALL_PERMISSIONS
        .iter()
        .map(|el| Permission::new(el))
        .collect();

    create_permissions_db(pool, perms).await?;

    // create owner role
    let owner_role = Role::new(
        "Owner",
        DEFAULT_ALL_PERMISSIONS
            .iter()
            .map(|el| el.to_string())
            .collect(),
        Some("Default Owner role created by OxideAuth".to_string()),
    );
    create_role_db(pool, &owner_role).await?;

    // create admin role
    let admin_role = Role::new(
        "Admin",
        DEFAULT_ALL_PERMISSIONS
            .iter()
            .map(|el| el.to_string())
            .collect(),
        Some("Default Admin role created by OxideAuth".to_string()),
    );
    create_role_db(pool, &admin_role).await?;

    // create auditor role
    let auditor_role = Role::new(
        "Auditor",
        DEFAULT_AUDITOR_PERMISSIONS
            .iter()
            .map(|el| el.to_string())
            .collect(),
        Some("Default Auditor role created by OxideAuth".to_string()),
    );
    create_role_db(pool, &auditor_role).await?;

    // create viewer role
    let viewer_role = Role::new(
        "Viewer",
        DEFAULT_VIEWER_PERMISSIONS
            .iter()
            .map(|el| el.to_string())
            .collect(),
        Some("Default Viewer role created by OxideAuth".to_string()),
    );
    create_role_db(pool, &viewer_role).await?;

    // create default service account role
    let sa_role = Role::new(
        "Service",
        DEFAULT_SA_PERMISSIONS
            .iter()
            .map(|el| el.to_string())
            .collect(),
        Some("Default Service Account Role created by OxideAuth".to_string()),
    );
    create_role_db(pool, &sa_role).await?;

    // TODO: remove development accounts
    // ---
    let pw_hash = hash_password(&"password").unwrap();
    let image_url = format!("{}/assets/images/users/default.png", config.client_origin);
    let mut viewer_acc = Account::new_local_user(
        "viewer@email.com",
        "Default Viewer",
        &pw_hash,
        Some(image_url),
    );
    viewer_acc.description = Some("Default Viewer account created by OxideAuth".to_string());
    viewer_acc.verified = true;

    create_account_db(pool, &viewer_acc).await?;
    bind_role_to_account_db(pool, &viewer_acc, &viewer_role).await?;
    // ---

    // create default service account
    let sa = Account::new_service_account(
        "service@email.com",
        "OxideAuth Service Account",
        Some("Default Service Account created by OxideAuth".to_string()),
    );
    create_account_db(pool, &sa).await?;
    bind_role_to_account_db(pool, &sa, &sa_role).await?;

    // create owner account
    create_account_db(pool, owner_acc).await?;
    bind_role_to_account_db(pool, owner_acc, &owner_role).await?;

    // Create default Auth service

    let auth_endpoint = format!("{}:{}", config.host, config.port);
    let auth_service = Service::new(
        "OxideAuth",
        Some(auth_endpoint),
        Some("Default Auth service provided by OxideAuth".to_string()),
    );
    create_service_db(pool, &auth_service).await?;

    Ok(())
}
