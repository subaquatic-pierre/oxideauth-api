use log::{debug, error};
use sqlx::{Error, PgPool, Postgres, Result};
use uuid::Uuid;

use crate::models::{
    account::Account,
    api::{ApiError, ApiResult},
    role::{Permission, Role, RolePermissions},
};

use super::account::get_account_db;

pub async fn create_role_db(pool: &PgPool, role: &Role) -> Result<Role> {
    debug!("Creating role: {role:?}");
    sqlx::query!(
        r#"
        INSERT INTO roles (id, name)
        VALUES ($1, $2)
        "#,
        role.id,
        role.name
    )
    .execute(pool)
    // .execute(&mut tx)
    .await?;

    let existing_perms = get_all_permissions(pool).await?;

    debug!("Existing permissions: {existing_perms:?}");

    let mut perms = vec![];

    for perm in &role.permissions {
        perms.push(perm.to_string());
    }

    bind_permissions_to_role(pool, role, &perms).await?;

    get_role_db(pool, &role.name).await
}

pub async fn update_role_db(pool: &PgPool, role: &Role) -> Result<Role> {
    let r = sqlx::query!(
        r#"
        UPDATE roles
            SET name = $1
            WHERE id = $2
            RETURNING *
        "#,
        role.name,
        role.id
    )
    // .execute(&mut tx)
    .fetch_optional(pool)
    .await?;

    match r {
        Some(r) => {
            let permissions = get_role_permissions_db(pool, &r.id).await?;
            Ok(Role {
                id: r.id,
                name: r.name,
                permissions,
                description: r.description,
            })
        }
        None => Err(Error::RowNotFound),
    }
}

pub async fn delete_role_db(pool: &PgPool, role: &Role) -> Result<()> {
    let mut tx = pool.begin().await?;

    // Delete from permission_bindings
    sqlx::query!(
        r#"
        DELETE FROM permission_bindings
        WHERE role_id = $1
        "#,
        role.id
    )
    .execute(&mut *tx)
    // .execute(&mut tx)
    .await?;

    // Delete from role_bindings
    sqlx::query!(
        r#"
        DELETE FROM role_bindings
        WHERE role_id = $1
        "#,
        role.id
    )
    // .execute(&mut tx)
    .execute(&mut *tx)
    .await?;

    // // Delete the role itself
    sqlx::query!(
        r#"
        DELETE FROM roles
        WHERE id = $1
        "#,
        role.id
    )
    // .execute(&mut tx)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(())
}

pub async fn get_role_db(pool: &PgPool, id_or_name: &str) -> Result<Role> {
    let (id, name, description) = match Uuid::parse_str(id_or_name) {
        Ok(id) => {
            if let Some(r) = sqlx::query!(
                r#"
                SELECT * FROM roles
                WHERE id = $1
                "#,
                id
            )
            .fetch_optional(pool)
            .await?
            {
                (r.id, r.name, r.description)
            } else {
                return Err(Error::RowNotFound);
            }
        }
        Err(_) => {
            if let Some(r) = sqlx::query!(
                r#"
                SELECT * FROM roles
                WHERE name = $1
                "#,
                id_or_name
            )
            .fetch_optional(pool)
            .await?
            {
                (r.id, r.name, r.description)
            } else {
                return Err(Error::RowNotFound);
            }
        }
    };

    let permissions = get_role_permissions_db(pool, &id).await?;
    Ok(Role {
        id,
        name: name.to_string(),
        permissions,
        description,
    })
}

pub async fn get_role_permissions_db(pool: &PgPool, role_id: &Uuid) -> Result<RolePermissions> {
    let permission_rows = sqlx::query!(
        r#"
            SELECT permission_name FROM permission_bindings
            WHERE role_id = $1
            "#,
        role_id
    )
    .fetch_all(pool)
    .await?;

    let permissions: Vec<String> = permission_rows
        .into_iter()
        .map(|row| row.permission_name.to_string())
        .collect();

    debug!("Permissions in get_role_permissions_db, {permissions:?}");

    Ok(RolePermissions::new(permissions))
}

pub async fn get_all_roles_db(pool: &PgPool) -> Result<Vec<Role>> {
    let rs = sqlx::query!(
        r#"
        SELECT name FROM roles
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut roles: Vec<Role> = vec![];
    for r in rs {
        let role = get_role_db(pool, &r.name).await?;
        roles.push(role)
    }

    Ok(roles)
}

pub async fn create_permissions_db(pool: &PgPool, perms: Vec<Permission>) -> Result<Vec<String>> {
    let existing_perms = get_all_permissions(pool).await?;
    let mut created_perms = vec![];
    // let mut tx = pool
    //     .begin()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    for perm in perms {
        if !existing_perms.contains(&perm.name) {
            sqlx::query!(
                r#"
                INSERT INTO permissions (id, name)
                VALUES ($1, $2)
                "#,
                perm.id,
                perm.name
            )
            .execute(pool)
            // .execute(&mut tx)
            .await?;

            created_perms.push(perm.name.clone())
        }
    }

    // tx.commit()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    Ok(created_perms)
}

pub async fn get_permission_db(pool: &PgPool, permission_name: &str) -> Result<String> {
    match sqlx::query!(
        r#"
        SELECT name FROM permissions
        WHERE name = $1
        "#,
        permission_name
    )
    .fetch_optional(pool)
    .await?
    {
        Some(perm) => Ok(perm.name.to_string()),
        None => Err(Error::RowNotFound),
    }
}

pub async fn get_all_permissions(pool: &PgPool) -> Result<Vec<String>> {
    let rs = sqlx::query!(
        r#"
        SELECT name FROM permissions
        "#,
    )
    .fetch_all(pool)
    .await?;

    let permissions: Vec<String> = rs.iter().map(|i| i.name.to_string()).collect();

    Ok(permissions)
}

pub async fn delete_permissions_db(pool: &PgPool, perms: Vec<String>) -> Result<Vec<String>> {
    let mut tx = pool.begin().await?;

    let mut created_perms = vec![];

    for perm in perms {
        if let Ok(perm) = get_permission_db(pool, &perm).await {
            sqlx::query!(
                r#"
                    DELETE FROM permission_bindings 
                    WHERE permission_name = $1
                    "#,
                perm
            )
            .execute(&mut *tx)
            // .execute(&mut tx)
            .await?;

            sqlx::query!(
                r#"
                DELETE FROM permissions 
                WHERE name = $1
                "#,
                perm
            )
            .execute(&mut *tx)
            // .execute(&mut tx)
            .await?;

            created_perms.push(perm);
        }
    }

    tx.commit().await?;

    Ok(created_perms)
}

pub async fn bind_role_to_account_db(pool: &PgPool, acc: &Account, role: &Role) -> Result<()> {
    // only create binding if both role and account exist!
    if let (Ok(_role), Ok(_acc)) = (
        get_role_db(pool, &role.name).await,
        get_account_db(pool, &acc.email).await,
    ) {}
    sqlx::query!(
        r#"
        INSERT INTO role_bindings (account_id, role_id)
        VALUES ($1, $2)
        "#,
        acc.id,
        role.id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn bind_permissions_to_role(
    pool: &PgPool,
    role: &Role,
    perms: &Vec<String>,
) -> Result<()> {
    let mut tx = pool.begin().await?;

    for perm in perms {
        if let Err(e) = sqlx::query!(
            r#"
                INSERT INTO permission_bindings (role_id, permission_name)
                VALUES ($1, $2)
                "#,
            role.id,
            perm
        )
        .execute(&mut *tx)
        .await
        {
            error!("Unable to bind permission '{perm}' to role '{role:?}', {e}");
        }
    }

    tx.commit().await?;

    Ok(())
}

pub async fn remove_permissions_from_role_db(
    pool: &PgPool,
    role: &Role,
    perms: &Vec<String>,
) -> Result<()> {
    let mut tx = pool.begin().await?;

    // only create binding if both role and permission exist!
    for perm in perms {
        debug!("Removing permission binding, for permission_name: {perm:?}, and role: {role:?}");
        if let Err(e) = sqlx::query!(
            r#"
                DELETE FROM permission_bindings 
                WHERE role_id = $1 AND permission_name = $2
                "#,
            role.id,
            perm
        )
        .execute(&mut *tx)
        // .execute(&mut tx)
        .await
        {
            error!("Unable to remove permission '{perm}' to role '{role:?}', {e}");
        }
    }

    tx.commit().await?;

    Ok(())
}

pub async fn remove_role_binding_db(pool: &PgPool, acc: &Account, role: &Role) -> Result<()> {
    // let mut tx = pool
    //     .begin()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    // only create binding if both role and permission exist!
    if let Ok(role) = get_role_db(pool, &role.name).await {
        debug!("Removing role binding, for account: {role:?}, and role: {acc:?}");
        sqlx::query!(
            r#"
                DELETE FROM role_bindings 
                WHERE role_id = $1 AND account_id = $2
                "#,
            role.id,
            acc.id,
        )
        .execute(pool)
        // .execute(&mut tx)
        .await?;
    }

    // tx.commit()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    Ok(())
}
