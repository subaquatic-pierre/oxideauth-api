use log::debug;
use sqlx::{Error, PgPool, Postgres, Result, SqlitePool};
use uuid::Uuid;

use crate::models::{
    account::Account,
    api::{ApiError, ApiResult},
    role::{Permission, Role, RolePermissions},
};

use super::account::get_account_by_email_db;

pub async fn create_role_db(pool: &SqlitePool, role: &Role) -> Result<Role> {
    let id = role.id_str();
    // let mut tx = pool
    //     .begin()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    debug!("Creating role: {role:?}");
    sqlx::query!(
        r#"
        INSERT INTO roles (id, name)
        VALUES (?, ?)
        "#,
        id,
        role.name
    )
    .execute(pool)
    // .execute(&mut tx)
    .await?;

    let existing_perms = get_all_permissions(pool).await?;
    debug!("Existing permissions: {existing_perms:?}");

    for perm in &role.permissions {
        let new_perm = Permission::new(&perm);

        if !existing_perms.contains(&perm) {
            create_permissions_db(pool, vec![new_perm.clone()]).await?;
        }
        bind_permission_to_role(pool, role, &new_perm.name).await?;
    }

    get_role_db(pool, &role.name).await
}

pub async fn update_role_db(pool: &SqlitePool, role: &Role) -> Result<Role> {
    let role_id = role.id_str();
    // let name = update.new_name.as_deref().unwrap_or(current_role_name);
    // // let mut tx = pool.begin().await?;

    // // Update the role name if provided
    sqlx::query!(
        r#"
        UPDATE roles
        SET name = ?
        WHERE id = ?
        "#,
        role.name,
        role_id
    )
    // .execute(&mut tx)
    .execute(pool)
    .await?;

    // Delete existing permission bindings for the role
    sqlx::query!(
        r#"
        DELETE FROM permission_bindings
        WHERE role_id = ?
        "#,
        role_id
    )
    // .execute(&mut tx)
    .execute(pool)
    .await?;

    let existing_perms = get_all_permissions(pool).await?;

    for perm in &role.permissions {
        let new_perm = Permission::new(&perm);

        if !existing_perms.contains(&perm) {
            create_permissions_db(pool, vec![new_perm.clone()]).await?;
        }
        bind_permission_to_role(pool, role, &new_perm.name).await?;
    }

    // tx.commit().await?;

    get_role_db(pool, &role.name).await
}

pub async fn delete_role_db(pool: &SqlitePool, role: &Role) -> Result<()> {
    let role_id = role.id_str();
    // let mut tx = pool
    //     .begin()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    // Delete from permission_bindings
    sqlx::query!(
        r#"
        DELETE FROM permission_bindings
        WHERE role_id = ?
        "#,
        role_id
    )
    .execute(pool)
    // .execute(&mut tx)
    .await?;

    // Delete from role_bindings
    sqlx::query!(
        r#"
        DELETE FROM role_bindings
        WHERE role_id = ?
        "#,
        role_id
    )
    // .execute(&mut tx)
    .execute(pool)
    .await?;

    // // Delete the role itself
    sqlx::query!(
        r#"
        DELETE FROM roles
        WHERE id = ?
        "#,
        role_id
    )
    // .execute(&mut tx)
    .execute(pool)
    .await?;

    // tx.commit()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    Ok(())
}

pub async fn get_role_db(pool: &SqlitePool, role_name: &str) -> Result<Role> {
    let r = sqlx::query!(
        r#"
        SELECT * FROM roles
        WHERE name = ?
        "#,
        role_name
    )
    .fetch_optional(pool)
    .await?;

    match r {
        Some(r) => {
            let role_id = get_role_id_db(pool, role_name).await?;
            let permissions = get_role_permissions_db(pool, &role_id).await?;
            Ok(Role {
                id: Uuid::parse_str(&r.id).unwrap(),
                name: r.name.to_string(),
                permissions: RolePermissions::new(permissions),
            })
        }
        None => Err(Error::RowNotFound),
    }
}

pub async fn get_role_id_db(pool: &SqlitePool, role_name: &str) -> Result<String> {
    match sqlx::query!(
        r#"
        SELECT id FROM roles
        WHERE name = ?
        "#,
        role_name
    )
    .fetch_optional(pool)
    .await?
    {
        Some(r) => Ok(r.id),
        None => Err(Error::RowNotFound),
    }
}

pub async fn get_role_name_db(pool: &SqlitePool, role_id: &str) -> Result<String> {
    match sqlx::query!(
        r#"
        SELECT name FROM roles
        WHERE id = ?
        "#,
        role_id
    )
    .fetch_optional(pool)
    .await?
    {
        Some(r) => Ok(r.name),
        None => Err(Error::RowNotFound),
    }
}

pub async fn get_role_permissions_db(pool: &SqlitePool, role_id: &str) -> Result<Vec<String>> {
    let permission_rows = sqlx::query!(
        r#"
                SELECT permission_name FROM permission_bindings
                WHERE role_id = ?
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

    Ok(permissions)
}

pub async fn get_all_roles_db(pool: &SqlitePool) -> Result<Vec<Role>> {
    let rs = sqlx::query!(
        r#"
        SELECT * FROM roles
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

pub async fn create_permissions_db(
    pool: &SqlitePool,
    perms: Vec<Permission>,
) -> Result<Vec<String>> {
    let existing_perms = get_all_permissions(pool).await?;
    let mut created_perms = vec![];
    // let mut tx = pool
    //     .begin()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    for perm in perms {
        if !existing_perms.contains(&perm.name) {
            let id = perm.id.to_string();
            sqlx::query!(
                r#"
                INSERT INTO permissions (id, name)
                VALUES (?, ?)
                "#,
                id,
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

pub async fn get_permission_db(pool: &SqlitePool, permission_name: &str) -> Result<String> {
    match sqlx::query!(
        r#"
        SELECT name FROM permissions
        WHERE name = ?
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

pub async fn get_all_permissions(pool: &SqlitePool) -> Result<Vec<String>> {
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

pub async fn delete_permissions_db(pool: &SqlitePool, perms: Vec<String>) -> Result<Vec<String>> {
    // let mut tx = pool
    //     .begin()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    let mut created_perms = vec![];

    for perm in perms {
        if let Ok(perm) = get_permission_db(pool, &perm).await {
            sqlx::query!(
                r#"
                    DELETE FROM permission_bindings 
                    WHERE permission_name = ?
                    "#,
                perm
            )
            .execute(pool)
            // .execute(&mut tx)
            .await?;

            sqlx::query!(
                r#"
                DELETE FROM permissions 
                WHERE name = ?
                "#,
                perm
            )
            .execute(pool)
            // .execute(&mut tx)
            .await?;

            created_perms.push(perm);
        }
    }

    // tx.commit()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    Ok(created_perms)
}

pub async fn bind_role_to_account_db(pool: &SqlitePool, acc: &Account, role: &Role) -> Result<()> {
    let acc_id: String = acc.id.to_string();
    let role_id = role.id.to_string();

    // only create binding if both role and account exist!
    if let (Ok(_role), Ok(_acc)) = (
        get_role_db(pool, &role.name).await,
        get_account_by_email_db(pool, &acc.email).await,
    ) {}
    sqlx::query!(
        r#"
        INSERT INTO role_bindings (account_id, role_id)
        VALUES (?, ?)
        "#,
        acc_id,
        role_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn bind_permission_to_role(pool: &SqlitePool, role: &Role, perm: &str) -> Result<()> {
    let role_id = role.id.to_string();

    debug!("Creating permission binding, for permission_name: {perm:?}, and role: {role:?}");

    // only create binding if both role and permission exist!
    if let (Ok(_role), Ok(perm)) = (
        get_role_db(pool, &role.name).await,
        get_permission_db(pool, perm).await,
    ) {
        sqlx::query!(
            r#"
            INSERT INTO permission_bindings (role_id, permission_name)
            VALUES (?, ?)
            "#,
            role_id,
            perm
        )
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub async fn remove_permission_from_role_db(
    pool: &SqlitePool,
    role: &Role,
    perm: &str,
) -> Result<()> {
    let role_id = role.id.to_string();
    // let mut tx = pool
    //     .begin()
    //     .await
    //     .map_err(|e| ApiError::new(&e.to_string()))?;

    // only create binding if both role and permission exist!
    if let (Ok(_role), Ok(perm)) = (
        get_role_db(pool, &role.name).await,
        get_permission_db(pool, perm).await,
    ) {
        debug!("Removing permission binding, for permission_name: {perm:?}, and role: {role:?}");
        sqlx::query!(
            r#"
                DELETE FROM permission_bindings 
                WHERE role_id = ? AND permission_name = ?
                "#,
            role_id,
            perm
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

pub async fn remove_role_from_account_db(
    pool: &SqlitePool,
    acc: &Account,
    role: &Role,
) -> Result<()> {
    let role_id = role.id.to_string();
    let account_id = acc.id.to_string();

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
                WHERE role_id = ? AND account_id = ?
                "#,
            role_id,
            account_id,
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

// pub async fn _remove_permissions_from_role(
//     pool: &SqlitePool,
//     role: &Role,
//     perms: Vec<String>,
// ) -> Result<()> {
//     let role_id = role.id.to_string();
//     // let mut tx = pool
//     //     .begin()
//     //     .await
//     //     .map_err(|e| ApiError::new(&e.to_string()))?;

//     // only create binding if both role and permission exist!
//     if let Ok(_role) = get_role_db(pool, &role.name).await {
//         for perm in perms {
//             debug!(
//                 "Creating permission binding, for permission_name: {perm:?}, and role: {role:?}"
//             );
//             sqlx::query!(
//                 r#"
//                 INSERT INTO permission_bindings (role_id, permission_name)
//                 VALUES (?, ?)
//                 "#,
//                 role_id,
//                 perm
//             )
//             .execute(pool)
//             // .execute(&mut tx)
//             .await?;
//         }
//     }

//     // tx.commit()
//     //     .await
//     //     .map_err(|e| ApiError::new(&e.to_string()))?;

//     Ok(())
// }

// pub async fn _bind_permissions_to_role(
//     pool: &SqlitePool,
//     role: &Role,
//     perms: Vec<String>,
// ) -> Result<()> {
//     let role_id = role.id.to_string();
//     // let mut tx = pool
//     //     .begin()
//     //     .await
//     //     .map_err(|e| ApiError::new(&e.to_string()))?;

//     // only create binding if both role and permission exist!
//     if let Ok(_role) = get_role_db(pool, &role.name).await {
//         for perm in perms {
//             debug!(
//                 "Creating permission binding, for permission_name: {perm:?}, and role: {role:?}"
//             );
//             sqlx::query!(
//                 r#"
//                 INSERT INTO permission_bindings (role_id, permission_name)
//                 VALUES (?, ?)
//                 "#,
//                 role_id,
//                 perm
//             )
//             .execute(pool)
//             // .execute(&mut tx)
//             .await?;
//         }
//     }

//     // tx.commit()
//     //     .await
//     //     .map_err(|e| ApiError::new(&e.to_string()))?;

//     Ok(())
// }

// pub async fn _bind_permission_to_role(pool: &PgPool, role: &Role, perm: &str) -> Result<()> {
//     let role_id = role.id.to_string();

//     debug!("Creating permission binding, for permission_name: {perm:?}, and role: {role:?}");

//     let mut tx = pool.begin().await?;

//     let role_exists = sqlx::query_scalar!(
//         r#"
//         SELECT EXISTS(
//             SELECT 1
//             FROM roles
//             WHERE name = ?
//         )
//         "#,
//         role.name
//     )
//     .fetch_one(&mut tx)
//     .await?;

//     let perm_exists = sqlx::query_scalar!(
//         r#"
//         SELECT EXISTS(
//             SELECT 1
//             FROM permissions
//             WHERE name = ?
//         )
//         "#,
//         perm
//     )
//     .fetch_one(&mut tx)
//     .await?;

//     if role_exists && perm_exists {
//         sqlx::query!(
//             r#"
//             INSERT INTO permission_bindings (role_id, permission_name)
//             VALUES (?, ?)
//             "#,
//             role_id,
//             perm
//         )
//         .execute(&mut tx)
//         .await?;

//         tx.commit().await?;
//     } else {
//         tx.rollback().await?;
//         if !role_exists {
//             return Err(ApiError::new(&format!("Role {} does not exist", role.name)));
//         }
//         if !perm_exists {
//             return Err(ApiError::new(&format!(
//                 "Permission {} does not exist",
//                 perm
//             )));
//         }
//     }

//     Ok(())
// }
