use log::error;
use sqlx::{Error, Result, SqlitePool};
use uuid::Uuid;

use crate::models::{
    account::Account,
    error::{ApiError, ApiResult},
    role::{Permission, Role, RolePermissions},
};

use super::role::{
    get_role_id_db, get_role_name_db, get_role_permissions_db, remove_role_from_account_db,
};

pub async fn create_account_db(pool: &SqlitePool, acc: &Account) -> Result<Account> {
    let acc_type = acc.acc_type.to_string();
    let id = acc.id.to_string();

    sqlx::query!(
        r#"
        INSERT INTO accounts (id, email, name, password_hash, acc_type)
        VALUES (?, ?, ?, ?, ?)
      "#,
        id,
        acc.email,
        acc.name,
        acc.password_hash,
        acc_type
    )
    .execute(pool)
    .await?;

    // get role bindings

    // Fetch the newly created user from the database
    let acc_r = sqlx::query!(
        r#"
          SELECT * FROM accounts
          WHERE id = ?
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;

    match acc_r {
        Some(record) => Ok(Account {
            id: acc.id,
            name: record.name.to_string(),
            email: record.email,
            password_hash: record.password_hash,
            acc_type: record.acc_type.as_str().into(),
            roles: vec![],
        }),
        None => Err(Error::RowNotFound),
    }
}

pub async fn update_account_db(
    pool: &SqlitePool,
    id: &str,
    name: Option<String>,
    email: Option<String>,
) -> Result<Account> {
    if let Some(email) = email {
        sqlx::query!(
            r#"
            UPDATE accounts
            SET email = ?
            WHERE id = ?
          "#,
            email,
            id,
        )
        .execute(pool)
        .await?;
    }

    if let Some(name) = name {
        sqlx::query!(
            r#"
            UPDATE accounts
            SET name = ?
            WHERE id = ?
          "#,
            name,
            id,
        )
        .execute(pool)
        .await?;
    }

    get_account_by_id_db(pool, &id).await
}

pub async fn get_account_by_id_db(pool: &SqlitePool, id: &str) -> Result<Account> {
    // Fetch the newly created user from the database
    let acc_r = sqlx::query!(
        r#"
          SELECT * FROM accounts
          WHERE id = ?
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;

    match acc_r {
        Some(record) => {
            let roles_r = sqlx::query!(
                r#"
                  SELECT * FROM role_bindings
                  WHERE account_id = ?
                "#,
                record.id
            )
            .fetch_all(pool)
            .await?;

            let mut roles = vec![];

            for role_r in roles_r {
                let role_name = get_role_name_db(pool, &role_r.role_id).await?;
                let permissions = get_role_permissions_db(pool, &role_r.role_id).await?;

                let role = Role {
                    id: Uuid::parse_str(&role_r.role_id).unwrap(),
                    name: role_name,
                    permissions: RolePermissions::new(permissions),
                };

                roles.push(role);
            }

            let id_str = record.id.unwrap_or("".to_string()).to_string();
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| {
                    Error::Decode(Box::new(ApiError {
                        message: "Error".to_string(),
                    }))
                })
                .map_err(|e| Error::WorkerCrashed)?;

            Ok(Account {
                id,
                name: record.name.to_string(),
                email: record.email,
                password_hash: record.password_hash,
                acc_type: record.acc_type.as_str().into(),
                roles,
            })
        }
        None => Err(Error::RowNotFound),
    }
}

pub async fn get_account_by_email_db(pool: &SqlitePool, email: &str) -> Result<Account> {
    // Fetch the newly created user from the database
    let acc_r = sqlx::query!(
        r#"
          SELECT * FROM accounts
          WHERE email = ?
        "#,
        email
    )
    .fetch_optional(pool)
    .await?;

    match acc_r {
        Some(record) => {
            let roles_r = sqlx::query!(
                r#"
                  SELECT * FROM role_bindings
                  WHERE account_id = ?
                "#,
                record.id
            )
            .fetch_all(pool)
            .await?;

            let mut roles = vec![];

            for role_r in roles_r {
                let role_name = get_role_name_db(pool, &role_r.role_id).await?;
                let permissions = get_role_permissions_db(pool, &role_r.role_id).await?;

                let role = Role {
                    id: Uuid::parse_str(&role_r.role_id).unwrap(),
                    name: role_name,
                    permissions: RolePermissions::new(permissions),
                };

                roles.push(role);
            }

            let id_str = record.id.unwrap_or("".to_string()).to_string();
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| {
                    Error::Decode(Box::new(ApiError {
                        message: "Error".to_string(),
                    }))
                })
                .map_err(|e| Error::WorkerCrashed)?;

            Ok(Account {
                id,
                name: record.name.to_string(),
                email: record.email,
                password_hash: record.password_hash,
                acc_type: record.acc_type.as_str().into(),
                roles,
            })
        }
        None => Err(Error::RowNotFound),
    }
}

pub async fn delete_account_db(pool: &SqlitePool, account: &Account) -> Result<()> {
    let acc_id = account.id.to_string();
    // remove role bindings
    for role in &account.roles {
        remove_role_from_account_db(pool, account, role).await?
    }

    // Fetch the newly created user from the database
    let acc_rs = sqlx::query!(
        r#"
          DELETE FROM accounts
          WHERE id = ?
        "#,
        acc_id
    )
    .fetch_all(pool)
    .await?;

    Ok(())
}

pub async fn get_all_accounts_db(pool: &SqlitePool) -> Result<Vec<Account>> {
    // Fetch the newly created user from the database
    let acc_rs = sqlx::query!(
        r#"
          SELECT email FROM accounts
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut accounts = vec![];

    for acc_r in acc_rs {
        match get_account_by_email_db(pool, &acc_r.email).await {
            Ok(acc) => accounts.push(acc),
            Err(e) => {
                error!("Unable to get account by email: {}", acc_r.email);
            }
        }
    }

    Ok(accounts)
}

pub async fn get_account_id_by_email_db(pool: &SqlitePool, email: &str) -> Result<String> {
    // Fetch the newly created user from the database
    match sqlx::query!(
        r#"
          SELECT id FROM accounts
          WHERE email = ?
        "#,
        email
    )
    .fetch_optional(pool)
    .await?
    {
        Some(r) => Ok(r.id.unwrap()),
        None => Err(Error::RowNotFound),
    }
}
