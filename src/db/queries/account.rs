use sqlx::{Error, Result, SqlitePool};
use uuid::Uuid;

use crate::models::{
    account::Account,
    error::{ApiError, ApiResult},
    role::{Permission, Role},
};

use super::role::{get_role_id_db, get_role_name_db, get_role_permissions_db};

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
                  WHERE role_id = ?
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
                    permissions,
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
