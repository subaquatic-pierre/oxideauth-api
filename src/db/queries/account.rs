use sqlx::{Error, Result, SqlitePool};
use uuid::Uuid;

use crate::models::{
    account::Account,
    error::{ApiError, ApiResult},
    role::Role,
};

pub async fn create_account(pool: &SqlitePool, acc: &Account) -> ApiResult<Option<Account>> {
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
    .await
    .map_err(|e| ApiError::new(&e.to_string()))?;

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
    .await
    .map_err(|e| ApiError::new(&e.to_string()))?;

    let user = match acc_r {
        Some(record) => Some(Account {
            id: acc.id,
            name: record.name.unwrap_or("".to_string()).to_string(),
            email: record.email,
            password_hash: record.password_hash,
            acc_type: record
                .acc_type
                .unwrap_or("unknown".to_string())
                .as_str()
                .into(),
            roles: vec![],
        }),
        None => None,
    };

    Ok(user)
    // Ok(Some(Account::default()))
}

pub async fn get_by_email(pool: &SqlitePool, email: &str) -> ApiResult<Option<Account>> {
    // Fetch the newly created user from the database
    let acc_r = sqlx::query!(
        r#"
          SELECT * FROM accounts
          WHERE email = ?
        "#,
        email
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::new(&e.to_string()))?;

    let user = match acc_r {
        Some(record) => {
            let id_str = record.id.unwrap_or("".to_string()).to_string();
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| {
                    Error::Decode(Box::new(ApiError {
                        message: "Error".to_string(),
                    }))
                })
                .map_err(|e| ApiError::new(&e.to_string()))?;
            Some(Account {
                id,
                name: record.name.unwrap_or("".to_string()).to_string(),
                email: record.email,
                password_hash: record.password_hash,
                acc_type: record
                    .acc_type
                    .unwrap_or("unknown".to_string())
                    .as_str()
                    .into(),
                roles: vec![],
            })
        }
        None => None,
    };

    Ok(user)
}
