use log::{debug, error, info};
use sqlx::{Error, PgPool, Result};
use uuid::Uuid;

use crate::models::account::Account;

use super::role::get_role_db;

pub async fn create_account_db(pool: &PgPool, acc: &Account) -> Result<Account> {
    let acc_type = acc.acc_type.to_string();

    let acc_r = sqlx::query!(
        r#"
        INSERT INTO accounts (id, email, name, password_hash, acc_type)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      "#,
        acc.id,
        acc.email,
        acc.name,
        acc.password_hash,
        acc_type
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
    pool: &PgPool,
    id: &Uuid,
    name: Option<String>,
    email: Option<String>,
    password_hash: Option<String>,
) -> Result<Account> {
    let mut tx = pool.begin().await?;
    if let Some(email) = email {
        sqlx::query!(
            r#"
            UPDATE accounts
            SET email = $1
            WHERE id = $2
          "#,
            email,
            id,
        )
        .execute(&mut *tx)
        .await?;
    }

    if let Some(name) = name {
        sqlx::query!(
            r#"
            UPDATE accounts
            SET name = $1
            WHERE id = $2
          "#,
            name,
            id,
        )
        .execute(&mut *tx)
        .await?;
    }

    if let Some(password_hash) = password_hash {
        sqlx::query!(
            r#"
            UPDATE accounts
            SET password_hash = $1
            WHERE id = $2
          "#,
            password_hash,
            id,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    get_account_db(pool, &id.to_string()).await
}

pub async fn get_account_db(pool: &PgPool, id_or_email: &str) -> Result<Account> {
    struct AccR {
        pub id: Uuid,
        pub name: String,
        pub email: String,
        pub acc_type: String,
        pub pw: String,
    }

    let acc_r = match Uuid::parse_str(id_or_email) {
        Ok(id) => {
            if let Some(r) = sqlx::query!(
                r#"
                  SELECT * FROM accounts
                  WHERE id = $1 
                "#,
                id,
            )
            .fetch_optional(pool)
            .await?
            {
                AccR {
                    id: r.id,
                    name: r.name,
                    email: r.email,
                    acc_type: r.acc_type,
                    pw: r.password_hash,
                }
            } else {
                return Err(Error::RowNotFound);
            }
        }
        Err(_) => {
            if let Some(r) = sqlx::query!(
                r#"
                SELECT * FROM accounts
                WHERE email = $1 
                "#,
                id_or_email,
            )
            .fetch_optional(pool)
            .await?
            {
                AccR {
                    id: r.id,
                    name: r.name,
                    email: r.email,
                    acc_type: r.acc_type,
                    pw: r.password_hash,
                }
            } else {
                return Err(Error::RowNotFound);
            }
        }
    };

    let roles_r = sqlx::query!(
        r#"
        SELECT * FROM role_bindings
        WHERE account_id = $1
        "#,
        acc_r.id
    )
    .fetch_all(pool)
    .await?;

    let mut roles = vec![];

    for role_r in roles_r {
        let role = get_role_db(pool, &role_r.role_id.to_string()).await?;
        roles.push(role);
    }

    Ok(Account {
        id: acc_r.id,
        name: acc_r.name.to_string(),
        email: acc_r.email,
        password_hash: acc_r.pw,
        acc_type: acc_r.acc_type.as_str().into(),
        roles,
    })
}

pub async fn delete_account_db(pool: &PgPool, account: &Account) -> Result<()> {
    let mut tx = pool.begin().await?;
    // remove role bindings
    for role in &account.roles {
        debug!("Removing role binding, for account: {role:?}, and role: {account:?}");

        sqlx::query!(
            r#"
                DELETE FROM role_bindings 
                WHERE role_id = $1 AND account_id = $2
                "#,
            role.id,
            account.id,
        )
        .execute(&mut *tx)
        // .execute(&mut tx)
        .await?;
    }

    // Fetch the newly created user from the database
    sqlx::query!(
        r#"
          DELETE FROM accounts
          WHERE id = $1
        "#,
        account.id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(())
}

pub async fn get_all_accounts_db(pool: &PgPool) -> Result<Vec<Account>> {
    // TODO: Implement Limit paging for query all
    let acc_rs = sqlx::query!(
        r#"
          SELECT * FROM accounts
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut accounts = vec![];

    for acc_r in acc_rs {
        match get_account_db(pool, &acc_r.email).await {
            Ok(acc) => accounts.push(acc),
            Err(e) => {
                error!("Unable to get account by email: {}", acc_r.email);
            }
        }
    }

    Ok(accounts)
}
