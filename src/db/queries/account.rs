use log::{debug, error, info};
use sqlx::{Error, PgPool, Result};
use uuid::Uuid;

use crate::models::account::{Account, AccountProvider};

use super::role::get_role_db;

pub async fn create_account_db(pool: &PgPool, acc: &Account) -> Result<Account> {
    let acc_type = acc.acc_type.to_string();
    let provider = acc.provider.to_string();

    let acc_r = sqlx::query!(
        r#"
        INSERT INTO accounts (id, email, name, password_hash, acc_type, description, provider,provider_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
      "#,
        acc.id,
        acc.email,
        acc.name,
        acc.password_hash,
        acc_type,
        acc.description,
        provider,
        acc.provider_id
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
            provider: record.provider.as_str().into(),
            provider_id: record.provider_id,
            description: record.description,
        }),
        None => Err(Error::RowNotFound),
    }
}

pub async fn update_account_db(pool: &PgPool, account: &Account) -> Result<Account> {
    let mut tx = pool.begin().await?;
    sqlx::query!(
        r#"
        UPDATE accounts
        SET email = $2,
            name = $3,
            description = $4,
            password_hash = $5
        WHERE id = $1
      "#,
        account.id,
        account.email,
        account.name,
        account.description,
        account.password_hash
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    get_account_db(pool, &account.id.to_string()).await
}

pub async fn get_account_db(pool: &PgPool, id_or_email: &str) -> Result<Account> {
    struct AccR {
        pub id: Uuid,
        pub name: String,
        pub email: String,
        pub acc_type: String,
        pub pw: String,
        pub desc: Option<String>,
        pub p: String,
        pub p_id: Option<String>,
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
                    desc: r.description,
                    p: r.provider,
                    p_id: r.provider_id,
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
                    desc: r.description,
                    p: r.provider,
                    p_id: r.provider_id,
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
        provider: acc_r.p.as_str().into(),
        provider_id: acc_r.p_id,
        description: acc_r.desc,
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
