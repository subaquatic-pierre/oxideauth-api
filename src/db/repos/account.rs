// src/db/repos/account.rs

use anyhow::{bail, Context, Result};
use diesel::prelude::*;
use uuid::Uuid;

use std::sync::Arc;

use crate::schema::accounts;

use crate::db::models::account::{DbAccount, NewAccount};
use crate::models::account::{Account, AccountProvider, AccountType};

/// Insert a new account (minimal: name + lowercased email).
/// NOTE: If your `accounts` table includes more columns (password_hash, provider, ...),
/// extend `NewAccount` and the insert below accordingly.
pub async fn create_account_db(pool: &Arc<PgPool>, acc: &Account) -> Result<Account> {
    let email_lower = acc.email.to_lowercase();

    // Uniqueness check (application-level; still rely on DB unique index on lower(email))
    if get_account_db(pool, &email_lower).await.is_ok() {
        bail!("Cannot create Account with email '{}'", email_lower);
    }

    let created: DbAccount = db_tx(pool.clone(), move |c| {
        diesel::insert_into(accounts::table)
            .values(&NewAccount {
                name: &acc.name,
                email: &email_lower,
            })
            .get_result::<DbAccount>(c) // <- QueryResult<T>
    })
    .await?;

    Ok(Account::from(created))
}

/// Update an account (minimal: name + email).
/// Add fields in `set(( ... ))` when your table includes them.
pub async fn update_account_db(pool: &Arc<PgPool>, account: &Account) -> Result<Account> {
    let id = account.id;
    let name_new = account.name.clone();
    let email_lower = account.email.to_lowercase();

    let updated: DbAccount = db_tx(pool.clone(), move |c| {
        diesel::update(accounts::table.find(id))
            .set((
                accounts::name.eq(&name_new),
                accounts::email.eq(&email_lower),
                // accounts::password_hash.eq(&account.password_hash), // if column exists
                // ... add other fields when present
            ))
            .get_result::<DbAccount>(c)
            .context("update accounts")
    })
    .await?;

    Ok(Account::from(updated))
}

/// Fetch by UUID or email (case-insensitive).
pub async fn get_account_db(pool: &Arc<PgPool>, id_or_email: &str) -> Result<Account> {
    // If parse as UUID succeeds, fetch by id; otherwise by lower(email)
    if let Ok(id) = Uuid::parse_str(id_or_email) {
        let found = db_tx_opt(pool.clone(), move |c| {
            accounts::table.find(id).first::<DbAccount>(c)
        })
        .await?
        .ok_or_else(|| anyhow::anyhow!("account not found"))?;

        return Ok(Account::from(found));
    }

    let email_lower = id_or_email.to_lowercase();
    let found = db_tx_opt(pool.clone(), move |c| {
        use diesel::dsl::lower;
        accounts::table
            .filter(lower(accounts::email).eq(email_lower.as_str()))
            .first::<DbAccount>(c)
    })
    .await?
    .ok_or_else(|| anyhow::anyhow!("account not found"))?;

    Ok(Account::from(found))
}

/// Delete an account (and, later, any dependent rows in a tx if needed).
pub async fn delete_account_db(pool: &Arc<PgPool>, account: &Account) -> Result<()> {
    let id = account.id;

    db_tx(pool.clone(), move |c| {
        // If you have join tables (e.g., account_roles), delete those here first in the same tx.
        diesel::delete(accounts::table.find(id))
            .execute(c)
            .context("delete accounts")?;
        Ok::<(), anyhow::Error>(())
    })
    .await?;

    Ok(())
}

/// List all accounts (no paging yet).
pub async fn get_all_accounts_db(pool: &Arc<PgPool>) -> Result<Vec<Account>> {
    let rows: Vec<DbAccount> = db_tx(pool.clone(), |c| {
        accounts::table
            .order(accounts::created_at.desc())
            .load::<DbAccount>(c)
            .context("select accounts")
    })
    .await?;

    // Map DbAccount -> domain Account. Roles can be hydrated in a separate step if needed.
    Ok(rows.into_iter().map(Account::from).collect())
}
