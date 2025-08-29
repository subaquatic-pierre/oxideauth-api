// src/db/init.rs
use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};

use crate::{config::Config, models::account::Account};

// Type alias for DB
pub type DbPool = Pool<Postgres>;

// ---- Embedded migrations (expects a `migrations/` folder at project root) ----
// Generate with: `sqlx migrate add -r <name>` then `sqlx migrate run`
// static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!(); // embeds migrations at compile time

pub async fn new_db_pool(database_url: &str, max_connections: u32) -> DbPool {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await
        .expect("Failed to create pool")
}

/// Initialize DB:
/// - optionally drop schema (if `drop == true`)
/// - run migrations
/// - optionally seed defaults
pub async fn init_db(pool: &DbPool, owner_acc: &Account, _config: &Config) -> Result<()> {
    // Nuke and recreate the default schema (Postgres).
    // If you’re using multiple schemas or extensions, adjust accordingly.
    // sqlx::query("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    //     .execute(pool)
    //     .await
    //     .context("dropping & recreating public schema failed")?;

    // Run all pending migrations
    // MIGRATOR
    //     .run(pool)
    //     .await
    //     .context("running sqlx migrations failed")?;

    // ---- Seed defaults (optional) ----
    // seed_defaults(pool, owner_acc, _config).await.context("seeding defaults failed")?;

    Ok(())
}

/*
// Example seeding function (SQLx)
use uuid::Uuid;

async fn seed_defaults(pool: &DbPool, owner: &Account, _config: &AppConfig) -> Result<()> {
    // Example: ensure an "Owner" role exists
    let exists: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM roles WHERE name = 'Owner'
        )
        "#,
    )
    .fetch_one(pool)
    .await?;

    if !exists.0 {
        let _inserted: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO roles (id, name, namespace, description)
            VALUES ($1, 'Owner', NULL, 'Project owner')
            RETURNING id
            "#,
        )
        .bind(Uuid::new_v4())
        .fetch_one(pool)
        .await?;
    }

    // Attach role to owner, insert base permissions, etc...
    Ok(())
}
*/
