// src/db/init.rs
use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};

use crate::{app::AppConfig, models::account::Account};

// Type alias to keep call sites clean
pub type PgPool = Pool<Postgres>;

// ---- Embedded migrations (expects a `migrations/` folder at project root) ----
// Generate with: `sqlx migrate add -r <name>` then `sqlx migrate run`
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!(); // embeds migrations at compile time

pub async fn establish_connection(database_url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .expect("Failed to create pool")
}

/// Initialize DB:
/// - optionally drop schema (if `drop == true`)
/// - run migrations
/// - optionally seed defaults
pub async fn init_db(
    pool: &PgPool,
    owner_acc: &Account,
    drop: bool,
    _config: &AppConfig,
) -> Result<()> {
    if drop {
        // Nuke and recreate the default schema (Postgres).
        // If you’re using multiple schemas or extensions, adjust accordingly.
        sqlx::query("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            .execute(pool)
            .await
            .context("dropping & recreating public schema failed")?;
    }

    // Run all pending migrations
    MIGRATOR
        .run(pool)
        .await
        .context("running sqlx migrations failed")?;

    // ---- Seed defaults (optional) ----
    // seed_defaults(pool, owner_acc, _config).await.context("seeding defaults failed")?;

    Ok(())
}

/*
// Example seeding function (SQLx)
use uuid::Uuid;

async fn seed_defaults(pool: &PgPool, owner: &Account, _config: &AppConfig) -> Result<()> {
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
