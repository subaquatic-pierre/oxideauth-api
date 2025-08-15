use anyhow::Context;
use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel_migrations::{embed_migrations, MigrationHarness};

use crate::{app::AppConfig, models::account::Account};

use diesel_async::{pooled_connection::bb8::Pool, AsyncPgConnection};

pub type PgPool = Pool<AsyncPgConnection>;

// use super::queries::init::{create_defaults, create_tables, drop_tables};

// pub async fn establish_connection(database_url: &str) -> PgPool {
//     PgPool::connect(database_url)
//         .await
//         .expect("Failed to create pool")
// }

// pub async fn init_db(
//     pool: &PgPool,
//     owner_acc: &Account,
//     drop: bool,
//     config: &AppConfig,
// ) -> Result<(), sqlx::Error> {
//     // if drop {
//     //     drop_tables(pool).await?;
//     // }

//     // create_tables(pool).await?;

//     // if drop {
//     //     create_defaults(pool, owner_acc, config).await?;
//     // }

//     Ok(())
// }

// ---- Embedded migrations (expects a `migrations/` folder at project root) ----
pub const MIGRATIONS: diesel_migrations::EmbeddedMigrations = embed_migrations!("migrations");

// Keep the same async signature as before for minimal churn.
pub async fn establish_connection(database_url: &str) -> PgPool {
    Pool::builder()
        .build(diesel_async::pooled_connection::AsyncDieselConnectionManager::new(database_url))
        .await
        .expect("Failed to create pool")
}

// Initialize DB: optionally drop schema, run migrations, then (optionally) seed defaults.
pub async fn init_db(
    pool: &PgPool,
    owner_acc: &Account,
    drop: bool,
    _config: &AppConfig,
) -> anyhow::Result<()> {
    // Diesel is sync; grab a connection from the pool
    let mut conn = pool.get().context("db pool get() failed")?;

    // If you really want a clean slate, reset the public schema.
    // (Safer in dev/test. For production, prefer dedicated revert migrations.)
    if drop {
        conn.batch_execute(
            r#"
            DROP SCHEMA IF EXISTS public CASCADE;
            CREATE SCHEMA public;
            GRANT ALL ON SCHEMA public TO public;
            "#,
        )
        .context("failed to drop & recreate public schema")?;
    }

    // Run all pending migrations
    // conn.run_pending_migrations(MIGRATIONS)
    //     .context("running diesel migrations failed")?;

    // ---- Seed defaults (optional) ----
    // seed_defaults(&mut conn, owner_acc, _config).context("seeding defaults failed")?;

    Ok(())
}

/*
// Example seeding function if/when you’re ready to port it:
use diesel::prelude::*;
use crate::schema::roles::dsl::*;
use crate::models::role::{NewRole, Role};

fn seed_defaults(conn: &mut PgConnection, owner: &Account, _config: &AppConfig) -> anyhow::Result<()> {
    // Example: ensure an "Owner" role exists
    let exists: bool = diesel::select(diesel::dsl::exists(roles.filter(name.eq("Owner"))))
        .get_result(conn)?;
    if !exists {
        diesel::insert_into(roles)
            .values(&NewRole { name: "Owner", namespace: None, description: Some("Project owner") })
            .execute(conn)?;
    }

    // Attach role to owner, insert base permissions, etc...
    Ok(())
}
*/
