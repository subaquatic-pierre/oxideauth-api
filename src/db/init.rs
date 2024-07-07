use sqlx::PgPool;

use crate::models::account::Account;

use super::queries::init::{create_defaults, create_tables, drop_tables};

pub async fn establish_connection(database_url: &str) -> PgPool {
    PgPool::connect(database_url)
        .await
        .expect("Failed to create pool")
}

pub async fn init_db(pool: &PgPool, owner_acc: &Account, drop: bool) -> Result<(), sqlx::Error> {
    if drop {
        drop_tables(pool).await?;
    }

    create_tables(pool).await?;

    if drop {
        create_defaults(pool, owner_acc).await?;
    }

    Ok(())
}
