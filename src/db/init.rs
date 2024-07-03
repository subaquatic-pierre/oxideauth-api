use sqlx::sqlite::SqlitePool;

use super::queries::init::{create_tables, drop_tables};

pub async fn establish_connection(database_url: &str) -> SqlitePool {
    SqlitePool::connect(database_url)
        .await
        .expect("Failed to create pool")
}

pub async fn init_db(pool: &SqlitePool, drop: bool) -> Result<(), sqlx::Error> {
    if drop {
        drop_tables(pool).await?;
    }

    create_tables(pool).await?;

    Ok(())
}
