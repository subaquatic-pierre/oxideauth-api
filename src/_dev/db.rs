use std::path::{Path, PathBuf};

use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::OnceCell;
use tracing::info;

use crate::config::PROJECT_ROOT;
use crate::db::init::DbPool;

// NOTE: Hardcode to prevent deployed system db update.
const PG_DEV_POSTGRES_URL: &str = "postgres://oxideauth:password@localhost/oxideauth";
const PG_DEV_TEST_URL: &str = "postgres://test_user:password@localhost/tests_db";
const PG_DEV_APP_URL: &str = "postgres://oxideauth:password@localhost/apps_db";
const SQL_DIR: &str = "sql/_dev";

static INIT: OnceCell<()> = OnceCell::const_new();

pub async fn init_dev_db(pool: &DbPool) -> Result<()> {
    INIT.get_or_init(|| async {
        info!("{:<12} - init_dev_db()", "FOR-DEV-ONLY");
    })
    .await;

    // let pool = new_db_pool()
    Ok(())
}

pub async fn init_test_db(pool: &DbPool) -> Result<()> {
    INIT.get_or_init(|| async {
        info!("{:<12} - init_test_db()", "FOR-DEV-ONLY");
    })
    .await;

    // let pool = new_db_pool()
    Ok(())
}

pub fn get_sql_dir() -> PathBuf {
    let base_dir = PathBuf::from(PROJECT_ROOT);
    let sql_dir = base_dir.join(SQL_DIR);
    sql_dir
}

pub fn exec_psql(db: &DbPool, file: &Path) -> Result<(), sqlx::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PROJECT_ROOT;
    use anyhow::{Context, Result};
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_path() -> Result<()> {
        let path = get_sql_dir();
        println!(
            "{:<12} - path: {path:?} , PROJECT_ROOT:{PROJECT_ROOT:?}",
            "FOR-DEV-ONLY"
        );
        Ok(())
    }
}
