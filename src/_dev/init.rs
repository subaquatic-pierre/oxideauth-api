use std::{
    env::current_dir,
    path::{Path, PathBuf},
};

use anyhow::Result;
use oxideauth::db::init::new_db_pool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::OnceCell;
use tracing::info;

use crate::{
    config::PROJECT_ROOT,
    db::{store::DataStore, DbPool},
};

// NOTE: Hardcode to prevent deployed system db update.
const PG_DEV_POSTGRES_URL: &str = "postgres://oxideauth:password@localhost/oxideauth";
const PG_DEV_APP_URL: &str = "postgres://test_user:password@localhost/tests_db";
const SQL_RECREATE_DB_FILE_NAME: &str = "00-recreate-db.sql";

pub async fn init_dev(db_pool: DbPool) {
    static INIT: OnceCell<()> = OnceCell::const_new();

    INIT.get_or_init(|| async {
        info!("{:<12} - init_dev()", "FOR-DEV-ONLY");
    })
    .await;
}

pub async fn init_test<'a>(db_pool: DbPool) -> &'a DataStore {
    static INIT: OnceCell<DataStore> = OnceCell::const_new();

    let ds = INIT
        .get_or_init(|| async {
            info!("{:<12} - init_test()", "FOR-DEV-ONLY");
            DataStore::new(db_pool)
        })
        .await;

    ds
}
