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
    _dev::{
        config::PROJECT_ROOT,
        db::{init_test_db, reset_db, run_migrations},
    },
    db::{store::DataStore, DbPool},
};

pub async fn init_dev(db_pool: &DbPool) {
    static INIT: OnceCell<()> = OnceCell::const_new();

    INIT.get_or_init(|| async {
        info!("{:<12} - init_dev()", "FOR-DEV-ONLY");
    })
    .await;
}

pub async fn init_test<'a>(db_pool: &DbPool) -> &'a DataStore {
    static INIT: OnceCell<DataStore> = OnceCell::const_new();

    let ds = INIT
        .get_or_init(|| async {
            info!("{:<12} - init_test()", "FOR-DEV-ONLY");
            init_test_db(db_pool).await;

            DataStore::new(db_pool.clone())
        })
        .await;

    ds
}
