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
    _dev::db::{init_dev_db, init_test_db},
    app::{new_test_app_data, AppData},
    db::{store::DataStore, DbPool},
};

pub async fn init_dev(db_pool: &DbPool) {
    static INIT: OnceCell<()> = OnceCell::const_new();

    INIT.get_or_init(|| async {
        info!("{:<12} - init_dev()", "FOR-DEV-ONLY");
        init_dev_db(db_pool).await;
    })
    .await;
}

pub async fn init_test<'a>() -> &'a AppData {
    static INIT: OnceCell<AppData> = OnceCell::const_new();

    let ds = INIT
        .get_or_init(|| async {
            info!("{:<12} - init_test()", "FOR-DEV-ONLY");

            let app = new_test_app_data().await;
            init_test_db(&app.db).await;

            app
        })
        .await;

    ds
}
