use std::{env, sync::Arc};

use tracing::{debug, info};

use sqlx::Pool;

use crate::dev::init::init_dev;
use crate::store::manager::StoreManager;
use crate::{
    config::Config,
    store::init::{new_db_pool, DbPool},
};

pub enum AppEnv {
    Development,
    Production,
}

impl AppEnv {
    pub fn from_env() -> Self {
        let app_env = env::var("APP_ENV").expect("APP_ENV must be set in your .env file");

        match app_env.as_str() {
            "dev" => AppEnv::Development,
            "prod" => AppEnv::Production,
            _ => panic!("incorrect environment value set for APP_ENV, must be 'prod' or 'dev"),
        }
    }
}

pub struct AppData {
    pub config: Config,
    pub db: DbPool,
    pub sm: StoreManager,
}

pub async fn new_app_data() -> AppData {
    let app_env = AppEnv::from_env();
    let app = match app_env {
        AppEnv::Development => {
            debug!(
                "{:<12} - new_app_data()",
                "Application started in DEVELOPMENT mode"
            );

            let app = new_dev_app_data().await;
            init_dev(&app.db).await;
            app
        }
        AppEnv::Production => {
            debug!(
                "{:<12} - new_app_data()",
                "Application started in PRODUCTION mode"
            );
            let app = new_prod_app_data().await;
            app
        }
    };

    app
}

pub async fn new_prod_app_data() -> AppData {
    let config = Config::from_env();
    let db: DbPool = new_db_pool(&config.database_url, 5).await;

    let sm = StoreManager::new(db.clone());

    AppData { db, config, sm }
}

pub async fn new_dev_app_data() -> AppData {
    let config = Config::dev_config();

    let db: DbPool = new_db_pool(&config.database_url, 5).await;
    let sm = StoreManager::new(db.clone());

    AppData { db, config, sm }
}

pub async fn new_test_app_data() -> AppData {
    let config = Config::test_config();

    let db: DbPool = new_db_pool(&config.database_url, 1).await;
    let sm = StoreManager::new(db.clone());

    AppData { db, config, sm }
}
