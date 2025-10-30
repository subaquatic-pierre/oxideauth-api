use std::{env, sync::Arc};

use tracing::{debug, info};

use sqlx::Pool;

use crate::dev::init::init_dev;
use crate::store::dbx::PgDbx;
use crate::store::manager::StoreManager;
use crate::{
    config::Config,
    store::init::{new_db_pool, PgPool},
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

pub struct AppState {
    pub config: Config,
    pub dbx: Arc<PgDbx>,
    pub sm: Arc<StoreManager<PgDbx>>,
}

pub async fn new_app_data() -> AppState {
    let app_env = AppEnv::from_env();
    let app = match app_env {
        AppEnv::Development => {
            debug!(
                "{:<12} - new_app_data()",
                "Application started in DEVELOPMENT mode"
            );

            let app = new_dev_app_data().await;
            init_dev(&app.dbx.pool()).await;
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

pub async fn new_prod_app_data() -> AppState {
    let config = Config::from_env();
    let db: PgPool = new_db_pool(&config.database_url, 5).await;
    let dbx = Arc::new(PgDbx::new(db.clone()));

    let sm = Arc::new(StoreManager::new(dbx.clone()));

    AppState {
        dbx: dbx.clone(),
        config,
        sm,
    }
}

pub async fn new_dev_app_data() -> AppState {
    let config = Config::dev_config();

    let db: PgPool = new_db_pool(&config.database_url, 5).await;
    let dbx = Arc::new(PgDbx::new(db.clone()));

    let sm = Arc::new(StoreManager::new(dbx.clone()));

    AppState {
        dbx: dbx.clone(),
        config,
        sm,
    }
}

pub async fn new_test_app_data() -> AppState {
    let config = Config::test_config();

    let db: PgPool = new_db_pool(&config.database_url, 1).await;
    let dbx = Arc::new(PgDbx::new(db.clone()));
    let sm = Arc::new(StoreManager::new(dbx.clone()));

    AppState {
        dbx: dbx.clone(),
        config,
        sm,
    }
}
