use std::{env, sync::Arc};

use tracing::{debug, info};

use sqlx::Pool;

use crate::cache::redis::RedisChx;
use crate::cache::traits::CacheExecutor;
use crate::core::services::factory::ServiceFactory;
use crate::dev::init::init_dev;
use crate::store::dbx::{DbExecutor, PgDbx};
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

pub struct AppState<Dbx: DbExecutor, Chx: CacheExecutor> {
    pub config: Config,
    pub dbx: Arc<Dbx>,
    pub chx: Arc<Chx>,
    pub sm: Arc<StoreManager<Dbx>>,
    pub svc_build: Arc<ServiceFactory<Dbx>>,
}

pub async fn new_app_data() -> AppState<PgDbx, RedisChx> {
    let app_env = AppEnv::from_env();
    let (config, sm, dbx, chx) = match app_env {
        AppEnv::Development => {
            let config = Config::dev_config();

            let db: PgPool = new_db_pool(&config.database_url, 1).await;
            let dbx = Arc::new(PgDbx::new(db.clone()));
            let sm = Arc::new(StoreManager::new(dbx.clone()));

            debug!(
                "{:<12} - new_app_data()",
                "Application started in DEVELOPMENT mode"
            );

            init_dev(&dbx.pool()).await;

            let chx = Arc::new(RedisChx::new(&config.redis_url));

            (config, sm, dbx, chx)
        }
        AppEnv::Production => {
            let config = Config::from_env();
            let db: PgPool = new_db_pool(&config.database_url, 5).await;
            let dbx = Arc::new(PgDbx::new(db.clone()));
            let sm = Arc::new(StoreManager::new(dbx.clone()));

            debug!(
                "{:<12} - new_app_data()",
                "Application started in PRODUCTION mode"
            );

            let chx = Arc::new(RedisChx::new(&config.redis_url));

            (config, sm, dbx, chx)
        }
        _ => {
            let config = Config::test_config();

            let db: PgPool = new_db_pool(&config.database_url, 1).await;
            let dbx = Arc::new(PgDbx::new(db.clone()));
            let sm = Arc::new(StoreManager::new(dbx.clone()));

            debug!(
                "{:<12} - new_app_data()",
                "Application started in TEST mode"
            );

            let chx = Arc::new(RedisChx::new(&config.redis_url));

            (config, sm, dbx, chx)
        }
    };

    let svc_build = Arc::new(ServiceFactory::new(sm.clone()));

    AppState {
        dbx: dbx.clone(),
        config,
        chx,
        sm,
        svc_build,
    }
}

pub type App = Arc<AppState<PgDbx, RedisChx>>;
