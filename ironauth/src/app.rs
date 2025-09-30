use std::{env, sync::Arc};

use actix_web::web::{scope, Data};
use actix_web::Scope;
use dotenv::dotenv;
use tracing::{debug, info};

use sqlx::Pool;

use crate::dev::init::init_dev;
use crate::store::manager::StoreManager;
use crate::{
    config::Config,
    models::guard::AuthGuard,
    store::init::{new_db_pool, DbPool},
};

use crate::routes::accounts::register_accounts_collection;
// use crate::routes::utils::register_utils_services;
// use crate::routes::auth::register_auth_collection;
// use crate::routes::roles::register_roles_collection;
// use crate::routes::services::register_services_collection;

// Main guard to ensure APP_ENV is set,
// will ensure correct configs and not reset database
// const APP_ENV: &'static str = env!("APP_ENV");

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
    pub guard: AuthGuard,
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

    let guard = AuthGuard::new(&config.jwt_secret, db.clone());
    let sm = StoreManager::new(db.clone());

    AppData {
        db,
        config,
        guard,
        sm,
    }
}

pub async fn new_dev_app_data() -> AppData {
    let config = Config::dev_config();

    let db: DbPool = new_db_pool(&config.database_url, 5).await;
    let guard = AuthGuard::new(&config.jwt_secret, db.clone());
    let sm = StoreManager::new(db.clone());

    AppData {
        db,
        config,
        guard,
        sm,
    }
}

pub async fn new_test_app_data() -> AppData {
    let config = Config::test_config();

    let db: DbPool = new_db_pool(&config.database_url, 1).await;
    let guard = AuthGuard::new(&config.jwt_secret, db.clone());
    let sm = StoreManager::new(db.clone());

    AppData {
        db,
        config,
        guard,
        sm,
    }
}

pub fn register_all_services() -> Scope {
    scope("")
        // .service(register_auth_collection())
        // .service(register_roles_collection())
        // .service(register_services_collection())
        // .service(register_utils_services())
        .service(register_accounts_collection())
}
