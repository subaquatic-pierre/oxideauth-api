use std::{env, sync::Arc};

use actix_web::web::{scope, Data};
use actix_web::Scope;
use dotenv::dotenv;

use sqlx::Pool;

use crate::db::store::DataStore;
use crate::{
    config::Config,
    db::init::{new_db_pool, DbPool},
    models::guard::AuthGuard,
};

use crate::routes::accounts::register_accounts_collection;
// use crate::routes::utils::register_utils_services;
// use crate::routes::auth::register_auth_collection;
// use crate::routes::roles::register_roles_collection;
// use crate::routes::services::register_services_collection;

pub struct AppData {
    pub config: Config,
    pub db: DbPool,
    pub guard: AuthGuard,
    pub ds: DataStore,
}

pub async fn new_app_data() -> AppData {
    let config = Config::from_env();
    let db: DbPool = new_db_pool(&config.database_url, 5).await;

    let guard = AuthGuard::new(&config.jwt_secret, db.clone());
    let ds = DataStore::new(db.clone());

    AppData {
        db: db.clone(),
        config,
        guard,
        ds,
    }
}

pub async fn new_dev_app_data() -> AppData {
    let config = Config::dev_config();

    let db: DbPool = new_db_pool(&config.database_url, 5).await;
    let guard = AuthGuard::new(&config.jwt_secret, db.clone());
    let ds = DataStore::new(db.clone());

    AppData {
        db: db.clone(),
        config,
        guard,
        ds,
    }
}

pub async fn new_test_app_data() -> AppData {
    let config = Config::test_config();

    let db: DbPool = new_db_pool(&config.database_url, 5).await;
    let guard = AuthGuard::new(&config.jwt_secret, db.clone());
    let ds = DataStore::new(db.clone());

    AppData {
        db: db.clone(),
        config,
        guard,
        ds,
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
