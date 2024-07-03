use std::{env, sync::Arc};

use actix_web::web::Data;
use dotenv::dotenv;
use sqlx::{Pool, Sqlite};

use crate::{db::init::establish_connection, models::guard::Guard};

pub struct AppConfig {
    pub database_url: String,
    pub jwt_secret: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        dotenv().ok();
        AppConfig {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            jwt_secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
        }
    }
}

pub struct AppData {
    pub config: AppConfig,
    pub db: Arc<Pool<Sqlite>>,
    pub guard: Guard,
}

pub async fn new_app_data() -> Data<AppData> {
    let config = AppConfig::from_env();
    let db: Pool<Sqlite> = establish_connection(&config.database_url).await;
    let arc_db = Arc::new(db);

    let guard = Guard::new(&config.jwt_secret, arc_db.clone());
    Data::new(AppData {
        db: arc_db.clone(),
        config,
        guard,
    })
}
