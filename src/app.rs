use std::{env, sync::Arc};

use actix_web::web::{scope, Data};
use actix_web::Scope;
use dotenv::dotenv;
use sqlx::{PgPool, Pool};

use crate::{db::init::establish_connection, models::guard::AuthGuard};

use crate::routes::accounts::register_accounts_collection;
use crate::routes::auth::register_auth_collection;
use crate::routes::roles::register_roles_collection;
use crate::routes::services::register_services_collection;

pub struct AppConfig {
    pub database_url: String,
    pub jwt_secret: String,
    pub default_sa_password: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        dotenv().ok();
        AppConfig {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            jwt_secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
            default_sa_password: env::var("DEFAULT_SERVICE_ACCOUNT_PASSWORD")
                .expect("DEFAULT_SERVICE_ACCOUNT_PASSWORD must be set"),
        }
    }
}

pub struct AppData {
    pub config: AppConfig,
    pub db: Arc<PgPool>,
    pub guard: AuthGuard,
}

pub async fn new_app_data() -> Data<AppData> {
    let config = AppConfig::from_env();
    let db: PgPool = establish_connection(&config.database_url).await;
    let arc_db = Arc::new(db);
    let guard = AuthGuard::new(&config.jwt_secret, arc_db.clone());

    Data::new(AppData {
        db: arc_db.clone(),
        config,
        guard,
    })
}

pub fn register_all_services() -> Scope {
    scope("")
        .service(register_auth_collection())
        .service(register_roles_collection())
        .service(register_services_collection())
        .service(register_accounts_collection())
}
