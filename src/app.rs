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
    pub client_origin: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub default_sa_password: String,
    pub jwt_expires_in: String,
    pub jwt_max_age: i64,
    pub google_oauth_client_id: String,
    pub google_oauth_client_secret: String,
    pub google_oauth_redirect_url: String,
    pub host: String,
    pub port: u16,
    // pub github_oauth_client_id: String,
    // pub github_oauth_client_secret: String,
    // pub github_oauth_redirect_url: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        dotenv().ok();
        let client_origin = std::env::var("CLIENT_ORIGIN").expect("CLIENT_ORIGIN must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in =
            std::env::var("TOKEN_EXPIRED_IN").expect("TOKEN_EXPIRED_IN must be set");
        let jwt_max_age = std::env::var("TOKEN_MAXAGE").expect("TOKEN_MAXAGE must be set");
        let google_oauth_client_id =
            std::env::var("GOOGLE_OAUTH_CLIENT_ID").expect("GOOGLE_OAUTH_CLIENT_ID must be set");
        let google_oauth_client_secret = std::env::var("GOOGLE_OAUTH_CLIENT_SECRET")
            .expect("GOOGLE_OAUTH_CLIENT_SECRET must be set");
        let google_oauth_redirect_url = std::env::var("GOOGLE_OAUTH_REDIRECT_URL")
            .expect("GOOGLE_OAUTH_REDIRECT_URL must be set");
        // let github_oauth_client_id =
        //     std::env::var("GITHUB_OAUTH_CLIENT_ID").expect("GITHUB_OAUTH_CLIENT_ID must be set");
        // let github_oauth_client_secret = std::env::var("GITHUB_OAUTH_CLIENT_SECRET")
        //     .expect("GITHUB_OAUTH_CLIENT_SECRET must be set");
        // let github_oauth_redirect_url = std::env::var("GITHUB_OAUTH_REDIRECT_URL")
        //     .expect("GITHUB_OAUTH_REDIRECT_URL must be set");

        let default_sa_password = env::var("DEFAULT_SERVICE_ACCOUNT_PASSWORD")
            .expect("DEFAULT_SERVICE_ACCOUNT_PASSWORD must be set");

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let host = env::var("HOST").unwrap_or("http://localhost".to_string());

        let port = env::var("PORT")
            .unwrap_or("8080".to_string())
            .parse::<u16>()
            .expect("Unable to parse PORT from .env, value must be valid number");

        dotenv().ok();
        AppConfig {
            database_url,
            default_sa_password,
            jwt_secret,
            client_origin,
            jwt_expires_in,
            jwt_max_age: jwt_max_age.parse::<i64>().unwrap(),
            google_oauth_client_id,
            google_oauth_client_secret,
            google_oauth_redirect_url,
            host,
            port, // github_oauth_client_id,
                  // github_oauth_client_secret,
                  // github_oauth_redirect_url,
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
