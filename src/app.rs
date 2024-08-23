use std::{env, sync::Arc};

use actix_web::web::{scope, Data};
use actix_web::Scope;
use dotenv::dotenv;
use sqlx::{PgPool, Pool};

use crate::routes::utils::register_utils_services;
use crate::{db::init::establish_connection, models::guard::AuthGuard};

use crate::routes::accounts::register_accounts_collection;
use crate::routes::auth::register_auth_collection;
use crate::routes::roles::register_roles_collection;
use crate::routes::services::register_services_collection;

#[derive(Debug)]
pub struct AppConfig {
    pub host: String,
    pub port: usize,
    pub drop_tables: bool,

    pub client_origin: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_max_age: i64,

    pub google_oauth_client_id: String,
    pub google_oauth_client_secret: String,
    pub google_oauth_redirect_url: String,

    pub aws_region: String,

    pub aws_ses_from: String,
    pub aws_ses_host: String,

    pub aws_ses_access_key: String,
    pub aws_ses_secret_key: String,

    pub aws_s3_access_key: String,
    pub aws_s3_secret_key: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        dotenv().ok();
        let client_origin = std::env::var("CLIENT_ORIGIN").expect("CLIENT_ORIGIN must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
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

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let host = env::var("HOST").unwrap_or("http://localhost".to_string());

        let port = env::var("PORT")
            .unwrap_or("8080".to_string())
            .parse::<usize>()
            .expect("Unable to parse PORT from .env, value must be valid number");

        let aws_ses_host = env::var("AWS_SES_HOST").expect("AWS_SES_HOST must be set in .env");
        let aws_ses_access_key = env::var("AWS_SES_ACCESS_KEY")
            .expect("AWS_SES_ACCESS_KEY credentials must be set in .env");
        let aws_ses_secret_key = env::var("AWS_SES_SECRET_KEY")
            .expect("AWS_SES_SECRET_KEY credentials must be set in .env");

        let aws_s3_access_key = env::var("AWS_S3_ACCESS_KEY")
            .expect("AWS_SES_ACCESS_KEY credentials must be set in .env");
        let aws_s3_secret_key = env::var("AWS_S3_SECRET_KEY")
            .expect("AWS_SES_SECRET_KEY credentials must be set in .env");

        let aws_ses_from =
            env::var("AWS_SES_FROM").expect("AWS_SES_FROM credentials must be set in .env");
        let aws_region =
            env::var("AWS_REGION").expect("AWS_REGION credentials must be set in .env");

        let mut s_drop_tables =
            env::var("DROP_TABLES").expect("DROP_TABLES credentials must be set in .env");

        let mut drop_tables = false;

        if s_drop_tables == "true".to_string() {
            drop_tables = true;
        }

        dotenv().ok();
        AppConfig {
            database_url,
            jwt_secret,
            client_origin,
            jwt_max_age: jwt_max_age.parse::<i64>().unwrap(),
            google_oauth_client_id,
            google_oauth_client_secret,
            google_oauth_redirect_url,
            host,
            port,
            aws_ses_host,
            aws_ses_access_key,
            aws_ses_secret_key,
            aws_ses_from,
            aws_region,
            aws_s3_access_key,
            aws_s3_secret_key,
            drop_tables,
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

pub async fn new_test_app_data() -> Data<AppData> {
    let mut config = AppConfig::from_env();

    config.drop_tables = true;
    config.database_url = "postgres://test_user:password@localhost/test_db".to_string();

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
        .service(register_utils_services())
}
