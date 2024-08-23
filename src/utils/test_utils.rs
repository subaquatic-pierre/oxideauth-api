use actix_cors::Cors;
use actix_http::Request;
use actix_web::dev::Server;
use actix_web::middleware::Logger;
use actix_web::{http::header, test, web, App, HttpServer, Scope};
use log::info;
use serde_json::json;
use serde_json::Value;
use std::any::Any;
use std::{env, io};

use crate::db::init::init_db;
use crate::models::account::Account;
use crate::utils::auth::build_owner_account;

use crate::app::{new_app_data, new_test_app_data, register_all_services};

// use actix_http::Request;
use actix_web::dev::{Service, ServiceResponse};

pub async fn setup_test_server(
) -> impl Service<Request, Response = ServiceResponse, Error = actix_web::Error> {
    // Setup the app
    let app_data = new_test_app_data().await;

    let owner_acc = build_owner_account();

    init_db(
        &app_data.db,
        &owner_acc,
        app_data.config.drop_tables,
        &app_data.config,
    )
    .await
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    .expect("Unable to initialize test database");

    // Initialize the app with routes and services
    let mut app = test::init_service(
        App::new()
            .app_data(app_data.clone())
            .service(register_all_services()),
    )
    .await;
    app
}

// Helper function to create an account in the test database
pub async fn create_test_account(
    app: impl Service<Request, Response = ServiceResponse, Error = actix_web::Error>,
    email: &str,
    password: &str,
) -> Value {
    let create_account_req = json!({
        "email": email,
        "name": "Test User",
        "password": password
    });

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&create_account_req)
        .to_request();

    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;

    body
}

// Helper function to create an account in the test database
pub async fn login_user(
    app: impl Service<Request, Response = ServiceResponse, Error = actix_web::Error>,
    email: &str,
    password: &str,
) -> Value {
    let login_req = json!({
        "email": email,
        "password": password
    });

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_req)
        .to_request();

    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;

    body
}

// Helper function to create an account in the test database
pub async fn login_owner(
    app: impl Service<Request, Response = ServiceResponse, Error = actix_web::Error>,
) -> Value {
    let email = env::var("OWNER_EMAIL").unwrap_or("owner@email.com".to_string());
    let password = env::var("OWNER_PASSWORD").unwrap_or("password".to_string());

    login_user(app, &email, &password).await
}
