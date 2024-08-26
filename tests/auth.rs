use actix_web::dev::ServiceResponse;
use actix_web::http::header::{HeaderValue, AUTHORIZATION};
use actix_web::{http::StatusCode, test, App};
use oxideauth::db::queries::account::get_account_db;
use oxideauth::models::account::Account;
use oxideauth::models::token::TokenType;
use oxideauth::routes::accounts::{DeleteAccountReq, UpdateAccountReq};
use oxideauth::routes::auth::login_user;
use oxideauth::utils::auth::build_owner_account;
use oxideauth::utils::token::gen_token;
use serde_json::json;
use serial_test::serial;

use oxideauth::app::{new_app_data, new_test_app_data, register_all_services};
use oxideauth::utils::test_utils::{create_test_account, login_owner, setup_test_server};

#[actix_web::test]
#[serial]
async fn test_register_user() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&json!({
            "email": "new_user@example.com",
            "password": "new_password",
            "name": "New User",
        }))
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
#[serial]
async fn test_register_user_with_existing_email() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&json!({
            "email": "pierre@codativity.com",
            "password": "new_password",
            "name": "Test User",
        }))
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), 400);
}
#[actix_web::test]
#[serial]
async fn test_login_user() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&json!({
            "email": "viewer@email.com",
            "password": "password"
        }))
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
#[serial]
async fn test_login_user_with_wrong_password() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&json!({
            "email": "viewer@email.com",
            "password": "wrong"
        }))
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
#[serial]
async fn test_confirm_account() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&json!({
            "email": "new_user@example.com",
            "password": "new_password",
            "name": "New User",
        }))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    let account = get_account_db(&data.db, "new_user@example.com")
        .await
        .unwrap();

    let token = gen_token(&data.config, &account, TokenType::ConfirmAccount, None).unwrap();

    let req = test::TestRequest::get()
        .uri(&format!(
            "/auth/confirm-account?token={}&redirectUrl=http://example.com&dashboardUrl=cool",
            token
        ))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 302); // redirect
}

#[actix_web::test]
#[serial]
async fn test_reset_password() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let req = test::TestRequest::post()
        .uri("/auth/reset-password")
        .set_json(&json!({
            "email": "viewer@email.com",
            "redirectUrl": "http://example.com/reset",
            "projectName": "TestProject"
        }))
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
#[serial]
async fn test_update_password() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let account = get_account_db(&data.db, "viewer@email.com").await.unwrap();

    let token = gen_token(&data.config, &account, TokenType::ResetPassword, None).unwrap();

    let req = test::TestRequest::post()
        .uri("/auth/update-password")
        .set_json(&json!({
            "token": token,
            "password": "new_password"
        }))
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
#[serial]
async fn test_resend_confirm() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&json!({
            "email": "new_user@example.com",
            "password": "new_password",
            "name": "New User",
        }))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    let account = get_account_db(&data.db, "new_user@example.com")
        .await
        .unwrap();

    let req = test::TestRequest::post()
        .uri("/auth/resend-confirm")
        .set_json(&json!({
            "email": account.email,
            "password": "new_password",
            "name": "Test User",
        }))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
#[serial]
async fn test_refresh_token() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();

    // Assuming you have a method to authorize request with token
    let req = test::TestRequest::get()
        .uri("/auth/refresh-token")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), 200);
}
