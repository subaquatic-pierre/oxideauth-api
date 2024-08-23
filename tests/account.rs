use actix_web::dev::ServiceResponse;
use actix_web::{http::StatusCode, test, App};
use oxideauth::models::account::Account;
use serde_json::json;

use oxideauth::app::{new_app_data, register_all_services};
use oxideauth::utils::test_utils::{create_test_account, setup_test_server};

#[actix_web::test]
async fn test_list_accounts() {
    let mut app = setup_test_server().await;

    // Create a test account
    create_test_account(&mut app, "test_list@example.com", "password").await;

    let req = test::TestRequest::get()
        .uri("/accounts/list-accounts")
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["accounts"].is_array());
}

#[actix_web::test]
async fn test_update_account() {
    let mut app = setup_test_server().await;

    // Create a test account
    let account = create_test_account(&mut app, "test_update@example.com", "password").await;

    let update_account_req = json!({
        "account": account.email,
        "name": "Updated Name"
    });

    let req = test::TestRequest::post()
        .uri("/accounts/update-account")
        .set_json(&update_account_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["account"]["name"], "Updated Name");
}

#[actix_web::test]
async fn test_delete_account() {
    let mut app = setup_test_server().await;

    // Create a test account
    let account = create_test_account(&mut app, "test_delete@example.com", "password").await;

    let delete_account_req = json!({
        "account": account.email
    });

    let req = test::TestRequest::post()
        .uri("/accounts/delete-account")
        .set_json(&delete_account_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["deleted"], true);
}

#[actix_web::test]
async fn test_describe_account() {
    let mut app = setup_test_server().await;

    // Create a test account
    let account = create_test_account(&mut app, "test_describe@example.com", "password").await;

    let describe_account_req = json!({
        "account": account.email
    });

    let req = test::TestRequest::post()
        .uri("/accounts/describe-account")
        .set_json(&describe_account_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["account"]["email"], account.email);
}

#[actix_web::test]
async fn test_describe_self() {
    let mut app = setup_test_server().await;

    // Create a test account and simulate authentication
    let account = create_test_account(&mut app, "test_describe_self@example.com", "password").await;

    let req = test::TestRequest::get()
        .uri("/accounts/describe-self")
        .insert_header(("Authorization", "Bearer fake_token"))
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["account"]["email"], account.email);
}

#[actix_web::test]
async fn test_update_self() {
    let mut app = setup_test_server().await;

    // Create a test account and simulate authentication
    let account = create_test_account(&mut app, "test_update_self@example.com", "password").await;

    let update_self_req = json!({
        "name": "Updated Self Name",
        "password": "newpassword"
    });

    let req = test::TestRequest::post()
        .uri("/accounts/update-self")
        .insert_header(("Authorization", "Bearer fake_token"))
        .set_json(&update_self_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["account"]["name"], "Updated Self Name");
}

#[actix_web::test]
async fn test_delete_self() {
    let mut app = setup_test_server().await;

    // Create a test account and simulate authentication
    let account = create_test_account(&mut app, "test_delete_self@example.com", "password").await;

    let req = test::TestRequest::delete()
        .uri("/accounts/delete-self")
        .insert_header(("Authorization", "Bearer fake_token"))
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["deleted"], true);
}

#[actix_web::test]
async fn test_create_service_account() {
    let mut app = setup_test_server().await;

    let create_service_account_req = json!({
        "email": "service_account@example.com",
        "name": "Service Account",
        "description": "A service account"
    });

    let req = test::TestRequest::post()
        .uri("/accounts/create-service-account")
        .set_json(&create_service_account_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["account"].is_object());
}

#[actix_web::test]
async fn test_create_user_account() {
    let mut app = setup_test_server().await;

    let create_user_account_req = json!({
        "name": "New User",
        "email": "new_user@example.com",
        "password": "password"
    });

    let req = test::TestRequest::post()
        .uri("/accounts/create-user-account")
        .set_json(&create_user_account_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["account"].is_object());
}

#[actix_web::test]
async fn test_get_sa_secret_key() {
    let mut app = setup_test_server().await;

    // Create a test service account
    let account =
        create_test_account(&mut app, "service_account_secret@example.com", "password").await;

    let get_sa_secret_key_req = json!({
        "account": account.email,
        "exp": 3600
    });

    let req = test::TestRequest::post()
        .uri("/accounts/service-account-secret-key")
        .set_json(&get_sa_secret_key_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["key"].is_string());
}
