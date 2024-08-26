use actix_web::dev::ServiceResponse;
use actix_web::http::header::{HeaderValue, AUTHORIZATION};
use actix_web::{http::StatusCode, test, App};
use oxideauth::db::queries::account::get_account_db;
use oxideauth::models::account::Account;
use oxideauth::routes::accounts::{DeleteAccountReq, UpdateAccountReq};
use oxideauth::routes::auth::login_user;
use oxideauth::utils::auth::build_owner_account;
use serde_json::json;
use serial_test::serial;

use oxideauth::app::{new_app_data, new_test_app_data, register_all_services};
use oxideauth::utils::test_utils::{create_test_account, login_owner, setup_test_server};

#[actix_web::test]
#[serial]
async fn test_list_accounts() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();

    let value = format!("Bearer {token}");

    let header = format!("Authorization: Bearer {token}");
    println!("{header}");

    let req = test::TestRequest::get()
        .uri("/accounts/list-accounts")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    println!("body: {body:?}");
}

#[actix_web::test]
#[serial]
async fn test_update_account() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let update_req = UpdateAccountReq {
        account: "viewer@email.com".into(),
        name: Some("New Name".into()),
        password: Some("new_password".into()),
        description: None,
        verified: None,
        enabled: None,
    };

    let req = test::TestRequest::post()
        .uri("/accounts/update-account")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&update_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
}

#[actix_web::test]
#[serial]
async fn test_delete_account() {
    // Create a test account
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let res = create_test_account(&mut app, "test_delete@example.com", "password").await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let delete_req = DeleteAccountReq {
        account: "test_delete@example.com".into(),
    };

    let req = test::TestRequest::post()
        .uri("/accounts/delete-account")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&delete_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_describe_account() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let req = test::TestRequest::post()
        .uri("/accounts/describe-account")
        .set_json(json!({"account":"viewer@email.com"}))
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_describe_self() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let req = test::TestRequest::get()
        .uri("/accounts/describe-self")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
}

#[actix_web::test]
async fn test_update_self() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let update_req = UpdateAccountReq {
        account: "owner@example.com".into(),
        name: Some("Updated Owner".into()),
        password: Some("new_owner_password".into()),
        description: None,
        verified: None,
        enabled: None,
    };

    let req = test::TestRequest::post()
        .uri("/accounts/update-self")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&update_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
}

#[actix_web::test]
async fn test_delete_self() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let req = test::TestRequest::delete()
        .uri("/accounts/delete-self")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_create_service_account() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let create_req = json!({
        "email": "new_service_account@example.com",
        "name": "Service Account",
    });

    let req = test::TestRequest::post()
        .uri("/accounts/create-service-account")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_create_user_account() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let create_req = json!({
        "email": "new_user_account@example.com",
        "name": "User Account",
        "password": "password",
    });

    let req = test::TestRequest::post()
        .uri("/accounts/create-user-account")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_req)
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_get_sa_secret_key() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let sa = get_account_db(&data.db, "service@email.com").await.unwrap();

    let payload = json!({
        "account": sa.id.to_string()
    });

    let req = test::TestRequest::post()
        .uri("/accounts/service-account-secret-key")
        .set_json(payload)
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
}
