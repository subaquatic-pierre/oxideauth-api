use actix_web::dev::ServiceResponse;
use actix_web::http::header::{HeaderValue, AUTHORIZATION};
use actix_web::{http::StatusCode, test, App};
use oxideauth::app::new_test_app_data;
use oxideauth::db::queries::account::get_account_db;
use oxideauth::models::account::Principal;
use oxideauth::models::service::Service;
use oxideauth::routes::services::{
    CreateServiceReq, CreateServiceRes, DeleteServiceReq, DeleteServiceRes, DescribeServiceReq,
    DescribeServiceRes, ListServicesRes, UpdateServiceReq, UpdateServiceRes,
    ValidatePermissionsReq, ValidatePermissionsRes,
};
use oxideauth::utils::test_utils::{login_owner, setup_test_server};
use serde_json::json;
use serial_test::serial;

// Test for creating a new service
#[actix_web::test]
#[serial]
async fn test_create_service() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // Prepare the request payload
    let payload = CreateServiceReq {
        name: "new_service".to_string(),
        endpoint: Some("http://example.com".to_string()),
        description: Some("A test service".to_string()),
    };

    // Make the request to create a service
    let req = test::TestRequest::post()
        .uri("/services/create-service")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&payload)
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;

    // Validate the response
    assert_eq!(resp.status(), StatusCode::OK);

    let body: CreateServiceRes = test::read_body_json(resp).await;

    assert_eq!(body.service.name, "new_service");
    assert_eq!(body.service.endpoint.unwrap(), "http://example.com");
    assert_eq!(body.service.description.unwrap(), "A test service");
}

// Test for listing all services
#[actix_web::test]
#[serial]
async fn test_list_services() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // Make the request to list services
    let req = test::TestRequest::get()
        .uri("/services/list-services")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;

    // Validate the response
    assert_eq!(resp.status(), StatusCode::OK);

    let body: ListServicesRes = test::read_body_json(resp).await;

    assert!(!body.services.is_empty());
}

// Test for updating an existing service
#[actix_web::test]
#[serial]
async fn test_update_service() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // First, create a service to update
    let create_payload = CreateServiceReq {
        name: "service_to_update".to_string(),
        endpoint: Some("http://example.com".to_string()),
        description: Some("Original description".to_string()),
    };

    let create_req = test::TestRequest::post()
        .uri("/services/create-service")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_payload)
        .to_request();

    let create_resp: ServiceResponse = test::call_service(&mut app, create_req).await;
    let created_service: CreateServiceRes = test::read_body_json(create_resp).await;

    // Prepare the update payload
    let update_payload = UpdateServiceReq {
        service: created_service.service.id.to_string(),
        name: Some("updated_service".to_string()),
        endpoint: Some("http://updated.com".to_string()),
        description: Some("Updated description".to_string()),
    };

    // Make the request to update the service
    let update_req = test::TestRequest::post()
        .uri("/services/update-service")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&update_payload)
        .to_request();

    let update_resp: ServiceResponse = test::call_service(&mut app, update_req).await;

    // Validate the response
    assert_eq!(update_resp.status(), StatusCode::OK);

    let body: UpdateServiceRes = test::read_body_json(update_resp).await;

    assert_eq!(body.service.name, "updated_service");
    assert_eq!(body.service.endpoint.unwrap(), "http://updated.com");
    assert_eq!(body.service.description.unwrap(), "Updated description");
}

// Test for describing a specific service
#[actix_web::test]
#[serial]
async fn test_describe_service() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // First, create a service to describe
    let create_payload = CreateServiceReq {
        name: "service_to_describe".to_string(),
        endpoint: Some("http://example.com".to_string()),
        description: Some("A test service".to_string()),
    };

    let create_req = test::TestRequest::post()
        .uri("/services/create-service")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_payload)
        .to_request();

    let create_resp: ServiceResponse = test::call_service(&mut app, create_req).await;
    let created_service: CreateServiceRes = test::read_body_json(create_resp).await;

    // Prepare the describe payload
    let describe_payload = DescribeServiceReq {
        service: created_service.service.id.to_string(),
    };

    // Make the request to describe the service
    let describe_req = test::TestRequest::post()
        .uri("/services/describe-service")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&describe_payload)
        .to_request();

    let describe_resp: ServiceResponse = test::call_service(&mut app, describe_req).await;

    // Validate the response
    assert_eq!(describe_resp.status(), StatusCode::OK);

    let body: DescribeServiceRes = test::read_body_json(describe_resp).await;

    assert_eq!(body.service.name, "service_to_describe");
    assert_eq!(body.service.endpoint.unwrap(), "http://example.com");
    assert_eq!(body.service.description.unwrap(), "A test service");
}

// Test for deleting a service
#[actix_web::test]
#[serial]
async fn test_delete_service() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // First, create a service to delete
    let create_payload = CreateServiceReq {
        name: "service_to_delete".to_string(),
        endpoint: Some("http://example.com".to_string()),
        description: Some("A test service".to_string()),
    };

    let create_req = test::TestRequest::post()
        .uri("/services/create-service")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_payload)
        .to_request();

    let create_resp: ServiceResponse = test::call_service(&mut app, create_req).await;
    let created_service: CreateServiceRes = test::read_body_json(create_resp).await;

    // Prepare the delete payload
    let delete_payload = DeleteServiceReq {
        service: created_service.service.id.to_string(),
    };

    // Make the request to delete the service
    let delete_req = test::TestRequest::post()
        .uri("/services/delete-service")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&delete_payload)
        .to_request();

    let delete_resp: ServiceResponse = test::call_service(&mut app, delete_req).await;

    // Validate the response
    assert_eq!(delete_resp.status(), StatusCode::OK);

    let body: DeleteServiceRes = test::read_body_json(delete_resp).await;

    assert!(body.deleted);
}

// Test for validating permissions
#[actix_web::test]
#[serial]
async fn test_validate_permissions() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // Prepare the validate permissions payload
    let validate_payload = ValidatePermissionsReq {
        requesting_token: token.to_string(),
        required_permissions: vec!["auth.services.create".to_string()],
    };

    // Make the request to validate permissions
    let validate_req = test::TestRequest::post()
        .uri("/services/validate-permissions")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&validate_payload)
        .to_request();

    let validate_resp: ServiceResponse = test::call_service(&mut app, validate_req).await;

    // Validate the response
    assert_eq!(validate_resp.status(), StatusCode::OK);

    let body: ValidatePermissionsRes = test::read_body_json(validate_resp).await;

    assert!(body.authorized);
}
