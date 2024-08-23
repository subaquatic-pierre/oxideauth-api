use actix_web::{test, App};
use oxideauth;

use oxideauth::app::{new_app_data, register_all_services};

#[actix_rt::test]
async fn test_token_endpoint() {
    // Setup the app
    let app_data = new_app_data().await;

    // Initialize the app with routes and services
    let mut app = test::init_service(
        App::new()
            .app_data(app_data.clone())
            .service(register_all_services()),
    )
    .await;

    // Create the request
    let req = test::TestRequest::post()
        .uri("/api/token")
        .set_json(&serde_json::json!({
            "username": "test_user",
            "password": "test_password"
        }))
        .to_request();

    // Send the request and get the response
    let resp = test::call_service(&mut app, req).await;

    // Assert the response status code
    assert_eq!(resp.status(), 200);

    // Optionally, parse and assert the response body
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("token").is_some(), "Token was not returned");
}
