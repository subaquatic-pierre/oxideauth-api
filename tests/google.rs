use oxideauth::{
    app::AppConfig,
    utils::auth::{get_google_user, request_google_token, GoogleUserResult, OAuthResponse},
};
use serde_json::json;

// NOTE: Unable to run async thread from within async method
// need to find another way to mock response from google

// Mock request for Google token
// #[tokio::test]
// async fn test_request_google_token() {
//     let config = AppConfig::mock_config();
//     let authorization_code = "mock_authorization_code";

//     // Mock response
//     let response = OAuthResponse {
//         access_token: "mock_access_token".to_string(),
//         id_token: "mock_id_token".to_string(),
//     };

//     // Set up the mock HTTP client
//     let client = reqwest::Client::builder().build().unwrap();
//     let mut mock_server = mockito::Server::new();
//     let _mock = mock_server
//         .mock("POST", "/token")
//         .with_status(200)
//         .with_body(json!(response).to_string())
//         .create();

//     let res = request_google_token(authorization_code, &config).await;
//     assert!(res.is_ok());

//     let oauth_response = res.unwrap();
//     assert_eq!(oauth_response.access_token, "mock_access_token");
//     assert_eq!(oauth_response.id_token, "mock_id_token");
// }

// // Mock response for Google user info
// #[actix_web::test]
// async fn test_get_google_user() {
//     let access_token = "mock_access_token";
//     let id_token = "mock_id_token";

//     // Mock response
//     let response = GoogleUserResult {
//         id: "mock_id".to_string(),
//         email: "mock_email@example.com".to_string(),
//         verified_email: true,
//         name: "Mock User".to_string(),
//         given_name: Some("Mock".to_string()),
//         family_name: Some("User".to_string()),
//         picture: Some("http://example.com/picture".to_string()),
//         locale: Some("en".to_string()),
//     };

//     // Set up the mock HTTP client
//     let client = reqwest::Client::builder().build().unwrap();
//     let mut mock_server = mockito::Server::new();
//     let _mock = mock_server
//         .mock("GET", "/userinfo")
//         .with_status(200)
//         .with_body(json!(response).to_string())
//         .create();

//     let res = get_google_user(access_token, id_token).await;
//     assert!(res.is_ok());

//     let user_info = res.unwrap();
//     assert_eq!(user_info.id, "mock_id");
//     assert_eq!(user_info.email, "mock_email@example.com");
//     assert_eq!(user_info.name, "Mock User");
// }
