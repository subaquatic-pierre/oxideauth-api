use actix_http::StatusCode;
use actix_web::{test, web, App};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use oxideauth::app::AppConfig;
use oxideauth::db::queries::account::get_account_db;
use oxideauth::models::account::Principal;
use oxideauth::utils::token::{encode_token, gen_token};
use oxideauth::{
    app::new_test_app_data,
    models::{
        account::Account,
        guard::AuthGuard,
        token::{TokenClaims, TokenType},
    },
};
use serial_test::serial;

fn generate_test_token(config: &AppConfig, account: &Account, token_type: TokenType) -> String {
    let token = gen_token(config, account, token_type, None).unwrap();
    token
}

#[actix_web::test]
#[serial]
async fn test_get_token_claims_success() {
    let data = new_test_app_data().await;

    let auth_guard = AuthGuard::new(&data.config.jwt_secret, data.db.clone());

    let account = get_account_db(&data.db, "viewer@email.com").await.unwrap();

    let token_str = generate_test_token(&data.config, &account, TokenType::Auth);
    let claims = auth_guard.get_token_claims(&token_str).await.unwrap();

    assert_eq!(claims.token_type, TokenType::Auth);
    assert_eq!(claims.sub, account.id());
}

#[actix_web::test]
#[serial]
async fn test_authorize_req_success() {
    let data = new_test_app_data().await;
    let auth_guard = AuthGuard::new(&data.config.jwt_secret, data.db.clone());

    let account = get_account_db(&data.db, "viewer@email.com").await.unwrap();

    let token_str = generate_test_token(&data.config, &account, TokenType::Auth);
    let req = test::TestRequest::default()
        .insert_header(("Authorization", format!("Bearer {}", token_str)))
        .to_http_request();

    let res = auth_guard
        .authorize_req(&req, &["auth.accounts.describeSelf"])
        .await
        .unwrap();

    assert_eq!(res.id(), account.id());
}

#[actix_web::test]
#[serial]
async fn test_authorize_req_token_expired() {
    let data = new_test_app_data().await;
    let auth_guard = AuthGuard::new(&data.config.jwt_secret, data.db.clone());

    // Create an expired token
    let account = get_account_db(&data.db, "viewer@email.com").await.unwrap();

    let token_str = generate_test_token(&data.config, &account, TokenType::Auth);
    // Simulate expiration by modifying the token if necessary
    let mut claims = TokenClaims::from_str(&data.config.jwt_secret, &token_str).unwrap();
    claims.exp = 0;

    let expired_token_str = encode_token(&data.config.jwt_secret, &claims).unwrap();

    let req = test::TestRequest::default()
        .insert_header(("Authorization", format!("Bearer {}", expired_token_str)))
        .to_http_request();

    let result = auth_guard.authorize_req(&req, &["some_permission"]).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().status, StatusCode::BAD_REQUEST);
}

#[actix_web::test]
#[serial]
async fn test_authorize_req_invalid_token_type() {
    let data = new_test_app_data().await;
    let jwt_secret = "supersecretkey";
    let auth_guard = AuthGuard::new(jwt_secret, data.db.clone());

    let account = get_account_db(&data.db, "viewer@email.com").await.unwrap();

    let token_str = generate_test_token(&data.config, &account, TokenType::Auth);
    let req = test::TestRequest::default()
        .insert_header(("Authorization", format!("Bearer {}", token_str)))
        .to_http_request();

    let result = auth_guard
        .authorize_req(&req, &["auth.accounts.create"])
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().status, StatusCode::BAD_REQUEST);
}
