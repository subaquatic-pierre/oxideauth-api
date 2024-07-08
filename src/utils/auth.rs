use actix_web::web::{scope, Data};
use actix_web::{web, App, HttpServer, Scope};
use log::info;
use std::{collections::HashSet, env};

use dotenv::dotenv;

use crate::app::AppConfig;
use crate::models::api::{ApiError, ApiResult};
use crate::routes::accounts::register_accounts_collection;
use crate::routes::auth::register_auth_collection;
use crate::routes::roles::register_roles_collection;
use crate::routes::services::register_services_collection;

use reqwest::{Client, Url};
use serde::Deserialize;
use std::error::Error;

use crate::models::{
    account::{Account, AccountType},
    role::RolePermissions,
};

use super::crypt::hash_password;

pub fn build_owner_account() -> Account {
    dotenv().ok();

    let owner_email = env::var("OWNER_EMAIL").unwrap_or("owner@email.com".to_string());
    let password = env::var("OWNER_PASSWORD").unwrap_or("password".to_string());

    let pw_hash = hash_password(&password).unwrap_or("unhashed_password".to_string());

    let owner_acc = Account::new_local_user(&owner_email, "owner", &pw_hash);
    owner_acc
}

#[derive(Deserialize, Debug)]
pub struct OAuthResponse {
    pub access_token: String,
    pub id_token: String,
}

#[derive(Deserialize, Debug)]
pub struct OAuthErrorResponse {
    pub error: String,
    pub error_description: String,
}

#[derive(Deserialize, Debug)]
pub struct GoogleUserResult {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
}

pub async fn request_google_token(
    authorization_code: &str,
    config: &AppConfig,
) -> ApiResult<OAuthResponse> {
    let redirect_url = config.google_oauth_redirect_url.to_owned();
    let client_secret = config.google_oauth_client_secret.to_owned();
    let client_id = config.google_oauth_client_id.to_owned();

    let root_url = "https://oauth2.googleapis.com/token";
    let client = Client::new();

    let params = [
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_url.as_str()),
        ("client_id", client_id.as_str()),
        ("code", authorization_code),
        ("client_secret", client_secret.as_str()),
    ];

    let res = client
        .post(root_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            ApiError::new(&format!(
                "An error occurred while trying to retrieve access token, {e}"
            ))
        })?;

    info!("response: {res:?}");

    match res.status().is_success() {
        true => match res.json::<OAuthResponse>().await {
            Ok(r) => Ok(r),
            Err(e) => Err(ApiError::new(&format!(
                "An error occurred while trying to retrieve access token, {e}"
            ))),
        },
        false => {
            if let Ok(json) = res.json::<OAuthErrorResponse>().await {
                Err(ApiError::new(&format!(
                    "An error occurred while trying to retrieve access token, error: {}, description: {}",
                    json.error,
                    json.error_description
                )))
            } else {
                Err(ApiError::new(&format!(
                    "An error occurred while trying to retrieve access token.",
                )))
            }
        }
    }
}

pub async fn get_google_user(access_token: &str, id_token: &str) -> ApiResult<GoogleUserResult> {
    let client = Client::new();
    let mut url = Url::parse("https://www.googleapis.com/oauth2/v1/userinfo").unwrap();
    url.query_pairs_mut().append_pair("alt", "json");
    url.query_pairs_mut()
        .append_pair("access_token", access_token);

    let response = client
        .get(url)
        .bearer_auth(id_token)
        .send()
        .await
        .map_err(|e| {
            ApiError::new(&format!(
                "An error occurred while trying to retrieve access token, {e}"
            ))
        })?;

    if response.status().is_success() {
        let user_info = response.json::<GoogleUserResult>().await.map_err(|e| {
            ApiError::new(&format!(
                "An error occurred while trying to retrieve access token, {e}"
            ))
        })?;
        Ok(user_info)
    } else {
        let message = "An error occurred while trying to retrieve user information.";
        Err(ApiError::new(message))
    }
}
