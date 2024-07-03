use std::borrow::Cow;

use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::app::AppData;
use crate::db::queries::account::{
    delete_account_db, get_account_by_email_db, get_account_id_by_email_db, get_all_accounts_db,
    update_account_db,
};
use crate::models::account::Account;
use crate::models::error::ApiError;
use crate::models::token::TokenClaims;

#[derive(Debug, Serialize)]
pub struct ListAccountsRes {
    pub accounts: Vec<Account>,
}

#[get("/list-accounts")]
pub async fn list_accounts(req: HttpRequest, app_data: Data<AppData>) -> impl Responder {
    // check user exists in DB

    // update db

    // respond
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let user = Account::default();
    let token_claims = TokenClaims::new(user, None, vec![]);

    let token = encode(
        &Header::default(),
        &token_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap();

    let accounts = match get_all_accounts_db(&app_data.db_pool).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(ListAccountsRes { accounts })
}

#[derive(Debug, Deserialize)]
pub struct UpdateAccountReq {
    pub account: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateAccountRes {
    pub account: Account,
}

#[post("/update-account")]
pub async fn update_account(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<UpdateAccountReq>,
) -> impl Responder {
    // check user exists in DB

    // update db

    // respond
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let user = Account::default();
    let token_claims = TokenClaims::new(user, None, vec![]);

    let token = encode(
        &Header::default(),
        &token_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap();

    let account = match get_account_by_email_db(&app_data.db_pool, &body.account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    // update account with new values, or default to old values

    let updated_account = match update_account_db(
        &app_data.db_pool,
        &account.id.to_string(),
        body.name.clone(),
        body.email.clone(),
    )
    .await
    {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(UpdateAccountRes {
        account: updated_account,
    })
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountReq {
    pub account: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteAccountRes {
    pub deleted: bool,
}

#[post("/delete-account")]
pub async fn delete_account(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<DeleteAccountReq>,
) -> impl Responder {
    // check user exists in DB

    // update db

    // respond
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let user = Account::default();
    let token_claims = TokenClaims::new(user, None, vec![]);

    let token = encode(
        &Header::default(),
        &token_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap();

    let account = match get_account_by_email_db(&app_data.db_pool, &body.account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    // update account with new values, or default to old values

    match delete_account_db(&app_data.db_pool, &account).await {
        Ok(_) => HttpResponse::Ok().json(DeleteAccountRes { deleted: true }),
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    }
}

#[derive(Debug, Deserialize)]
pub struct DescribeAccountReq {
    pub account: String,
}

#[derive(Debug, Serialize)]
pub struct DescribeAccountRes {
    pub account: Account,
}

#[post("/describe-account")]
pub async fn describe_account(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<DescribeAccountReq>,
) -> impl Responder {
    // check user exists in DB

    // update db

    // respond
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let user = Account::default();
    let token_claims = TokenClaims::new(user, None, vec![]);

    let token = encode(
        &Header::default(),
        &token_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap();

    let account = match get_account_by_email_db(&app_data.db_pool, &body.account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(DescribeAccountRes { account })
}

pub fn register_accounts_collection() -> Scope {
    scope("/accounts")
        .service(describe_account)
        .service(update_account)
        .service(delete_account)
        .service(list_accounts)
}
