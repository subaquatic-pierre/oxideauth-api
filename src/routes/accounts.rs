use std::borrow::Cow;

use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::app::AppData;
use crate::db::queries::account::{get_account_by_email_db, get_account_id_by_email_db};
use crate::models::account::Account;
use crate::models::error::ApiError;
use crate::models::token::TokenClaims;

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

// #[derive(Debug, Deserialize)]
// pub struct LoginReq {
//     pub identity: String,
//     pub password: String,
// }

// #[derive(Debug, Serialize)]
// pub struct LoginRes {
//     pub token: String,
// }

// // TODO: Implement login
// #[post("/login")]
// pub async fn login_user(body: Json<LoginReq>) -> impl Responder {
//     // verify credentials

//     // update db

//     // respond
//     let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

//     let user = Account::default();
//     let token_claims = TokenClaims::new(user, None, None);

//     let token = encode(
//         &Header::default(),
//         &token_claims,
//         &EncodingKey::from_secret(secret.as_ref()),
//     )
//     .unwrap();

//     HttpResponse::Ok().json(LoginRes { token })
// }

// #[derive(Debug, Deserialize)]
// pub struct LogoutReq {
//     pub email: String,
// }

// #[derive(Debug, Serialize)]
// pub struct LogoutRes {
//     pub status: String,
// }

// // TODO: Implement logout
// #[post("/logout")]
// pub async fn logout(req: HttpRequest, body: Json<LogoutReq>) -> impl Responder {
//     // verify token

//     // remove token from DB

//     // respond

//     HttpResponse::Ok().json(LogoutRes {
//         status: "ok".to_string(),
//     })
// }

// // TODO: Implement refresh
// #[post("/refresh-token")]
// pub async fn refresh_user_token(req: HttpRequest, body: Json<LogoutReq>) -> impl Responder {
//     // verify token

//     // remove token from DB

//     // respond

//     HttpResponse::Ok().json(LogoutRes {
//         status: "ok".to_string(),
//     })
// }

pub fn register_accounts_collection() -> Scope {
    scope("/accounts").service(describe_account)
}
