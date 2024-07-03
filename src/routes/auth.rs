use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::app::AppData;
use crate::db::queries::account::{create_account_db, get_account_by_email_db};
use crate::models::account::{Account, AccountType};
use crate::models::error::ApiError;
use crate::models::token::TokenClaims;
use crate::utils::crypt::{hash_password, verify_password};
use crate::utils::token::gen_token;

#[derive(Debug, Deserialize)]
pub struct RegisterReq {
    pub email: String,
    pub password: String,
    pub username: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterRes {
    pub user: Account,
    pub token: String,
}

// TODO: Implement login
#[post("/register")]
pub async fn register_user(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<RegisterReq>,
) -> impl Responder {
    let password_hash = match hash_password(&body.password) {
        Ok(hash) => hash,
        Err(e) => return e.respond_to(&req),
    };

    if let Ok(_) = get_account_by_email_db(&app_data.db_pool, &body.email).await {
        return ApiError::new("User already exists").respond_to(&req);
    }

    let name = &body.username.clone().unwrap_or("".to_string());
    let user = Account::new(&body.email, name, &password_hash, AccountType::User, vec![]);

    // update db
    if let Err(e) = create_account_db(&app_data.db_pool, &user).await {
        return ApiError::new(&e.to_string()).respond_to(&req);
    }

    let token = match gen_token(&app_data.config, &user) {
        Ok(t) => t,
        Err(e) => return e.respond_to(&req),
    };

    HttpResponse::Ok().json(RegisterRes {
        token: token,
        user: user,
    })
}

#[derive(Debug, Deserialize)]
pub struct LoginReq {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginRes {
    pub token: String,
}

// TODO: Implement login
#[post("/login")]
pub async fn login_user(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<LoginReq>,
) -> impl Responder {
    match get_account_by_email_db(&app_data.db_pool, &body.email).await {
        Ok(user) => match verify_password(&user.password_hash, &body.password) {
            Ok(is_valid) => {
                if is_valid {
                    let token = match gen_token(&app_data.config, &user) {
                        Ok(t) => t,
                        Err(e) => return e.respond_to(&req),
                    };

                    return HttpResponse::Ok().json(LoginRes { token });
                } else {
                    return ApiError::new("invalid password").respond_to(&req);
                }
            }
            Err(e) => return e.respond_to(&req),
        },
        _ => {
            return ApiError::new("no user found").respond_to(&req);
        }
    }

    ApiError::new("unable to login").respond_to(&req)
}

#[derive(Debug, Deserialize)]
pub struct LogoutReq {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct LogoutRes {
    pub status: String,
}

// TODO: Implement logout
#[post("/logout")]
pub async fn logout_user(req: HttpRequest, body: Json<LogoutReq>) -> impl Responder {
    // verify token

    // remove token from DB

    // respond

    HttpResponse::Ok().json(LogoutRes {
        status: "ok".to_string(),
    })
}

// TODO: Implement refresh
#[post("/refresh-token")]
pub async fn refresh_user_token(req: HttpRequest, body: Json<LogoutReq>) -> impl Responder {
    // verify token

    // remove token from DB

    // respond

    HttpResponse::Ok().json(LogoutRes {
        status: "ok".to_string(),
    })
}

pub fn register_auth_collection() -> Scope {
    scope("/auth").service(login_user).service(register_user)
}
