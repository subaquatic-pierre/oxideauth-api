use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::app::AppData;
use crate::db::queries::account::{create_account_db, get_account_db};
use crate::db::queries::role::{bind_role_to_account_db, create_role_db, get_role_db};
use crate::lib::crypt::{hash_password, verify_password};
use crate::lib::token::gen_token;
use crate::models::account::{Account, AccountType};
use crate::models::api::ApiError;
use crate::models::role::Role;
use crate::models::token::TokenClaims;

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

#[post("/register")]
pub async fn register_user(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<RegisterReq>,
) -> impl Responder {
    let password_hash = match hash_password(&body.password) {
        Ok(hash) => hash,
        Err(e) => return e.respond_to(&req),
    };

    if let Ok(_) = get_account_db(&app.db, &body.email).await {
        return ApiError::new(&format!(
            "Cannot create Account with email '{}'",
            body.email
        ))
        .respond_to(&req);
    }

    let name = &body.username.clone().unwrap_or("".to_string());
    let user = Account::new(&body.email, name, &password_hash, AccountType::User, vec![]);

    // update db
    let new_acc = match create_account_db(&app.db, &user).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    let token = match gen_token(&app.config, &user) {
        Ok(t) => t,
        Err(e) => return e.respond_to(&req),
    };

    let role = match get_role_db(&app.db, "viewer").await {
        Ok(res) => res,
        Err(_e) => {
            let viewer_role = Role::new("viewer", vec![]);
            if let Err(e) = create_role_db(&app.db, &viewer_role).await {
                error!("Unable to create viewer role, {viewer_role:?}, {e}");
            }
            viewer_role
        }
    };

    match bind_role_to_account_db(&app.db, &user, &role).await {
        Ok(_) => HttpResponse::Ok().json(RegisterRes {
            token: token,
            user: new_acc,
        }),
        Err(e) => {
            error!("Unable to create new user, {user:?}");
            ApiError::new("Unable to bind viewer role to account").respond_to(&req)
        }
    }
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

#[post("/login")]
pub async fn login_user(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<LoginReq>,
) -> impl Responder {
    match get_account_db(&app.db, &body.email).await {
        Ok(user) => match verify_password(&user.password_hash, &body.password) {
            Ok(is_valid) => {
                if is_valid {
                    let token = match gen_token(&app.config, &user) {
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
