use actix_web::web::{Data, Json, Query};
use actix_web::{
    cookie::{time::Duration as ActixWebDuration, Cookie},
    web::scope,
    Scope,
};
use actix_web::{http::header, HttpResponse};
use chrono::{prelude::*, Duration};
use sqlx::Error;

use actix_web::{get, post, web, HttpRequest, Responder};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::app::AppData;
use crate::db::queries::account::{self, create_account_db, get_account_db};
use crate::db::queries::role::{bind_role_to_account_db, create_role_db, get_role_db};
use crate::models::account::{Account, AccountProvider, AccountType};
use crate::models::api::ApiError;
use crate::models::oauth::GoogleOAuthState;
use crate::models::role::Role;
use crate::models::token::TokenClaims;
use crate::utils::auth::{get_google_user, request_google_token};
use crate::utils::crypt::{hash_password, verify_password};
use crate::utils::token::gen_token;

#[derive(Debug, Deserialize)]
pub struct RegisterReq {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
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

    let name = &body.name.clone().unwrap_or("".to_string());
    let image_url = format!(
        "{}/assets/images/users/default.png",
        app.config.client_origin
    );
    let user = Account::new_local_user(&body.email, name, &password_hash, Some(image_url));

    // update db
    let new_acc = match create_account_db(&app.db, &user).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    let token = match gen_token(&app.config, &user) {
        Ok(t) => t,
        Err(e) => return e.respond_to(&req),
    };

    let role = match get_role_db(&app.db, "Viewer").await {
        Ok(res) => res,
        Err(_e) => {
            let viewer_role = Role::new("Viewer", vec![], None);
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
            ApiError::new("Unable to bind Viewer role to account").respond_to(&req)
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

#[derive(Debug, Deserialize)]
pub struct QueryCode {
    pub code: String,
    pub state: Option<String>,
}

// TODO: Implement refresh
#[get("/oauth/google")]
pub async fn google_oauth_handler(
    req: HttpRequest,
    query: Query<QueryCode>,
    app: Data<AppData>,
) -> impl Responder {
    let code = &query.code;
    let state = &query.state;

    let google_state = GoogleOAuthState::from_state(state.clone());

    info!("{google_state:?}");

    if google_state.csrf_token != "secretToken" {
        return HttpResponse::ExpectationFailed().json(json!({"message":"Incorrect CSRF token"}));
    }

    let google_token_res = match request_google_token(code.as_str(), &app.config)
        .await
        .map_err(|e| e.respond_to(&req))
    {
        Ok(t) => t,
        Err(e) => return e.respond_to(&req),
    };

    let google_user =
        match get_google_user(&google_token_res.access_token, &google_token_res.id_token).await {
            Ok(u) => u,
            Err(e) => return e.respond_to(&req),
        };

    info!("GOOGLE TOKEN: {google_token_res:?}, GOOGLE_USER: {google_user:?}");

    let account = match get_account_db(&app.db, &google_user.email).await {
        Ok(acc) => acc,
        Err(e) => match e {
            Error::RowNotFound => {
                // create new user
                let new_user = Account::new_provider_user(
                    &google_user.email,
                    &google_user.name,
                    AccountProvider::Google,
                    Some(google_user.id),
                    google_user.picture,
                );

                match create_account_db(&app.db, &new_user).await {
                    Ok(acc) => {
                        if let Ok(role) = get_role_db(&app.db, "Viewer").await {
                            bind_role_to_account_db(&app.db, &acc, &role).await.ok();
                        }
                        acc
                    }
                    Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
                }
            }
            _ => return ApiError::new(&e.to_string()).respond_to(&req),
        },
    };

    let exp = (Utc::now() + Duration::minutes(app.config.jwt_max_age)).timestamp() as usize;
    let claims: TokenClaims = TokenClaims::new(&account, Some(exp));
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(app.config.jwt_secret.as_ref()),
    )
    .unwrap();

    let mut response = HttpResponse::Found();
    let redirect_location = format!("{}?token={}", google_state.redirect_url, token,);
    response.append_header((header::LOCATION, redirect_location));

    response.finish()
}

pub fn register_auth_collection() -> Scope {
    scope("/auth")
        .service(login_user)
        .service(register_user)
        .service(google_oauth_handler)
}
