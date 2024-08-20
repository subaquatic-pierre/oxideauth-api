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
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tera::Context;

use crate::app::AppData;
use crate::db::queries::account::{self, create_account_db, get_account_db, update_account_db};
use crate::db::queries::role::{bind_role_to_account_db, create_role_db, get_role_db};
use crate::models::account::{Account, AccountProvider, AccountType};
use crate::models::api::ApiError;
use crate::models::oauth::GoogleOAuthState;
use crate::models::role::Role;
use crate::models::token::{TokenClaims, TokenType};
use crate::services::email::EmailService;
use crate::services::storage::S3StorageService;
use crate::utils::auth::{get_google_user, request_google_token, RegisterRedirectParams};
use crate::utils::crypt::{hash_password, verify_password};
use crate::utils::time::get_year;
use crate::utils::token::gen_token;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterReq {
    pub email: String,
    pub password: Option<String>,
    pub name: Option<String>,
    pub redirect_host: Option<String>,
    pub confirm_email_redirect_endpoint: Option<String>,
    pub dashboard_endpoint: Option<String>,
    pub project_name: Option<String>,
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
    if (body.password.is_none()) {
        return ApiError::new_400(&format!("Password required",)).respond_to(&req);
    }

    let password_hash = match hash_password(&body.password.clone().unwrap()) {
        Ok(hash) => hash,
        Err(e) => return e.respond_to(&req),
    };

    if let Ok(_) = get_account_db(&app.db, &body.email).await {
        return ApiError::new_400(&format!(
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
        Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
    };

    let token = match gen_token(&app.config, &user, TokenType::Auth, None) {
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

    let confirm_token = gen_token(&app.config, &new_acc, TokenType::ConfirmAccount, None).unwrap();
    let confirm_params = RegisterRedirectParams::from_req(body, &app.config, &confirm_token);

    // send confirm account email
    let mut context = Context::new();

    context.insert("project_name", &confirm_params.project_name);
    context.insert("name", &new_acc.name);
    context.insert("confirm_link", &confirm_params.confirm_url);
    context.insert("year", &get_year().to_string());

    let template_name = format!("{}/confirm_email.html", confirm_params.project_name);
    let storage = Box::new(S3StorageService::new("oxideauth-emails", &app.config));
    let email_service = EmailService::new(&app.config, storage);

    match email_service
        .send_email(
            &new_acc.email,
            "Confirm Your Account | OxideAuth",
            &template_name,
            context,
        )
        .await
    {
        Ok(res) => {
            info!("{res:?}")
        }
        Err(e) => {
            error!("{e}")
        }
    }

    match bind_role_to_account_db(&app.db, &user, &role).await {
        Ok(_) => HttpResponse::Ok().json(RegisterRes {
            token: token,
            user: new_acc,
        }),
        Err(e) => {
            error!("Unable to create new user, {user:?}");
            ApiError::new_400("Unable to bind Viewer role to account").respond_to(&req)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmAccountReq {
    pub token: String,
    pub redirect_url: String,

    // Next vars are used in welcome email
    pub dashboard_url: String,
    pub project_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConfirmAccountRes {
    pub account: Account,
}

#[get("/confirm-account")]
pub async fn confirm_account(
    req: HttpRequest,
    app: Data<AppData>,
    query: Query<ConfirmAccountReq>,
) -> impl Responder {
    let claims = match TokenClaims::from_str(app.config.jwt_secret.as_ref(), &query.token) {
        Ok(claims) => claims,
        Err(e) => {
            error!("Error building TokenClaims from string, {:?}", e);
            return e.respond_to(&req);
        }
    };

    if claims.token_type != TokenType::ConfirmAccount {
        return ApiError::new_400("Incorrect Token type").respond_to(&req);
    }

    let mut account = match get_account_db(&app.db, &claims.sub).await {
        Ok(acc) => acc,
        Err(e) => {
            error!("{e}");
            return ApiError::new_400("Unable to find account").respond_to(&req);
        }
    };

    account.verified = true;

    match update_account_db(&app.db, &account).await {
        Ok(acc) => {
            let mut context = Context::new();

            let project_name = &query
                .project_name
                .clone()
                .unwrap_or("OxideAuth".to_string());

            context.insert("project_name", &query.project_name);
            context.insert("name", &account.name);
            context.insert("dashboard_link", &query.dashboard_url);
            context.insert("year", &get_year().to_string());

            let template_name = format!("{}/welcome_email.html", project_name);
            let storage = Box::new(S3StorageService::new("oxideauth-emails", &app.config));
            let email_service = EmailService::new(&app.config, storage);

            match email_service
                .send_email(
                    &acc.email,
                    &format!("Welcome to {}", project_name),
                    &template_name,
                    context,
                )
                .await
            {
                Ok(res) => {
                    info!("{res:?}")
                }
                Err(e) => {
                    error!("{e}")
                }
            }

            let mut response = HttpResponse::Found();
            let redirect_url = format!(
                "{}?message=User Account Confirmed&email={}",
                query.redirect_url, account.email
            );
            response.append_header((header::LOCATION, redirect_url));

            response.finish()
        }

        Err(e) => {
            error!("Unable updated account to verified, {account:?}, {e}");
            ApiError::new_400("Unable updated account to verified").respond_to(&req)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetEmailReq {
    pub email: String,
    pub redirect_url: String,
    pub project_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResetEmailRes {
    pub success: bool,
}

#[post("/reset-password")]
pub async fn reset_password(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<ResetEmailReq>,
) -> impl Responder {
    let account = match get_account_db(&app.db, &body.email).await {
        Ok(acc) => acc,
        Err(e) => {
            error!("{e}");
            return ApiError::new_400("Unable to find account").respond_to(&req);
        }
    };

    let reset_token = gen_token(&app.config, &account, TokenType::ResetPassword, None).unwrap();
    let reset_url = format!("{}?token={}", body.redirect_url, reset_token);

    let mut context = Context::new();

    context.insert("year", &get_year().to_string());
    context.insert("reset_url", &reset_url);

    let project_name = &body.project_name.clone().unwrap_or("OxideAuth".to_string());

    let template_name = format!("{}/reset_password.html", project_name);
    let storage = Box::new(S3StorageService::new("oxideauth-emails", &app.config));
    let email_service = EmailService::new(&app.config, storage);

    match email_service
        .send_email(
            &account.email,
            &format!("Reset Your Password | {}", &project_name),
            &template_name,
            context,
        )
        .await
    {
        Ok(res) => {
            info!("{res:?}")
        }
        Err(e) => {
            error!("{e}")
        }
    }

    return HttpResponse::Ok().json(ResetEmailRes { success: true });
}

#[derive(Debug, Deserialize)]
pub struct UpdatePasswordReq {
    pub token: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UpdatePasswordRes {
    pub account: Account,
}

#[post("/update-password")]
pub async fn update_password(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<UpdatePasswordReq>,
) -> impl Responder {
    let claims = match TokenClaims::from_str(app.config.jwt_secret.as_ref(), &body.token) {
        Ok(claims) => claims,
        Err(e) => {
            error!("Error building TokenClaims from string, {:?}", e);
            return e.respond_to(&req);
        }
    };

    if claims.token_type != TokenType::ResetPassword {
        return ApiError::new_400("Incorrect Token type").respond_to(&req);
    }

    let mut account = match get_account_db(&app.db, &claims.sub).await {
        Ok(acc) => acc,
        Err(e) => {
            error!("{e}");
            return ApiError::new_400("Unable to find account").respond_to(&req);
        }
    };

    let password_hash = match hash_password(&body.password) {
        Ok(hash) => hash,
        Err(e) => return e.respond_to(&req),
    };

    account.password_hash = password_hash;

    let updated_account = match update_account_db(&app.db, &account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(UpdatePasswordRes {
        account: updated_account,
    })
}

#[derive(Debug, Serialize)]
pub struct ResendConfirmRes {
    pub success: bool,
}

#[post("/resend-confirm")]
pub async fn resend_confirm(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<RegisterReq>,
) -> impl Responder {
    let account = match get_account_db(&app.db, &body.email).await {
        Ok(acc) => acc,
        Err(e) => {
            error!("{e}");
            return ApiError::new_400("Unable to find account").respond_to(&req);
        }
    };

    if account.verified {
        return ApiError::new_400("Account already confirmed").respond_to(&req);
    }

    let confirm_token = gen_token(&app.config, &account, TokenType::ConfirmAccount, None).unwrap();
    let confirm_params = RegisterRedirectParams::from_req(body, &app.config, &confirm_token);

    // send confirm account email
    let mut context = Context::new();

    context.insert("project_name", &confirm_params.project_name);
    context.insert("name", &account.name);
    context.insert("confirm_link", &confirm_params.confirm_url);
    context.insert("year", &get_year().to_string());

    let template_name = format!("{}/confirm_email.html", confirm_params.project_name);
    let storage = Box::new(S3StorageService::new("oxideauth-emails", &app.config));
    let email_service = EmailService::new(&app.config, storage);

    match email_service
        .send_email(
            &account.email,
            &format!("Confirm Your Account | {}", confirm_params.project_name),
            &template_name,
            context,
        )
        .await
    {
        Ok(res) => {
            info!("{res:?}")
        }
        Err(e) => {
            error!("{e}")
        }
    }

    HttpResponse::Ok().json(ResendConfirmRes { success: true })
}

#[derive(Debug, Deserialize)]
pub struct LoginReq {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginRes {
    pub account: Account,
    pub token: String,
}

#[post("/login")]
pub async fn login_user(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<LoginReq>,
) -> impl Responder {
    match get_account_db(&app.db, &body.email).await {
        Ok(user) => {
            if (user.password_hash == "" && user.provider != AccountProvider::Local) {
                return ApiError::new_400("User account signed up with OAuth provider, please use 'forgot password' to create new password").respond_to(&req);
            }
            match verify_password(&user.password_hash, &body.password) {
                Ok(is_valid) => {
                    if is_valid {
                        let token = match gen_token(&app.config, &user, TokenType::Auth, None) {
                            Ok(t) => t,
                            Err(e) => return e.respond_to(&req),
                        };

                        return HttpResponse::Ok().json(LoginRes {
                            token,
                            account: user,
                        });
                    } else {
                        return ApiError::new_400("Invalid password").respond_to(&req);
                    }
                }

                Err(e) => return e.respond_to(&req),
            }
        }
        _ => {
            return ApiError::new_400("No user found").respond_to(&req);
        }
    }
}

#[derive(Debug, Serialize)]
struct RefreshTokenRes {
    token: String,
}

#[get("/refresh-token")]
pub async fn refresh_token(req: HttpRequest, app: Data<AppData>) -> impl Responder {
    let required_perms = [];

    let account = match app.guard.authorize_req(&req, &required_perms).await {
        Ok(token) => token,
        Err(e) => return e.respond_to(&req),
    };

    let token = gen_token(&app.config, &account, TokenType::Auth, None).unwrap();

    HttpResponse::Ok().json(RefreshTokenRes { token })
}

#[derive(Debug, Deserialize)]
pub struct QueryCode {
    pub code: String,
    pub state: Option<String>,
}

#[get("/oauth/google")]
pub async fn google_oauth_handler(
    req: HttpRequest,
    query: Query<QueryCode>,
    app: Data<AppData>,
) -> impl Responder {
    let code = &query.code;
    let state = &query.state;

    let google_state = GoogleOAuthState::from_state(state.clone(), &app.config);

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
                    google_user.verified_email,
                );

                match create_account_db(&app.db, &new_user).await {
                    Ok(acc) => {
                        if let Ok(role) = get_role_db(&app.db, "Viewer").await {
                            bind_role_to_account_db(&app.db, &acc, &role).await.ok();
                        }
                        // send welcome email
                        let mut context = Context::new();

                        context.insert("project_name", &google_state.project_name);
                        context.insert("name", &acc.name);
                        context.insert("dashboard_link", &google_state.dash_url);
                        context.insert("year", &get_year().to_string());

                        let template_name =
                            format!("{}/welcome_email.html", google_state.project_name);
                        let storage =
                            Box::new(S3StorageService::new("oxideauth-emails", &app.config));
                        let email_service = EmailService::new(&app.config, storage);

                        match email_service
                            .send_email(
                                &acc.email,
                                &format!("Welcome to {}", google_state.project_name),
                                &template_name,
                                context,
                            )
                            .await
                        {
                            Ok(res) => {
                                info!("{res:?}")
                            }
                            Err(e) => {
                                error!("{e}")
                            }
                        }

                        acc
                    }
                    Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
                }
            }
            _ => return ApiError::new_400(&e.to_string()).respond_to(&req),
        },
    };

    let token = gen_token(&app.config, &account, TokenType::Auth, None).unwrap();

    let mut response = HttpResponse::Found();
    let redirect_location = format!("{}?token={}", google_state.redirect_url, token);
    response.append_header((header::LOCATION, redirect_location));

    response.finish()
}

pub fn register_auth_collection() -> Scope {
    scope("/auth")
        .service(login_user)
        .service(register_user)
        .service(resend_confirm)
        .service(confirm_account)
        .service(reset_password)
        .service(update_password)
        .service(refresh_token)
        .service(google_oauth_handler)
}
