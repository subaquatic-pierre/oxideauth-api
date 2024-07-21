use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::error;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Error;
use uuid::Uuid;

use crate::app::AppData;
use crate::db::queries::account::{
    create_account_db, delete_account_db, get_account_db, get_all_accounts_db, update_account_db,
};
use crate::db::queries::role::{bind_role_to_account_db, create_role_db, get_role_db};
use crate::models::account::Account;
use crate::models::api::ApiError;
use crate::models::role::Role;
use crate::utils::crypt::hash_password;

#[derive(Debug, Serialize)]
pub struct ListAccountsRes {
    pub accounts: Vec<Account>,
}

#[get("/list-accounts")]
pub async fn list_accounts(req: HttpRequest, app: Data<AppData>) -> impl Responder {
    // TODO: authorize request
    let accounts = match get_all_accounts_db(&app.db).await {
        Ok(mut accounts) => {
            accounts
                .iter_mut()
                .for_each(|el| el.set_skip_serialize_permissions(true));
            accounts
        }
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(ListAccountsRes { accounts })
}

#[derive(Debug, Deserialize)]
pub struct UpdateAccountReq {
    pub account: String,
    // pub email: Option<String>,
    pub name: Option<String>,
    pub password: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateAccountRes {
    pub account: Account,
}

#[post("/update-account")]
pub async fn update_account(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<UpdateAccountReq>,
) -> impl Responder {
    // TODO: logic to check external provider email change
    // if the user registers from OAuth provider, they shouldn't be able to change their email

    // TODO: authorize request
    let mut account = match get_account_db(&app.db, &body.account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    // update account with new values
    if let Some(p) = &body.password {
        let hash = match hash_password(&p) {
            Ok(p) => p,
            Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
        };

        account.password_hash = hash
    }

    // NOTE: update user email currently not allowed
    // if let Some(email) = &body.email {
    //     // TODO: ensure correct check logic for email update/conflict
    //     // ensure cannot change email to account with email that already exists
    //     match Uuid::parse_str(&body.account) {
    //         Ok(_) => {
    //             if let Ok(existing_acc) = get_account_db(&app.db, &email.clone()).await {
    //                 if existing_acc.id != account.id {
    //                     return ApiError::new(&format!(
    //                         "Cannot update account to new email '{email}'"
    //                     ))
    //                     .respond_to(&req);
    //                 }
    //             }
    //         }
    //         Err(_) => {
    //             if let Ok(existing_acc) = get_account_db(&app.db, &email.clone()).await {
    //                 if existing_acc.id != account.id {
    //                     return ApiError::new(&format!(
    //                         "Cannot update account to new email '{email}'"
    //                     ))
    //                     .respond_to(&req);
    //                 }
    //             }
    //         }
    //     }

    //     account.email = email.to_string();
    // }

    if let Some(name) = &body.name {
        account.name = name.to_string();
    }
    if let Some(d) = &body.description {
        account.description = Some(d.to_string())
    }

    let updated_account = match update_account_db(&app.db, &account).await {
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
    app: Data<AppData>,
    body: Json<DeleteAccountReq>,
) -> impl Responder {
    // TODO: authorize request
    let account = match get_account_db(&app.db, &body.account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    match delete_account_db(&app.db, &account).await {
        Ok(_) => HttpResponse::Ok().json(DeleteAccountRes { deleted: true }),
        Err(e) => ApiError::new(&e.to_string()).respond_to(&req),
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
    app: Data<AppData>,
    body: Json<DescribeAccountReq>,
) -> impl Responder {
    // TODO: authorize request
    let account = match get_account_db(&app.db, &body.account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(DescribeAccountRes { account })
}

#[get("/describe-self")]
pub async fn describe_self(req: HttpRequest, app: Data<AppData>) -> impl Responder {
    let required_perms = ["auth.accounts.describeSelf"];

    let token = match app.guard.authorize_req(&req, &required_perms).await {
        Ok(token) => token,
        Err(e) => return e.respond_to(&req),
    };

    let account = match get_account_db(&app.db, &token.sub).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    return HttpResponse::Ok().json(DescribeAccountRes { account });
}

#[derive(Debug, Deserialize)]
pub struct UpdateSelfReq {
    pub name: Option<String>,
    // pub email: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateSelfRes {
    pub account: Account,
}

#[post("/update-self")]
pub async fn update_self(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<UpdateSelfReq>,
) -> impl Responder {
    // TODO: logic to check external provider email change
    // if the user registers from OAuth provider, they shouldn't be able to change their email

    let required_perms = ["auth.accounts.updateSelf"];

    let token = match app.guard.authorize_req(&req, &required_perms).await {
        Ok(token) => token,
        Err(e) => return e.respond_to(&req),
    };

    let mut account = match get_account_db(&app.db, &token.sub).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    // update account with new values
    if let Some(p) = &body.password {
        let hash = match hash_password(&p) {
            Ok(p) => p,
            Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
        };

        account.password_hash = hash
    }

    // NOTE: update user email currently not allowed
    // if let Some(email) = &body.email {
    //     // ensure cannot change email to account with email that already exists
    //     if let Ok(existing_acc) = get_account_db(&app.db, &email.clone()).await {
    //         if existing_acc.id != account.id {
    //             return ApiError::new(&format!("Cannot update account to new email '{email}'"))
    //                 .respond_to(&req);
    //         }
    //     }
    //     account.email = email.to_string();
    // }

    if let Some(name) = &body.name {
        account.name = name.to_string();
    }

    let updated_account = match update_account_db(&app.db, &account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(UpdateSelfRes {
        account: updated_account,
    })
}

#[derive(Debug, Deserialize)]
pub struct CreateServiceAccountReq {
    pub email: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateServiceAccountRes {
    pub account: Account,
}

#[post("/create-service-account")]
pub async fn create_service_account(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<CreateServiceAccountReq>,
) -> impl Responder {
    // TODO: authorize request

    if let Ok(_) = get_account_db(&app.db, &body.email).await {
        return ApiError::new(&format!(
            "Cannot create Account with email '{}'",
            body.email
        ))
        .respond_to(&req);
    }

    let service_account =
        Account::new_service_account(&body.email, &body.name, body.description.clone());

    // update db
    let new_acc = match create_account_db(&app.db, &service_account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(CreateServiceAccountRes { account: new_acc })
}

#[derive(Debug, Deserialize)]
pub struct CreateUserAccountReq {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct CreateUserAccountRes {
    pub account: Account,
}

#[post("/create-user-account")]
pub async fn create_user_account(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<CreateUserAccountReq>,
) -> impl Responder {
    // TODO: authorize request

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

    let image_url = format!(
        "{}/assets/images/users/default.png",
        app.config.client_origin
    );
    let user = Account::new_local_user(&body.email, &body.name, &password_hash, Some(image_url));

    // update db
    let new_acc = match create_account_db(&app.db, &user).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
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
        Ok(_) => HttpResponse::Ok().json(CreateUserAccountRes { account: new_acc }),
        Err(e) => {
            error!("Unable to create new user, {user:?}");
            ApiError::new("Unable to bind Viewer role to account").respond_to(&req)
        }
    }
}

pub fn register_accounts_collection() -> Scope {
    scope("/accounts")
        .service(describe_account)
        .service(describe_self)
        .service(update_self)
        .service(update_account)
        .service(update_account)
        .service(delete_account)
        .service(list_accounts)
        .service(create_service_account)
        .service(create_user_account)
}
