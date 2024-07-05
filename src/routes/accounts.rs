use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Error;
use uuid::Uuid;

use crate::app::AppData;
use crate::db::queries::account::{
    delete_account_db, get_account_db, get_all_accounts_db, update_account_db,
};
use crate::lib::crypt::hash_password;
use crate::models::account::Account;
use crate::models::api::ApiError;

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
    pub email: Option<String>,
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

    if let Some(email) = &body.email {
        // ensure cannot change email to account with email that already exists
        match Uuid::parse_str(&body.account) {
            Ok(id) => {
                if let Ok(existing_acc) = get_account_db(&app.db, &email.clone()).await {
                    if existing_acc.id != account.id {
                        return ApiError::new(&format!(
                            "Cannot update account to new email '{email}'"
                        ))
                        .respond_to(&req);
                    }
                }
            }
            Err(_) => {
                if let Ok(existing_acc) = get_account_db(&app.db, &email.clone()).await {
                    if existing_acc.id != account.id {
                        return ApiError::new(&format!(
                            "Cannot update account to new email '{email}'"
                        ))
                        .respond_to(&req);
                    }
                }
            }
        }

        account.email = email.to_string();
    }
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
    pub email: Option<String>,
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
    if let Some(email) = &body.email {
        // ensure cannot change email to account with email that already exists
        if let Ok(existing_acc) = get_account_db(&app.db, &email.clone()).await {
            if existing_acc.id != account.id {
                return ApiError::new(&format!("Cannot update account to new email '{email}'"))
                    .respond_to(&req);
            }
        }
        account.email = email.to_string();
    }
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

// #[derive(Debug, Deserialize)]
// pub struct CreateAccountReq {
//     pub email: String,
//     pub name: Option<String>,
//     pub password: Option<String>,
//     pub description: Option<String>,
// }

// #[derive(Debug, Serialize)]
// pub struct CreateAccountRes {
//     pub account: Account,
// }

// #[post("/create-account")]
// pub async fn create_account(
//     req: HttpRequest,
//     app: Data<AppData>,
//     body: Json<UpdateAccountReq>,
// ) -> impl Responder {
//     let required_perms = ["auth.accounts.update"];

//     if let Ok(_) = get_account_db(&app.db, &body.email).await {
//         return ApiError::new(&format!(
//             "Account with email '{}' already exists",
//             body.email
//         ))
//         .respond_to(&req);
//     };

//     let password_hash = match &body.password {
//         Some(p) => {
//             let hash = match hash_password(&p) {
//                 Ok(hash) => hash,
//                 Err(e) => return e.respond_to(&req),
//             };
//             hash
//         }
//         None => {
//             let hash = match hash_password(&app.config.default_sa_password) {
//                 Ok(hash) => hash,
//                 Err(e) => return e.respond_to(&req),
//             };
//             hash
//         }
//     };

//     let token = match app.guard.authorize_req(&req, &required_perms).await {
//         Ok(token) => token,
//         Err(e) => return e.respond_to(&req),
//     };

//     let account = match get_account_db(&app.db, &token.sub).await {
//         Ok(acc) => acc,
//         Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
//     };

//     let pw_hash = match &body.password {
//         Some(p) => {
//             let hash = match hash_password(&p) {
//                 Ok(p) => p,
//                 Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
//             };
//             Some(hash)
//         }
//         None => None,
//     };

//     match update_account_db(
//         &app.db,
//         &account.id,
//         body.name.clone(),
//         body.email.clone(),
//         pw_hash,
//         body.description.clone(),
//     )
//     .await
//     {
//         Ok(updated) => return HttpResponse::Ok().json(DescribeAccountRes { account: updated }),
//         Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
//     };
// }

pub fn register_accounts_collection() -> Scope {
    scope("/accounts")
        .service(describe_account)
        .service(describe_self)
        .service(update_self)
        .service(update_account)
        .service(update_account)
        .service(delete_account)
        .service(list_accounts)
}
