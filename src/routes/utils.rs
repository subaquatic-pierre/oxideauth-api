use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Error;
use tera::Context;
use uuid::Uuid;

use crate::app::AppData;
use crate::db;
use crate::db::queries::account::get_account_db;
use crate::db::queries::service::{
    self, create_service_db, delete_service_db, get_all_services_db, get_service_db,
    update_service_db,
};
use crate::models::api::ApiError;
use crate::models::service::Service;
use crate::models::token::TokenClaims;
use crate::services::email::EmailService;
use crate::services::storage::{
    LocalStorageService, S3StorageService, StorageService, StorageServiceType,
};
use crate::utils::time::get_year;
use log::{debug, error, info};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailReq {
    pub to_email: String,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Serialize)]
pub struct SendEmailRes {
    pub message: String,
}

#[post("/send-email")]
pub async fn send_email_req(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<SendEmailReq>,
) -> impl Responder {
    if let Err(e) = app
        .guard
        .authorize_req(&req, &["auth.utils.sendEmail"])
        .await
    {
        return e.respond_to(&req);
    }

    let mut context = Context::new();

    context.insert("project_name", "OxideAuth");
    context.insert("name", "Pierre Du Toit");
    context.insert("confirm_link", "http://localhost:8081/auth/sign-in");
    context.insert("year", &get_year().to_string());

    // let template_name = "verify_email.html";
    let project_name = "OxideAuth";
    let template_name = format!("{project_name}/confirm_email.html");
    let storage = Box::new(S3StorageService::new("oxideauth-emails", &app.config));
    let email_service = EmailService::new(&app.config, storage);

    match email_service
        .send_email(&body.to_email, &body.subject, &template_name, context)
        .await
    {
        Ok(res) => HttpResponse::Ok().json(SendEmailRes {
            message: res.message,
        }),
        Err(e) => e.respond_to(&req),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetFileReq {
    pub filename: String,
    pub storage_type: StorageServiceType,
}

#[derive(Debug, Serialize)]
pub struct GetFileRes {
    pub content: String,
}

#[post("/get-file")]
pub async fn get_file(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<GetFileReq>,
) -> impl Responder {
    let storage: Box<dyn StorageService> = match body.storage_type {
        StorageServiceType::S3 => Box::new(S3StorageService::new("oxideauth-emails", &app.config)),
        StorageServiceType::Local => Box::new(LocalStorageService::new("data")),
    };

    let contents = match storage.get_file(&body.filename).await {
        Ok(s) => s.to_string(),
        Err(e) => {
            error!("Error reading file, {}, {e}", &body.filename);
            e.to_string()
        }
    };

    HttpResponse::Ok().json(GetFileRes { content: contents })
}

pub fn register_utils_services() -> Scope {
    scope("/utils").service(send_email_req).service(get_file)
}
