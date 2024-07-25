use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Error;
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
use crate::utils::email::{send_email, EmailVars};

#[derive(Debug, Deserialize)]
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
    // TODO: authorize request

    let vars = vec![
        EmailVars {
            key: "year".to_string(),
            val: "2024".to_string(),
        },
        EmailVars {
            key: "name".to_string(),
            val: "Pierre Du Toit".to_string(),
        },
        EmailVars {
            key: "confirm_link".to_string(),
            val: "http://localhost:8081/auth/sign-in".to_string(),
        },
    ];

    let template_name = "verify_email.html";
    // let template_name = "confirm_email.html";

    match send_email(
        &app.config,
        &body.to_email,
        &body.subject,
        &template_name,
        vars,
    )
    .await
    {
        Ok(res) => HttpResponse::Ok().json(SendEmailRes {
            message: res.message,
        }),
        Err(e) => e.respond_to(&req),
    }
}

pub fn register_utils_services() -> Scope {
    scope("/utils").service(send_email_req)
}
