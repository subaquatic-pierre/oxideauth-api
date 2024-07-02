use std::borrow::Cow;

use actix_web::web::Json;
use actix_web::{web::scope, Scope};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::models::account::Account;
use crate::models::role::Role;
use crate::models::token::TokenClaims;

#[derive(Debug, Serialize)]
pub struct RoleListRes {
    pub roles: Vec<Role>,
}

#[get("/list")]
pub async fn list_roles(req: HttpRequest) -> impl Responder {
    // verify credentials
    let role = Role::default();

    HttpResponse::Ok().json(RoleListRes { roles: vec![role] })
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleReq {
    pub name: String,
    pub principal: String,
}

#[derive(Debug, Serialize)]
pub struct CreateRoleRes {
    pub role: Role,
}

#[post("/create")]
pub async fn create_role(req: HttpRequest, body: Json<CreateRoleReq>) -> impl Responder {
    // verify credentials

    // update db

    // respond
    let role = Role::default();

    HttpResponse::Ok().json(CreateRoleRes { role })
}

#[derive(Debug, Deserialize)]
pub struct AssignRoleReq {
    pub name: String,
    pub principal: String,
}

#[derive(Debug, Serialize)]
pub struct AssignRoleRes {
    pub role: Role,
}

#[post("/assign")]
pub async fn assign_role(req: HttpRequest, body: Json<AssignRoleReq>) -> impl Responder {
    // verify credentials

    // update db

    // respond

    let role = Role::default();

    HttpResponse::Ok().json(AssignRoleRes { role })
}

pub fn register_roles_collection() -> Scope {
    scope("/roles")
        .service(list_roles)
        .service(create_role)
        .service(assign_role)
}
