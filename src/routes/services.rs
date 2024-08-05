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

#[derive(Debug, Deserialize)]
pub struct CreateServiceReq {
    pub name: String,
    pub endpoint: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateServiceRes {
    pub service: Service,
}

#[post("/create-service")]
pub async fn create_service(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<CreateServiceReq>,
) -> impl Responder {
    if let Err(e) = app
        .guard
        .authorize_req(&req, &["auth.services.create"])
        .await
    {
        return e.respond_to(&req);
    }

    let new_service = Service::new(&body.name, body.endpoint.clone(), body.description.clone());

    let created_service = match create_service_db(&app.db, &new_service).await {
        Ok(services) => services,
        Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(CreateServiceRes {
        service: created_service,
    })
}

#[derive(Debug, Serialize)]
pub struct ListServicesRes {
    pub services: Vec<Service>,
}

#[get("/list-services")]
pub async fn list_services(req: HttpRequest, app: Data<AppData>) -> impl Responder {
    if let Err(e) = app.guard.authorize_req(&req, &["auth.services.list"]).await {
        return e.respond_to(&req);
    }

    let services = match get_all_services_db(&app.db).await {
        Ok(services) => services,
        Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(ListServicesRes { services })
}

#[derive(Debug, Deserialize)]
pub struct UpdateServiceReq {
    pub service: String,
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateServiceRes {
    pub service: Service,
}

#[post("/update-service")]
pub async fn update_service(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<UpdateServiceReq>,
) -> impl Responder {
    if let Err(e) = app
        .guard
        .authorize_req(&req, &["auth.services.update"])
        .await
    {
        return e.respond_to(&req);
    }

    let mut service = match get_service_db(&app.db, &body.service).await {
        Ok(service) => service,
        Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
    };

    if service.name == "OxideAuth" {
        if body.description.is_some() {
            return ApiError::new_400(
                "Cannot change the description of the default OxideAuth service",
            )
            .respond_to(&req);
        }
        return ApiError::new_400("Cannot change the name of the default OxideAuth service")
            .respond_to(&req);
    }

    if let Some(name) = &body.name {
        // TODO: ensure correct check logic for name update/conflict
        // ensure cannot change service name to service with name that already exists
        match Uuid::parse_str(&body.service) {
            Ok(_) => {
                if let Ok(existing_svc) = get_service_db(&app.db, &name).await {
                    if existing_svc.id != service.id {
                        return ApiError::new_400(&format!(
                            "Cannot update service name to '{name}'"
                        ))
                        .respond_to(&req);
                    }
                }
            }
            Err(_) => {
                if let Ok(existing_svc) = get_service_db(&app.db, &name).await {
                    if existing_svc.id != service.id {
                        return ApiError::new_400(&format!(
                            "Cannot update service name to '{name}'"
                        ))
                        .respond_to(&req);
                    }
                }
            }
        }

        service.name = name.clone();
    };

    if body.endpoint.is_some() {
        service.endpoint = body.endpoint.clone();
    }
    if body.description.is_some() {
        service.description = body.description.clone();
    }

    let updated_service = match update_service_db(&app.db, &service).await {
        Ok(svc) => svc,
        Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(UpdateServiceRes {
        service: updated_service,
    })
}

#[derive(Debug, Deserialize)]
pub struct DescribeServiceReq {
    pub service: String,
}

#[derive(Debug, Serialize)]
pub struct DescribeServiceRes {
    pub service: Service,
}

#[post("/describe-service")]
pub async fn describe_service(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<UpdateServiceReq>,
) -> impl Responder {
    if let Err(e) = app
        .guard
        .authorize_req(&req, &["auth.services.describe"])
        .await
    {
        return e.respond_to(&req);
    }

    let service = match get_service_db(&app.db, &body.service).await {
        Ok(service) => service,
        Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(DescribeServiceRes { service: service })
}

#[derive(Debug, Deserialize)]
pub struct DeleteServiceReq {
    pub service: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteServiceRes {
    pub deleted: bool,
}

#[post("/delete-service")]
pub async fn delete_service(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<UpdateServiceReq>,
) -> impl Responder {
    if let Err(e) = app
        .guard
        .authorize_req(&req, &["auth.services.delete"])
        .await
    {
        return e.respond_to(&req);
    }

    let service = match get_service_db(&app.db, &body.service).await {
        Ok(service) => service,
        Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
    };

    if service.name == "OxideAuth" {
        return ApiError::new_400("Cannot delete default OxideAuth service").respond_to(&req);
    }

    match delete_service_db(&app.db, &service).await {
        Ok(_) => HttpResponse::Ok().json(DeleteServiceRes { deleted: true }),
        Err(e) => ApiError::new_400(&e.to_string()).respond_to(&req),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatePermissionsReq {
    pub requesting_token: String,
    pub required_permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ValidatePermissionsRes {
    pub authorized: bool,
}

#[post("/validate-permissions")]
pub async fn validate_permissions(
    req: HttpRequest,
    app: Data<AppData>,
    body: Json<ValidatePermissionsReq>,
) -> impl Responder {
    if let Err(e) = app
        .guard
        .authorize_req(&req, &["auth.services.validatePermissions"])
        .await
    {
        return e.respond_to(&req);
    }

    let requesting_claims = match app.guard.get_token_claims(&body.requesting_token).await {
        Ok(claims) => claims,
        Err(e) => return e.respond_to(&req),
    };

    let requesting_account = match get_account_db(&app.db, &requesting_claims.sub).await {
        Ok(service) => service,
        Err(e) => return ApiError::new_400(&e.to_string()).respond_to(&req),
    };

    let mut acc_perms = vec![];
    requesting_account
        .roles
        .iter()
        .for_each(|el| acc_perms.extend(el.permissions.clone()));

    for needed_perm in &body.required_permissions {
        if !acc_perms.contains(needed_perm) {
            return HttpResponse::Ok().json(ValidatePermissionsRes { authorized: false });
        }
    }
    return HttpResponse::Ok().json(ValidatePermissionsRes { authorized: true });
}

pub fn register_services_collection() -> Scope {
    scope("/services")
        .service(create_service)
        .service(list_services)
        .service(update_service)
        .service(describe_service)
        .service(delete_service)
        .service(validate_permissions)
}
