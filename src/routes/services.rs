use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Error;
use uuid::Uuid;

use crate::app::AppData;
use crate::db;
use crate::db::queries::service::{
    self, create_service_db, delete_service_db, get_all_services_db, get_service_db,
    update_service_db,
};
use crate::models::api::ApiError;
use crate::models::service::Service;

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
    // TODO: authorize request
    let new_service = Service::new(&body.name, body.endpoint.clone(), body.description.clone());

    let created_service = match create_service_db(&app.db, &new_service).await {
        Ok(services) => services,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
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
    // TODO: authorize request
    let services = match get_all_services_db(&app.db).await {
        Ok(services) => services,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
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
    // TODO: authorize request
    let mut service = match get_service_db(&app.db, &body.service).await {
        Ok(service) => service,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    if service.name == "Auth" {
        if body.description.is_some() {
            return ApiError::new("Cannot change the description of the default Auth service")
                .respond_to(&req);
        }
        return ApiError::new("Cannot change the name of the default Auth service")
            .respond_to(&req);
    }

    if let Some(name) = &body.name {
        // TODO: ensure correct check logic for name update/conflict
        // ensure cannot change service name to service with name that already exists
        match Uuid::parse_str(&body.service) {
            Ok(_) => {
                if let Ok(existing_svc) = get_service_db(&app.db, &name).await {
                    if existing_svc.id != service.id {
                        return ApiError::new(&format!("Cannot update service name to '{name}'"))
                            .respond_to(&req);
                    }
                }
            }
            Err(_) => {
                if let Ok(existing_svc) = get_service_db(&app.db, &name).await {
                    if existing_svc.id != service.id {
                        return ApiError::new(&format!("Cannot update service name to '{name}'"))
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
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
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
    // TODO: authorize request
    let service = match get_service_db(&app.db, &body.service).await {
        Ok(service) => service,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
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
    // TODO: authorize request
    let service = match get_service_db(&app.db, &body.service).await {
        Ok(service) => service,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    if service.name == "Auth" {
        return ApiError::new("Cannot delete Auth service").respond_to(&req);
    }

    match delete_service_db(&app.db, &service).await {
        Ok(_) => HttpResponse::Ok().json(DeleteServiceRes { deleted: true }),
        Err(e) => ApiError::new(&e.to_string()).respond_to(&req),
    }
}

pub fn register_services_collection() -> Scope {
    scope("/services")
        .service(create_service)
        .service(list_services)
        .service(update_service)
        .service(describe_service)
        .service(delete_service)
}
