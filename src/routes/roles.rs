use actix_web::web::{Data, Json};
use actix_web::{web::scope, Scope};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::app::AppData;
use crate::db::queries::account::get_account_by_email_db;
use crate::db::queries::role::{
    bind_permission_to_role, bind_role_to_account_db, create_permissions_db, create_role_db,
    delete_permissions_db, delete_role_db, get_all_permissions, get_all_roles_db, get_role_db,
    remove_permission_from_role_db, remove_role_from_account_db,
};
use crate::lib::token::get_token_from_req;
use crate::models::account::Account;
use crate::models::error::ApiError;
use crate::models::role::{Permission, Role};
use crate::models::token::TokenClaims;
use log::{debug, error, info};

#[derive(Debug, Deserialize)]
pub struct CreateRoleReq {
    pub name: String,
    pub permissions: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct CreateRoleRes {
    pub role: Role,
}

#[post("/create-role")]
pub async fn create_role(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<CreateRoleReq>,
) -> impl Responder {
    debug!("{:?}", body);
    let token_str = match get_token_from_req(&req) {
        Some(token) => token,
        None => return ApiError::new("Unable to get token from request").respond_to(&req),
    };

    debug!("token: {token_str:?}");

    let claims = match TokenClaims::from_str(&token_str, &app_data.config) {
        Ok(claims) => claims,
        Err(e) => {
            debug!("{:?}", e);
            // validate expiration

            // validate roles

            // create new role
            return e.respond_to(&req);
        }
    };

    if let Ok(role) = get_role_db(&app_data.db_pool, &body.name).await {
        return ApiError::new(&format!("Role '{:}' already exists", role.name)).respond_to(&req);
    }

    // create role
    let permissions = body.permissions.clone().unwrap_or(vec![]);
    let new_role = Role::new(&body.name, permissions);
    match create_role_db(&app_data.db_pool, &new_role).await {
        Ok(role) => return HttpResponse::Ok().json(CreateRoleRes { role }),
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    }
}

#[derive(Debug, Deserialize)]
pub struct DescribeRoleReq {
    pub role: String,
}
#[derive(Debug, Serialize)]
pub struct DescribeRoleRes {
    pub role: Role,
}

#[post("/describe-role")]
pub async fn describe_role(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<DescribeRoleReq>,
) -> impl Responder {
    // verify credentials
    match get_role_db(&app_data.db_pool, &body.role).await {
        Ok(role) => HttpResponse::Ok().json(DescribeRoleRes { role }),
        Err(e) => ApiError::new(&e.to_string()).respond_to(&req),
    }
}

#[derive(Debug, Serialize)]
pub struct ListRoleRes {
    pub roles: Vec<Role>,
}

#[get("/list-roles")]
pub async fn list_roles(req: HttpRequest, app_data: Data<AppData>) -> impl Responder {
    // verify credentials
    match get_all_roles_db(&app_data.db_pool).await {
        Ok(roles) => HttpResponse::Ok().json(ListRoleRes { roles }),
        Err(e) => ApiError::new(&e.to_string()).respond_to(&req),
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteRoleReq {
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteRoleRes {
    pub deleted_role: String,
}

#[post("/delete-role")]
pub async fn delete_role(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<DeleteRoleReq>,
) -> impl Responder {
    // verify credentials
    let token_str = match get_token_from_req(&req) {
        Some(token) => token,
        None => return ApiError::new("Unable to get token from request").respond_to(&req),
    };

    if let Ok(claims) = TokenClaims::from_str(&token_str, &app_data.config) {
        // validate expiration

        // validate roles

        // create new role
    }

    let role = match get_role_db(&app_data.db_pool, &body.role).await {
        Ok(role) => role,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    match delete_role_db(&app_data.db_pool, &role).await {
        Ok(_) => HttpResponse::Ok().json(DeleteRoleRes {
            deleted_role: role.name,
        }),
        Err(e) => ApiError::new(&e.to_string()).respond_to(&req),
    }
}

#[derive(Debug, Deserialize)]
pub struct AssignRolesReq {
    pub account: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AssignRoleRes {
    pub account: Account,
}

#[post("/assign-roles")]
pub async fn assign_roles(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<AssignRolesReq>,
) -> impl Responder {
    // verify credentials

    // update db

    // respond

    let account = match get_account_by_email_db(&app_data.db_pool, &body.account).await {
        Ok(role) => role,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    for role in &body.roles {
        if let Ok(role) = get_role_db(&app_data.db_pool, role).await {
            match bind_role_to_account_db(&app_data.db_pool, &account, &role).await {
                Ok(_) => {
                    debug!("Role: {role:?} assign to account: {account:?}");
                }
                Err(e) => {
                    error!("Unable to assign role: {role:?} to account: {account:?}, {e}");
                }
            }
        }
    }

    let updated_acc = match get_account_by_email_db(&app_data.db_pool, &body.account).await {
        Ok(role) => role,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(AssignRoleRes {
        account: updated_acc,
    })
}

#[derive(Debug, Deserialize)]
pub struct RemoveRoleReq {
    pub account: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RemoveRoleRes {
    pub account: Account,
}

#[post("/remove-roles")]
pub async fn remove_roles(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<RemoveRoleReq>,
) -> impl Responder {
    let account = match get_account_by_email_db(&app_data.db_pool, &body.account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    for role in &body.roles {
        match get_role_db(&app_data.db_pool, role).await {
            Ok(role) => {
                match remove_role_from_account_db(&app_data.db_pool, &account, &role).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Unable to remove role: {role:?} from account: {account:?}, {e}");
                    }
                }
            }
            Err(e) => {
                error!("Unable to find role '{role}'");
            }
        }
    }

    let updated_account = match get_account_by_email_db(&app_data.db_pool, &body.account).await {
        Ok(acc) => acc,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(RemoveRoleRes {
        account: updated_account,
    })
}

#[derive(Debug, Deserialize)]
struct CreatePermissionsReq {
    permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CreatePermissionsRes {
    created_permissions: Vec<String>,
}

#[post("/create-permissions")]
pub async fn create_permissions(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<CreatePermissionsReq>,
) -> impl Responder {
    // verify credentials
    let token_str = match get_token_from_req(&req) {
        Some(token) => token,
        None => return ApiError::new("unable to get token from request").respond_to(&req),
    };

    if let Ok(claims) = TokenClaims::from_str(&token_str, &app_data.config) {
        // validate expiration

        // validate roles

        // create new role
    }

    let perms = body
        .permissions
        .iter()
        .map(|el| Permission::new(el))
        .collect();

    // update db
    let created_permissions = match create_permissions_db(&app_data.db_pool, perms).await {
        Ok(created_perms) => created_perms,
        Err(e) => {
            return ApiError::new(&e.to_string()).respond_to(&req);
        }
    };

    HttpResponse::Ok().json(CreatePermissionsRes {
        created_permissions,
    })
}

#[derive(Debug, Serialize)]
struct ListPermissionsRes {
    permissions: Vec<String>,
}

#[get("/list-permissions")]
pub async fn list_permissions(req: HttpRequest, app_data: Data<AppData>) -> impl Responder {
    // verify credentials
    let token_str = match get_token_from_req(&req) {
        Some(token) => token,
        None => return ApiError::new("unable to get token from request").respond_to(&req),
    };

    if let Ok(claims) = TokenClaims::from_str(&token_str, &app_data.config) {
        // validate expiration

        // validate roles

        // create new role
    }

    let permissions = match get_all_permissions(&app_data.db_pool).await {
        Ok(perms) => perms,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(ListPermissionsRes { permissions })
}

#[derive(Debug, Deserialize)]
struct DeletePermissionsReq {
    permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DeletePermissionsRes {
    deleted_permissions: Vec<String>,
}

#[post("/delete-permissions")]
pub async fn delete_permissions(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<DeletePermissionsReq>,
) -> impl Responder {
    // verify credentials
    let token_str = match get_token_from_req(&req) {
        Some(token) => token,
        None => return ApiError::new("unable to get token from request").respond_to(&req),
    };

    if let Ok(claims) = TokenClaims::from_str(&token_str, &app_data.config) {
        // validate expiration

        // validate roles

        // create new role
    }

    // update db
    let deleted_permissions =
        match delete_permissions_db(&app_data.db_pool, body.permissions.clone()).await {
            Ok(perms) => perms,
            Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
        };

    HttpResponse::Ok().json(DeletePermissionsRes {
        deleted_permissions,
    })
}

#[derive(Debug, Deserialize)]
struct AssignPermissionsReq {
    role: String,
    permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AssignPermissionsRes {
    role: Role,
}

#[post("/assign-permissions")]
pub async fn assign_permissions(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<AssignPermissionsReq>,
) -> impl Responder {
    // verify credentials
    let token_str = match get_token_from_req(&req) {
        Some(token) => token,
        None => return ApiError::new("unable to get token from request").respond_to(&req),
    };

    if let Ok(claims) = TokenClaims::from_str(&token_str, &app_data.config) {
        // validate expiration

        // validate roles

        // create new role
    }

    let role = match get_role_db(&app_data.db_pool, &body.role).await {
        Ok(role) => role,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    for perm in &body.permissions {
        match bind_permission_to_role(&app_data.db_pool, &role, &perm).await {
            Ok(_) => {
                debug!("Permission: {perm} assign to role: {role:?}");
            }
            Err(e) => {
                error!("Unable to assign permission: {perm} to role: {role:?}, {e}");
            }
        }
    }

    let updated_role = match get_role_db(&app_data.db_pool, &body.role).await {
        Ok(role) => role,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(AssignPermissionsRes { role: updated_role })
}

#[derive(Debug, Deserialize)]
struct RemovePermissionsReq {
    role: String,
    permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RemovePermissionsRes {
    role: Role,
}

#[post("/remove-permissions")]
pub async fn remove_permissions(
    req: HttpRequest,
    app_data: Data<AppData>,
    body: Json<RemovePermissionsReq>,
) -> impl Responder {
    // verify credentials
    let token_str = match get_token_from_req(&req) {
        Some(token) => token,
        None => return ApiError::new("unable to get token from request").respond_to(&req),
    };

    if let Ok(claims) = TokenClaims::from_str(&token_str, &app_data.config) {
        // validate expiration

        // validate roles

        // create new role
    }

    let role = match get_role_db(&app_data.db_pool, &body.role).await {
        Ok(role) => role,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    for perm in &body.permissions {
        match remove_permission_from_role_db(&app_data.db_pool, &role, &perm).await {
            Ok(_) => {
                debug!("Permission: {perm} assign to role: {role:?}");
            }
            Err(e) => {
                error!("Unable to assign permission: {perm} to role: {role:?}, {e}");
            }
        }
    }

    let updated_role = match get_role_db(&app_data.db_pool, &body.role).await {
        Ok(role) => role,
        Err(e) => return ApiError::new(&e.to_string()).respond_to(&req),
    };

    HttpResponse::Ok().json(RemovePermissionsRes { role: updated_role })
}

pub fn register_roles_collection() -> Scope {
    scope("/roles")
        .service(create_role)
        .service(list_roles)
        .service(describe_role)
        .service(delete_role)
        .service(assign_roles)
        .service(remove_roles)
        .service(create_permissions)
        .service(list_permissions)
        .service(delete_permissions)
        .service(assign_permissions)
        .service(remove_permissions)
}
