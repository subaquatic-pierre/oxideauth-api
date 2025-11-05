use axum::{
    extract::{rejection::JsonRejection, Extension, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tracing::info;

use crate::{
    app::App,
    core::{
        ctx::CoreCtx,
        dto::{
            account::{AccountCreateParams, AccountDescribeParams},
            workspace::{
                WorkspaceCreateParams, WorkspaceDeleteParams, WorkspaceDescribeParams,
                WorkspaceListParams, WorkspaceUpdateParams,
            },
        },
        error::CoreError,
    },
    web::{error::WebResult, middlewares::cors::build_cors, response::WebResponse},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize)]
pub struct WorkspaceRes {
    pub id: Uuid,
}

#[derive(Deserialize)]
pub struct WorkspaceDescribeReq {
    pub email: String,
}

#[axum::debug_handler]
pub async fn describe_workspace(
    ctx: Extension<CoreCtx>,
    app: Extension<App>,
    body: Result<Json<WorkspaceDescribeReq>, JsonRejection>,
) -> WebResult<WebResponse<WorkspaceRes>> {
    let svc = app.svc_build.workspace();

    let params = WorkspaceDescribeParams { id: Uuid::new_v4() };
    let ws = svc.describe(&ctx, params).await?;

    let ws_res = WorkspaceRes { id: ws.id };

    info!("describe_workspace - CTX: {ctx:#?}");
    WebResponse::json(ws_res)
}

#[derive(Deserialize)]
pub struct WorkspaceListReq {
    pub email: String,
}

#[axum::debug_handler]
pub async fn list_workspace(
    ctx: Extension<CoreCtx>,
    app: Extension<App>,
    body: Json<WorkspaceListReq>,
) -> WebResult<WebResponse<Vec<WorkspaceRes>>> {
    let svc = app.svc_build.workspace();

    let params = WorkspaceListParams {};

    let ws = svc.list(&ctx, params).await?;

    let ws_res = ws.iter().map(|el| WorkspaceRes { id: el.id }).collect();

    info!("describe_workspace - CTX: {ctx:#?}");
    WebResponse::json(ws_res)
}

#[derive(Deserialize)]
pub struct WorkspaceCreateReq {
    pub email: String,
    pub password: String,
}

#[axum::debug_handler]
pub async fn create_workspace(
    ctx: Extension<CoreCtx>,
    app: Extension<App>,
    body: Json<WorkspaceCreateReq>,
) -> WebResult<WebResponse<WorkspaceRes>> {
    let svc = app.svc_build.workspace();

    let params = WorkspaceCreateParams {};

    let ws = svc.create(&ctx, params).await?;

    let ws_res = WorkspaceRes { id: ws.id };

    info!("describe_workspace - CTX: {ctx:#?}");
    WebResponse::json(ws_res)
}

#[derive(Deserialize)]
pub struct WorkspaceDeleteReq {
    pub email: String,
    pub password: String,
}

#[axum::debug_handler]
pub async fn delete_workspace(
    ctx: Extension<CoreCtx>,
    app: Extension<App>,
    body: Json<WorkspaceDeleteReq>,
) -> WebResult<WebResponse<WorkspaceRes>> {
    let svc = app.svc_build.workspace();

    let params = WorkspaceDeleteParams { id: Uuid::new_v4() };

    let ws = svc.delete(&ctx, params).await?;

    let ws_res = WorkspaceRes { id: ws.id };

    info!("describe_workspace - CTX: {ctx:#?}");
    WebResponse::json(ws_res)
}

#[derive(Deserialize)]
pub struct WorkspaceUpdateReq {
    pub email: String,
    pub password: String,
}

#[axum::debug_handler]
pub async fn update_workspace(
    ctx: Extension<CoreCtx>,
    app: Extension<App>,
    body: Json<WorkspaceUpdateReq>,
) -> WebResult<WebResponse<WorkspaceRes>> {
    let svc = app.svc_build.workspace();

    let params = WorkspaceUpdateParams { id: Uuid::new_v4() };

    let ws = svc.update(&ctx, params).await?;

    let ws_res = WorkspaceRes { id: ws.id };

    info!("describe_workspace - CTX: {ctx:#?}");
    WebResponse::json(ws_res)
}

pub struct WorkspaceRouter;

impl WorkspaceRouter {
    pub fn routes() -> Router {
        Router::new()
            .route("/describe", post(describe_workspace))
            .route("/list", post(list_workspace))
            .route("/create", post(create_workspace))
            .route("/update", post(update_workspace))
            .route("/delete", post(create_workspace))
    }
}
