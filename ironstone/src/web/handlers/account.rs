use axum::{
    extract::{rejection::JsonRejection, Extension, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tracing::info;

use crate::{
    app::AppState,
    core::{
        ctx::CoreCtx,
        dto::account::{AccountCreateParams, AccountDescribeParams},
        error::CoreError,
    },
    web::{error::WebResult, middlewares::cors::build_cors, response::WebResponse},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct AccountCreateReq {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct AccountDescribeReq {
    pub email: String,
}

#[derive(Serialize)]
pub struct AccountRes {
    pub id: Uuid,
    pub email: String,
}

#[axum::debug_handler]
pub async fn describe_account(
    ctx: Extension<CoreCtx>,
    app: Extension<Arc<AppState>>,
    body: Result<Json<AccountDescribeReq>, JsonRejection>,
) -> WebResult<WebResponse<AccountRes>> {
    let acc_svc = app.svc_build.account();

    let params = AccountDescribeParams {
        email: body?.email.clone(),
    };

    let acc = acc_svc.describe_account(&ctx, params).await?;

    let acc_res = AccountRes {
        id: acc.id,
        email: acc.email,
    };

    info!("describe_account - CTX: {ctx:#?}");
    WebResponse::json(acc_res)
}

#[axum::debug_handler]
pub async fn list_accounts(
    ctx: Extension<CoreCtx>,
    app: Extension<Arc<AppState>>,
    body: Json<AccountDescribeReq>,
) -> WebResult<WebResponse<AccountRes>> {
    let acc_svc = app.svc_build.account();

    let params = AccountDescribeParams {
        email: body.email.clone(),
    };

    let acc = acc_svc.describe_account(&ctx, params).await?;

    let acc_res = AccountRes {
        id: acc.id,
        email: acc.email,
    };

    info!("describe_account - CTX: {ctx:#?}");
    WebResponse::json(acc_res)
}

#[axum::debug_handler]
pub async fn create_account(
    ctx: Extension<CoreCtx>,
    app: Extension<Arc<AppState>>,
    body: Json<AccountCreateReq>,
) -> WebResult<WebResponse<AccountRes>> {
    let acc_svc = app.svc_build.account();

    let params = AccountCreateParams {
        email: body.email.clone(),
        password: body.password.clone(),
    };

    let acc = acc_svc.create_account(&ctx, params).await?;

    let acc_res = AccountRes {
        id: acc.id,
        email: acc.email,
    };

    info!("describe_account - CTX: {ctx:#?}");
    WebResponse::json(acc_res)
}

pub struct AccountRouter;

impl AccountRouter {
    pub fn routes() -> Router {
        Router::new()
            .route("/describe", post(describe_account))
            .route("/create", post(create_account))
    }
}
