use axum::{
    extract::{Extension, State},
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
    web::{
        dto::account::{AccountCreateReq, AccountDescribeReq, AccountRes},
        error::WebResult,
        middlewares::cors::build_cors,
        response::WebResponse,
    },
};

#[axum::debug_handler]
pub async fn describe_account(
    ctx: Extension<CoreCtx>,
    app: Extension<Arc<AppState>>,
    body: Json<AccountDescribeReq>,
) -> WebResult<WebResponse<AccountRes>> {
    let acc_svc = app.svc_build.build_acc_svc();

    let params = AccountDescribeParams {
        email: body.email.clone(),
    };

    let acc = acc_svc.describe_account(&ctx, params).await?;

    let acc_res = AccountRes {
        id: acc.id,
        email: acc.email,
    };

    info!("describe_account - CTX: {ctx:#?}");
    WebResponse::from_json(acc_res)
}

#[axum::debug_handler]
pub async fn create_account(
    ctx: Extension<CoreCtx>,
    app: Extension<Arc<AppState>>,
    body: Json<AccountCreateReq>,
) -> WebResult<WebResponse<AccountRes>> {
    let acc_svc = app.svc_build.build_acc_svc();

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
    WebResponse::from_json(acc_res)
}

pub fn build_account_routes() -> Router {
    Router::new()
        .route("/describe", post(describe_account))
        .route("/create", post(create_account))
}
