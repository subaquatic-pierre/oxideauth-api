use axum::{
    extract::{rejection::JsonRejection, Extension, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tracing::{debug, info};

use crate::{
    app::App,
    core::{
        ctx::CoreCtx,
        dto::{
            account::{AccountCreateParams, AccountDescribeParams, AccountListParams},
            list::{ListResponse, ListResponseMeta, RequestFilterParams, RequestListOptions},
        },
        error::CoreError,
        models::account::Account,
    },
    store::entities::account::AccountFilter,
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
    app: Extension<App>,
    body: Result<Json<AccountDescribeReq>, JsonRejection>,
) -> WebResult<WebResponse<AccountRes>> {
    let svc = app.svc_build.account();

    let params = AccountDescribeParams {
        email: body?.email.clone(),
    };

    let acc = svc.describe(&ctx, params).await?;

    let acc_res = AccountRes {
        id: acc.id,
        email: acc.email,
    };

    info!("describe_account - CTX: {ctx:#?}");
    WebResponse::json(acc_res)
}

#[derive(Deserialize, Debug)]
pub struct AccountListReq {
    pub filter: Option<RequestFilterParams<AccountFilter>>,
    pub options: Option<RequestListOptions>,
}

impl From<AccountListReq> for AccountListParams {
    fn from(value: AccountListReq) -> Self {
        Self {
            filter: value.filter,
            options: value.options,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct AccountListRes {
    pub accounts: Vec<Account>,
    pub metadata: ListResponseMeta,
}

#[axum::debug_handler]
pub async fn list_accounts(
    ctx: Extension<CoreCtx>,
    app: Extension<App>,
    body: Json<AccountListReq>,
) -> WebResult<AccountListRes> {
    let svc = app.svc_build.account();
    debug!("list_account - body: {:#?}", body);

    let params: AccountListParams = body.0.into();
    let res = svc.list(&ctx, params).await?;

    let res = AccountListRes {
        accounts: res.data,
        metadata: res.metadata,
    };

    // info!("list_account - CTX: {ctx:#?}");
    WebResponse::json_flat(res)
}

#[axum::debug_handler]
pub async fn create_account(
    ctx: Extension<CoreCtx>,
    app: Extension<App>,
    body: Json<AccountCreateReq>,
) -> WebResult<WebResponse<AccountRes>> {
    let svc = app.svc_build.account();

    let params = AccountCreateParams {
        email: body.email.clone(),
        password: body.password.clone(),
    };

    let acc = svc.create(&ctx, params).await?;

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
            .route("/list", post(list_accounts))
    }
}
