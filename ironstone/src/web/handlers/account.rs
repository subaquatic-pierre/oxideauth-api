use axum::{
    extract::{Extension, State},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tracing::info;

use crate::{
    app::AppState,
    core::{ctx::CoreCtx, error::CoreError},
    web::{error::WebResult, middlewares::cors::build_cors, response::WebResponse},
};

pub async fn describe_account(
    ctx: Extension<CoreCtx>,
    state: Extension<Arc<AppState>>,
) -> WebResult<WebResponse<String>> {
    info!("ROOT HANDLER - CTX: {ctx:#?}");
    WebResponse::from_json("Hello, World".to_string())
}

pub async fn create_account(
    ctx: Extension<CoreCtx>,
    state: Extension<Arc<AppState>>,
) -> &'static str {
    "Healthy!"
}

pub fn build_account_routes() -> Router {
    Router::new()
        .route("/describe", post(describe_account))
        .route("/create", post(create_account))
}
