use axum::{
    extract::{Extension, State},
    routing::get,
    Router,
};
use std::sync::Arc;
use tracing::info;

use crate::{
    app::AppState,
    core::ctx::CoreCtx,
    web::{error::WebResult, middlewares::cors::build_cors, response::WebResponse},
};

pub async fn root_handler(
    ctx: Extension<CoreCtx>,
    state: Extension<Arc<AppState>>,
) -> WebResult<WebResponse<String>> {
    info!("ROOT HANDLER - CTX: {ctx:#?}");
    WebResponse::from_json("Hello, World".to_string())
}

pub async fn health_check_handler(
    ctx: Extension<CoreCtx>,
    state: Extension<Arc<AppState>>,
) -> &'static str {
    "Healthy!"
}
