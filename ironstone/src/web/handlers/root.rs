use axum::{
    extract::{Extension, State},
    routing::get,
    Router,
};
use std::sync::Arc;
use tracing::info;

use crate::{
    app::AppState,
    core::{ctx::CoreCtx, error::CoreError},
    web::{error::WebResult, middlewares::cors::build_cors, response::WebResponse},
};

pub async fn root_handler(
    ctx: Extension<CoreCtx>,
    app: Extension<Arc<AppState>>,
) -> WebResult<WebResponse<String>> {
    info!("root_handler - CTX: {ctx:#?}");
    WebResponse::from_json("Hello, World".to_string())
}

pub async fn health_check_handler(
    ctx: Extension<CoreCtx>,
    app: Extension<Arc<AppState>>,
) -> WebResult<WebResponse<String>> {
    info!("health_check_handler - CTX: {ctx:#?}");
    WebResponse::from_json("Healthy".to_string())
}
