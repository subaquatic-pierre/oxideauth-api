use axum::{extract::State, routing::get, Router};
use std::sync::Arc;

use crate::{app::AppState, web::middlewares::cors::build_cors};

/// A simple handler function that returns a static string.
pub async fn root_handler(State(state): State<Arc<AppState>>) -> &'static str {
    "Hello, World!"
}

pub async fn health_check_handler(State(state): State<Arc<AppState>>) -> &'static str {
    "Healthy!"
}
