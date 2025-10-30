use axum::{routing::get, Router};

/// A simple handler function that returns a static string.
pub async fn root_handler() -> &'static str {
    "Hello, World!"
}

pub async fn health_check_handler() -> &'static str {
    "Healthy!"
}

pub fn build_root_router() -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/health-check", get(health_check_handler))
}
