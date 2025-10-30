use axum::{extract::State, routing::get, Router};
use std::sync::Arc;

use crate::{
    app::AppState,
    web::{
        handlers::root::{health_check_handler, root_handler},
        middlewares::cors::build_cors,
    },
};

pub struct RootRouter;

impl RootRouter {
    pub fn build_routes_with_state(state: Arc<AppState>) -> Router {
        let cors = build_cors();
        Router::new()
            .route("/", get(root_handler))
            .route("/health-check", get(health_check_handler))
            .layer(cors)
            .with_state(state)
    }
}
