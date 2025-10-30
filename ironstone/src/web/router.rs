use axum::{extract::Extension, routing::get, Router};
use std::sync::Arc;

use crate::{
    app::AppState,
    core::ctx::CoreCtx,
    web::{
        handlers::{
            account::build_account_routes,
            root::{health_check_handler, root_handler},
        },
        middlewares::{
            auth::{AuthLayer, AuthMiddleware},
            cors::build_cors,
        },
    },
};

pub struct RootRouter;

impl RootRouter {
    pub fn build_routes_with_state(state: Arc<AppState>) -> Router {
        let cors = build_cors();
        let auth = AuthLayer::new(&state);

        let acc_routes = build_account_routes();

        Router::new()
            .route("/", get(root_handler))
            .route("/health-check", get(health_check_handler))
            .nest("/accounts", acc_routes)
            .layer(cors)
            .layer(auth)
            .layer(Extension(state))
    }
}
