use axum::{
    error_handling::HandleErrorLayer,
    extract::Extension,
    middleware::{from_fn, map_response},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;

use crate::{
    app::App,
    core::ctx::CoreCtx,
    web::{
        handlers::{account::AccountRouter, root::RootRouter, workspace::WorkspaceRouter},
        middlewares::{
            cors::build_cors,
            ctx::{CtxLayer, CtxMw},
            fallback::FallbackMw,
            request::RequestMw,
            response::ResponseMw,
        },
    },
};

pub struct AppRouter;

impl AppRouter {
    pub fn routes_with_state(state: App) -> Router {
        let cors = build_cors();
        let ctx = CtxLayer::new(&state);

        let global_error_layer = ServiceBuilder::new()
            .layer(HandleErrorLayer::new(FallbackMw::global_error_handler))
            .timeout(Duration::from_secs(30));

        Router::new()
            // Define main routes
            .nest("/", RootRouter::routes())
            .nest("/account", AccountRouter::routes())
            .nest("/workspace", WorkspaceRouter::routes())
            // Define middleware
            .layer(global_error_layer)
            .layer(map_response(ResponseMw::response_map_handler))
            .layer(cors)
            .layer(ctx)
            .layer(Extension(state))
            .layer(from_fn(RequestMw::request_map_handler))
            .fallback(FallbackMw::fallback_handler)
    }
}
