use std::sync::Arc;

use tower::{
    layer::util::{Identity, Stack},
    Service, ServiceBuilder,
};
use tower_http::cors::CorsLayer;

use crate::{
    app::AppData,
    core::services::{authenticate::AuthenticateService, authorize::AuthorizeService},
    store::dbx::PgDbx,
    web::middlewares::{auth::AuthLayer, cors::build_cors},
};

pub fn build_app_middlewares(
    auth_service: Arc<AuthenticateService<PgDbx>>,
) -> ServiceBuilder<Stack<CorsLayer, Stack<AuthLayer, Identity>>> {
    let auth = AuthLayer::new(auth_service);
    let cors = build_cors();
    let mw = ServiceBuilder::new().layer(auth).layer(cors);
    mw
}
