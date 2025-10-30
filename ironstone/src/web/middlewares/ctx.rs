use axum::{
    body::Body,
    extract::{FromRequest, Request},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::Response,
    RequestExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::{app::AppState, core::services::ctx::CtxService};
use crate::{
    core::services::token::TokenService,
    store::dbx::{DbExecutor, PgDbx},
}; // Use Axum's body type

#[derive(Clone)]
pub struct CtxLayer {
    ctx_svc: Arc<CtxService<PgDbx>>,
}

impl CtxLayer {
    pub fn new(app_state: &Arc<AppState>) -> Self {
        let ctx_svc = Arc::new(CtxService::new(app_state.sm.clone()));
        Self { ctx_svc }
    }
}

impl<S> Layer<S> for CtxLayer {
    type Service = CtxMw<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CtxMw {
            inner,
            ctx_svc: self.ctx_svc.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CtxMw<S> {
    inner: S,
    ctx_svc: Arc<CtxService<PgDbx>>,
}

impl<S> Service<Request<Body>> for CtxMw<S>
where
    S: Service<Request, Response = Response> + Send + 'static + Clone,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        // Clone the state so we can move it into the async block
        let ctx_svc = self.ctx_svc.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract the Authorization header
            let token = TokenService::token_from_req(&req);

            // Call your auth service
            match ctx_svc.resolve_ctx(token).await {
                Ok(ctx) => {
                    req.extensions_mut().insert(ctx);

                    inner.call(req).await
                }
                Err(_) => {
                    // FAILED! Token is invalid. Return 401.
                    let res = Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::from("Invalid token"))
                        .unwrap();
                    Ok(res)
                }
            }
        })
    }
}
