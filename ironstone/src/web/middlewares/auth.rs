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

use crate::store::dbx::{DbExecutor, PgDbx};
use crate::{app::AppState, core::services::authenticate::AuthenticateService}; // Use Axum's body type

#[derive(Clone)]
pub struct AuthLayer {
    auth_service: Arc<AuthenticateService<PgDbx>>,
}

impl AuthLayer {
    pub fn new(app_state: &Arc<AppState>) -> Self {
        let auth_service = Arc::new(AuthenticateService::new(app_state.sm.clone()));
        Self { auth_service }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            auth_service: self.auth_service.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    auth_service: Arc<AuthenticateService<PgDbx>>,
}

impl<S> Service<Request<Body>> for AuthMiddleware<S>
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

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Clone the state so we can move it into the async block
        let auth_service = self.auth_service.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract the Authorization header
            let headers = req.headers();
            let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());

            let token = match auth_header {
                Some(str) => {
                    let mut iter = str.split(" ").into_iter();

                    let start = iter.next();
                    let token = iter.next();
                    token
                }
                None => None,
            };

            // Call your auth service
            match auth_service.resolve_ctx(token).await {
                Ok(ctx) => {
                    req.extensions_mut().insert(ctx);

                    // 2. Pass the request to the inner service (the RPC handler)
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
