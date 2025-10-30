use axum::body::Body;
use axum::extract::FromRequest;
use axum_extra::headers::{authorization::Bearer, Authorization};
use axum_extra::TypedHeader;
use http::HeaderMap;
use http::{Request, Response, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::core::services::authenticate::AuthenticateService;
use crate::store::dbx::{DbExecutor, PgDbx}; // Use Axum's body type

#[derive(Clone)]
pub struct AuthLayer {
    auth_service: Arc<AuthenticateService<PgDbx>>,
}

impl AuthLayer {
    pub fn new(auth_service: Arc<AuthenticateService<PgDbx>>) -> Self {
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
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
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
            let auth_header: Option<TypedHeader<Authorization<Bearer>>> =
                TypedHeader::from_request(req);

            let token = match auth_header {
                Some(TypedHeader(Authorization(bearer))) => bearer.token().to_string(),
                None => {
                    // No token provided. Return 401.
                    let res = Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::from("Missing credentials"))
                        .unwrap();
                    return Ok(res);
                }
            };

            // Call your auth service
            match auth_service.resolve_ctx(&token).await {
                Ok(ctx) => {
                    // SUCCESS!
                    // 1. (Optional) Inject user info into the request
                    //    so the RPC handler can access it.
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
