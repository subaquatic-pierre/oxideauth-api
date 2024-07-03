use std::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display},
};

use actix_web::{body::BoxBody, error::ResponseError, web::Json, HttpResponse, Responder};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    pub message: String,
}

impl ApiError {
    pub fn new(msg: &str) -> Self {
        Self {
            message: msg.to_string(),
        }
    }
}

impl Error for ApiError {}

impl Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

// impl ResponseError for ApiError {
//     fn error_response(&self) -> actix_web::HttpResponse {
//         return HttpResponse::ExpectationFailed()
//             .json(json!({"status":"error","message": self.message}));
//     }
// }

impl Responder for ApiError {
    type Body = BoxBody;
    fn respond_to(self, _req: &actix_web::HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::ExpectationFailed().json(json!({"status":"error","message": self.message}))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// pub struct ApiResult<T>(Result<T, ApiError>);

// impl<T> Responder for ApiResult<T> {
//     type Body = BoxBody;
//     fn respond_to(self, _req: &actix_web::HttpRequest) -> HttpResponse<Self::Body> {
//         match self.0 {
//             Ok(t) => HttpResponse::ExpectationFailed().json(json!({"status":"error"})),
//             Err(e) => HttpResponse::ExpectationFailed()
//                 .json(json!({"status":"error","message": e.message})),
//         }
//     }
// }
