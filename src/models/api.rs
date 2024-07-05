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

impl Responder for ApiError {
    type Body = BoxBody;
    fn respond_to(self, _req: &actix_web::HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::ExpectationFailed().json(json!({"status":"error","message": self.message}))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub trait ApiModel {
    fn save<T>(&self) -> ApiResult<T>;
}