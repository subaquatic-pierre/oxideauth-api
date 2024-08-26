use std::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display},
};

use actix_web::{
    body::BoxBody, error::ResponseError, http::StatusCode, web::Json, HttpResponse, Responder,
};
use serde_json::json;

#[derive(Debug, PartialEq)]
pub struct ApiError {
    pub message: String,
    pub status: StatusCode,
}

impl ApiError {
    pub fn new(msg: &str, status: u16) -> Self {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
        Self {
            message: msg.to_string(),
            status,
        }
    }

    pub fn new_400(msg: &str) -> Self {
        let status = StatusCode::from_u16(400).unwrap_or(StatusCode::BAD_REQUEST);
        Self {
            message: msg.to_string(),
            status,
        }
    }

    pub fn new_500(msg: &str) -> Self {
        let status = StatusCode::from_u16(500).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Self {
            message: msg.to_string(),
            status,
        }
    }
}

impl Default for ApiError {
    fn default() -> Self {
        Self::new("There was an error", 400)
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
        HttpResponse::build(self.status).json(json!({"status":"error","message": self.message}))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::dev::ServiceResponse;
    use actix_web::{test as actix_test, HttpRequest, HttpResponse};
    use serde_json::Value;

    #[test]
    fn test_api_error_creation() {
        let error = ApiError::new("Test error message", 404);
        assert_eq!(error.message, "Test error message");
        assert_eq!(error.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_api_error_new_400() {
        let error = ApiError::new_400("Bad request error");
        assert_eq!(error.message, "Bad request error");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_api_error_new_500() {
        let error = ApiError::new_500("Internal server error");
        assert_eq!(error.message, "Internal server error");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_api_error_default() {
        let error = ApiError::default();
        assert_eq!(error.message, "There was an error");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_api_error_display() {
        let error = ApiError::new("Display test", 400);
        assert_eq!(format!("{}", error), "Display test");
    }

    #[test]
    fn test_api_result() {
        let success: ApiResult<u32> = Ok(42);
        assert_eq!(success, Ok(42));

        let error: ApiResult<u32> = Err(ApiError::new("Test error", 500));
        assert!(error.is_err());
    }
}
