use axum::extract::rejection::{FormRejection, JsonRejection, QueryRejection};
use axum::{
    // HTTP status codes and routing setup
    http::StatusCode,
    // Core response traits and JSON extractor
    response::{IntoResponse, Response},
    routing::get,
    Json,
    Router,
};
use derive_more::Display;
use serde::{Deserialize, Serialize};

use crate::{core::error::CoreError, web::response::WebResponse};

pub type WebResult<T> = Result<Json<T>, WebError>;

/// Defines specific, named errors that can occur in the application.
#[derive(Debug, Display, Clone)]
pub enum WebError {
    /// 404 Not Found error.
    NotFound,
    /// 500 Internal Server Error (use for unexpected failures).
    InternalServerError,
    /// 400 Bad Request error with a custom message.
    ValidationError(String),
    /// 401 Unauthorized error.
    Unauthorized,
    ReqStampNotInReqExt,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    /// Indicates if the request was successful (always false for error responses).
    pub success: bool,
    /// The HTTP status code associated with the error.
    pub status: u16,
    /// A human-readable message describing the error.
    pub message: String,
}

/// Implementation of the IntoResponse trait for WebError.
/// This allows us to return `Err(WebError::...)` directly from a handler.
impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let (status_code, error_message) = match self {
            WebError::NotFound => (
                StatusCode::NOT_FOUND,
                "The requested resource was not found.".to_string(),
            ),
            WebError::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An unexpected server error occurred.".to_string(),
            ),
            WebError::ValidationError(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Validation failed: {}", msg),
            ),
            WebError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Authentication required or invalid credentials.".to_string(),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An unexpected server error occurred.".to_string(),
            ),
        };

        // Create the standardized error body
        let body = ErrorBody {
            success: false,
            status: status_code.as_u16(),
            message: error_message,
        };

        // Return the final response, combining the HTTP status code and the JSON error body
        (status_code, Json(body)).into_response()
    }
}

impl From<CoreError> for WebError {
    fn from(value: CoreError) -> Self {
        match value {
            CoreError::ParseError(..) => WebError::InternalServerError,
            _ => WebError::NotFound,
        }
    }
}

impl From<JsonRejection> for WebError {
    fn from(rej: JsonRejection) -> Self {
        match rej {
            JsonRejection::JsonSyntaxError(_) => {
                WebError::ValidationError("Malformed JSON syntax.".into())
            }
            JsonRejection::JsonDataError(_) => {
                WebError::ValidationError("Invalid JSON structure.".into())
            }
            JsonRejection::MissingJsonContentType(_) => {
                WebError::ValidationError("Missing Content-Type: application/json.".into())
            }
            _ => WebError::InternalServerError,
        }
    }
}

impl From<FormRejection> for WebError {
    fn from(rej: FormRejection) -> Self {
        match rej {
            FormRejection::InvalidFormContentType(_) => {
                WebError::ValidationError("Malformed JSON syntax.".into())
            }
            FormRejection::FailedToDeserializeForm(_) => {
                WebError::ValidationError("Invalid JSON structure.".into())
            }
            _ => WebError::InternalServerError,
        }
    }
}

impl From<QueryRejection> for WebError {
    fn from(rej: QueryRejection) -> Self {
        match rej {
            QueryRejection::FailedToDeserializeQueryString(_) => {
                WebError::ValidationError("Malformed JSON syntax.".into())
            }
            _ => WebError::InternalServerError,
        }
    }
}

impl std::error::Error for WebError {}
