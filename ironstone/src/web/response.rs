use axum::{
    // HTTP status codes and routing setup
    http::StatusCode,
    // Core response traits and JSON extractor
    response::{IntoResponse, Response},
    routing::get,
    Json,
    Router,
};
use serde::{Deserialize, Serialize};

use crate::web::error::WebResult;

#[derive(Debug, Serialize)]
pub struct WebResponse<T>
where
    T: Serialize,
{
    /// Indicates if the request was successful (always true for success responses).
    pub success: bool,
    /// The HTTP status code (redundant but useful for client debugging).
    pub status: u16,
    /// The actual data payload being returned.
    pub data: T,
}

impl<T: Serialize> WebResponse<T> {
    pub fn from_json(data: T) -> WebResult<Self> {
        let data = Self {
            success: true,
            status: StatusCode::OK.as_u16(),
            data,
        };

        Ok(Json(data))
    }
}
