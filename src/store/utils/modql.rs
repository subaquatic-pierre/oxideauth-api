use modql::filter::SeaResult;
use sea_query::Value as SeaValue;
use serde::Serialize;
use serde_json::{to_value, Value as JsonValue};
use std::fmt::Debug;
use time::serde::rfc3339;

pub fn time_to_sea_value(json_value: JsonValue) -> SeaResult<SeaValue> {
    Ok(rfc3339::deserialize(json_value)?.into())
}

pub fn json_to_sea_value(v: JsonValue) -> SeaResult<SeaValue> {
    match serde_json::to_value(v) {
        Ok(v) => Ok(SeaValue::Json(Some(Box::new(v)))),
        Err(e) => {
            tracing::error!(?e, "failed to serialize meta");
            Err(e.into())
        }
    }
}
