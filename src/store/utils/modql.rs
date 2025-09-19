use modql::filter::SeaResult;
use sea_query::Value as SeaValue;
use serde::Serialize;
use serde_json::{to_value, Value as JsonValue};
use std::fmt::Debug;
use time::{format_description::well_known::Rfc3339, serde::rfc3339, OffsetDateTime};

use crate::store::error::{Error, Result};

pub fn time_to_sea_value(json_value: JsonValue) -> SeaResult<SeaValue> {
    Ok(rfc3339::deserialize(json_value)?.into())
}

pub fn time_to_string(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap()
}

pub fn time_string_string(time: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(time, &Rfc3339).map_err(|e| Error::TimeError(e))
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
