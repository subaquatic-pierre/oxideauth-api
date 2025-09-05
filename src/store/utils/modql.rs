use sea_query::Value;
use serde::Serialize;
use serde_json::to_value;
use std::fmt::Debug;
use time::serde::rfc3339;

pub fn time_to_sea_value(
    json_value: serde_json::Value,
) -> modql::filter::SeaResult<sea_query::Value> {
    Ok(rfc3339::deserialize(json_value)?.into())
}

pub fn json_to_sea_value<T: Serialize + Default + Debug>(v: &T) -> Value {
    match serde_json::to_value(v) {
        Ok(v) => v.into(),
        Err(e) => {
            tracing::error!(
                ?e,
                "failed to serialize meta {v:?}; falling back to T::default()"
            );
            serde_json::to_value(T::default()).unwrap().into()
        }
    }
}
