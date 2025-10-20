use async_trait::async_trait;
use serde_json::Value as JsonValue;

use crate::store::ctx::StoreCtx;
use crate::store::error::StoreResult;
use crate::store::queries::contains::filter_by_value_contains;
use crate::store::queries::meta::ContainsFilter;
use crate::store::traits::meta::{ContainsFilterStore, Store};

/// Trait for filtering records where a JSONB column contains certain values.
pub trait FilterByContains: ContainsFilterStore {
    /// Finds all records where the designated tags column (a JSONB array)
    /// contains all of the specified tags.
    async fn filter_by_tags_contain(
        &self,
        ctx: &StoreCtx,
        tags: Vec<String>,
    ) -> StoreResult<Vec<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.contains_tags_meta();
        let value = ContainsFilter::Array(tags);
        filter_by_value_contains(ctx, &dbx, value, &meta).await
    }

    /// Finds all records where the designated JSONB column contains the
    /// key/value pairs specified in the json filter object.
    async fn filter_by_json_contains(
        &self,
        ctx: &StoreCtx,
        json: JsonValue,
    ) -> StoreResult<Vec<Self::Row>> {
        let dbx = self.dbx();
        let meta = self.contains_json_meta();
        let value = ContainsFilter::Json(json);
        filter_by_value_contains(ctx, &dbx, value, &meta).await
    }
}
