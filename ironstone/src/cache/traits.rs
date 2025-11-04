use axum::async_trait;
use serde::{Deserialize, Serialize};

use crate::cache::error::CacheResult;

#[async_trait]
pub trait CacheExecutor {
    fn get<T>(key: &str) -> CacheResult<Option<T>>
    where
        T: for<'de> Deserialize<'de>;

    fn set<T>(key: &str, val: &T, ttl: Option<usize>) -> CacheResult<()>;

    // Removes a key from the cache.
    async fn del(&self, key: &str) -> CacheResult<()>;
}
