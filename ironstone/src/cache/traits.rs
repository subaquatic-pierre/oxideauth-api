use std::sync::Arc;

use axum::async_trait;
use redis::{FromRedisValue, ToRedisArgs};
use serde::{Deserialize, Serialize};

use crate::cache::error::CacheResult;

#[async_trait]
pub trait CacheExecutor: Send + Sync {
    async fn get<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: FromRedisValue + Send + Sync;

    async fn set<T>(&self, key: &str, val: &T, ttl: Option<u64>) -> CacheResult<()>
    where
        T: ToRedisArgs + Send + Sync;

    // Removes a key from the cache.
    async fn del(&self, key: &str) -> CacheResult<()>;
}
