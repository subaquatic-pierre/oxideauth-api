use axum::async_trait;
use redis::Client;
use serde::{Deserialize, Serialize};

use crate::cache::{error::CacheResult, traits::CacheExecutor};

pub struct RedisChx {
    client: Client,
}

impl RedisChx {
    pub fn new() -> Self {
        todo!()
    }
}

#[async_trait]
impl CacheExecutor for RedisChx {
    fn get<T>(key: &str) -> CacheResult<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        Ok(None)
    }

    fn set<T>(key: &str, val: &T, ttl: Option<usize>) -> CacheResult<()> {
        Ok(())
    }

    // Removes a key from the cache.
    async fn del(&self, key: &str) -> CacheResult<()> {
        Ok(())
    }
}
