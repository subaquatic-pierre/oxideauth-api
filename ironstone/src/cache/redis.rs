use axum::async_trait;
use redis::{
    aio::{ConnectionManager, ConnectionManagerConfig},
    AsyncCommands, Client, Commands, FromRedisValue, ToRedisArgs,
};
use serde::{Deserialize, Serialize};

use crate::cache::{
    error::{CacheError, CacheResult},
    traits::CacheExecutor,
};

pub struct RedisChx {
    client: Client,
}

impl RedisChx {
    /// Creates a new RedisCacheExecutor. Takes a Redis connection string.
    pub fn new(redis_url: &str) -> Self {
        let client = Client::open(redis_url).expect("unable to create Redis Client");

        Self { client }
    }
}

impl CacheExecutor for RedisChx {
    /// Retrieves a value from Redis and deserializes it from JSON.
    async fn get<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: FromRedisValue,
    {
        // Get an asynchronous connection from the client
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let cached_value: Option<T> = conn.get(key).await?;
        Ok(cached_value)
    }

    /// Serializes the value to JSON and stores it in Redis.
    async fn set<T>(&self, key: &str, value: &T, ttl_seconds: Option<u64>) -> CacheResult<()>
    where
        T: ToRedisArgs + Send + Sync,
    {
        // Get an asynchronous connection from the client
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        match ttl_seconds {
            // Set with expiration (SETEX command)
            Some(ttl) => conn.set_ex::<_, _, ()>(key, value, ttl).await?,

            // Set without expiration (SET command)
            None => conn.set(key, value).await?,
        };

        Ok(())
    }

    /// Deletes a key from Redis.
    async fn del(&self, key: &str) -> CacheResult<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        conn.del::<_, ()>(key).await?;

        Ok(())
    }
}
