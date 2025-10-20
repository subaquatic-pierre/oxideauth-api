use async_trait::async_trait;
use sqlx::{
    query::{Query, QueryAs},
    Execute, FromRow, IntoArguments, Postgres, Transaction,
};
use std::{
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{oneshot, Mutex},
    task::JoinHandle,
    time::{interval, sleep, MissedTickBehavior},
};
use tracing::{debug, error};

use crate::store::{
    error::{StoreError, StoreResult},
    init::PgPool,
};

/// PgDbx is a thin wrapper over a sqlx Pool that can (optionally) route all queries
/// through a shared transaction. It also supports *nested* transactions via a
/// simple ref-count on a single physical transaction.
pub struct PgDbx {
    /// Underlying sqlx connection pool.
    db_pool: PgPool,
}

impl PgDbx {
    /// Create a new PgDbx from a pool.
    pub fn new(db: PgPool) -> Self {
        Self { db_pool: db }
    }

    /// Borrow the underlying pool (used when no transaction is active).
    pub fn pool(&self) -> &PgPool {
        &self.db_pool
    }

    /// Borrow the underlying pool (used when no transaction is active).
    pub async fn begin(&self) -> StoreResult<Transaction<'static, Postgres>> {
        Ok(self.db_pool.begin().await?)
    }

    // --- Query Execution methods

    /// Execute a `query_as` and fetch exactly one row.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    pub async fn fetch_one<'q, O, A>(&self, query: QueryAs<'q, Postgres, O, A>) -> StoreResult<O>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        let data = query.fetch_one(self.pool()).await?;

        Ok(data)
    }

    /// Execute a `query_as` and fetch an optional row.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    pub async fn fetch_optional<'q, O, A>(
        &self,
        query: QueryAs<'q, Postgres, O, A>,
    ) -> StoreResult<Option<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        let data = query.fetch_optional(self.pool()).await?;

        Ok(data)
    }

    /// Execute a `query_as` and fetch all rows.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    pub async fn fetch_all<'q, O, A>(
        &self,
        query: QueryAs<'q, Postgres, O, A>,
    ) -> StoreResult<Vec<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        // No need to debug here, sqlx::query logs debug info
        // debug!("--- QUERY --- : SQL: {}", query.sql());
        let data = query.fetch_all(self.pool()).await?;

        Ok(data)
    }

    /// Execute a `query` (no mapping) and return rows affected.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    pub async fn execute<'q, A>(&self, query: Query<'q, Postgres, A>) -> StoreResult<u64>
    where
        A: IntoArguments<'q, Postgres> + 'q,
    {
        let rows_affected = query.execute(self.pool()).await?.rows_affected();

        Ok(rows_affected)
    }
}
#[async_trait]
impl DbExecutor for PgDbx {
    async fn begin(&self) -> StoreResult<Transaction<'static, Postgres>> {
        self.begin().await
    }

    async fn fetch_one<'q, O, A>(&self, query: QueryAs<'q, Postgres, O, A>) -> StoreResult<O>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        self.fetch_one(query).await
    }

    async fn fetch_optional<'q, O, A>(
        &self,
        query: QueryAs<'q, Postgres, O, A>,
    ) -> StoreResult<Option<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        self.fetch_optional(query).await
    }

    async fn fetch_all<'q, O, A>(&self, query: QueryAs<'q, Postgres, O, A>) -> StoreResult<Vec<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        self.fetch_all(query).await
    }

    async fn execute<'q, A>(&self, query: Query<'q, Postgres, A>) -> StoreResult<u64>
    where
        A: IntoArguments<'q, Postgres> + 'q,
    {
        self.execute(query).await
    }
}

#[async_trait]
pub trait DbExecutor: Send + Sync + Unpin {
    /// Borrow the underlying pool (used when no transaction is active).
    async fn begin(&self) -> StoreResult<Transaction<'static, Postgres>>;

    // --- Query Execution methods

    /// Execute a `query_as` and fetch exactly one row.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    async fn fetch_one<'q, O, A>(&self, query: QueryAs<'q, Postgres, O, A>) -> StoreResult<O>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q;

    /// Execute a `query_as` and fetch an optional row.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    async fn fetch_optional<'q, O, A>(
        &self,
        query: QueryAs<'q, Postgres, O, A>,
    ) -> StoreResult<Option<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q;

    /// Execute a `query_as` and fetch all rows.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    async fn fetch_all<'q, O, A>(&self, query: QueryAs<'q, Postgres, O, A>) -> StoreResult<Vec<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q;

    /// Execute a `query` (no mapping) and return rows affected.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    async fn execute<'q, A>(&self, query: Query<'q, Postgres, A>) -> StoreResult<u64>
    where
        A: IntoArguments<'q, Postgres> + 'q;
}
#[async_trait]
impl<T: DbExecutor> DbExecutor for Arc<T> {
    async fn begin(&self) -> StoreResult<Transaction<'static, Postgres>> {
        self.as_ref().begin().await
    }

    async fn fetch_one<'q, O, A>(&self, query: QueryAs<'q, Postgres, O, A>) -> StoreResult<O>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        self.as_ref().fetch_one(query).await
    }

    async fn fetch_optional<'q, O, A>(
        &self,
        query: QueryAs<'q, Postgres, O, A>,
    ) -> StoreResult<Option<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        self.as_ref().fetch_optional(query).await
    }

    async fn fetch_all<'q, O, A>(&self, query: QueryAs<'q, Postgres, O, A>) -> StoreResult<Vec<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        self.as_ref().fetch_all(query).await
    }

    async fn execute<'q, A>(&self, query: Query<'q, Postgres, A>) -> StoreResult<u64>
    where
        A: IntoArguments<'q, Postgres> + 'q,
    {
        self.as_ref().execute(query).await
    }
}
