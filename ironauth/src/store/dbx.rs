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
    init::DbPool,
};

/// Dbx is a thin wrapper over a sqlx Pool that can (optionally) route all queries
/// through a shared transaction. It also supports *nested* transactions via a
/// simple ref-count on a single physical transaction.
pub struct Dbx {
    /// Underlying sqlx connection pool.
    db_pool: DbPool,
}

impl Dbx {
    /// Create a new Dbx from a pool.
    pub fn new(db: DbPool) -> Self {
        Self { db_pool: db }
    }

    /// Borrow the underlying pool (used when no transaction is active).
    pub fn db(&self) -> &DbPool {
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
        let data = query.fetch_one(self.db()).await?;

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
        let data = query.fetch_optional(self.db()).await?;

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
        let data = query.fetch_all(self.db()).await?;

        Ok(data)
    }

    /// Execute a `query` (no mapping) and return rows affected.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    pub async fn execute<'q, A>(&self, query: Query<'q, Postgres, A>) -> StoreResult<u64>
    where
        A: IntoArguments<'q, Postgres> + 'q,
    {
        let rows_affected = query.execute(self.db()).await?.rows_affected();

        Ok(rows_affected)
    }
}
