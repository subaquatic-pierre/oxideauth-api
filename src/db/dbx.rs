use log::error;
use sqlx::{
    query::{Query, QueryAs},
    FromRow, IntoArguments, Postgres, Transaction,
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

use crate::db::{
    error::{Error, Result},
    init::DbPool,
};

/// Dbx is a thin wrapper over a sqlx Pool that can (optionally) route all queries
/// through a shared transaction. It also supports *nested* transactions via a
/// simple ref-count on a single physical transaction.
pub struct Dbx {
    /// Underlying sqlx connection pool.
    db_pool: DbPool,
    /// Shared slot holding the current open transaction and a nesting counter.
    /// - Arc: Dbx is Clone and can be passed around freely.
    /// - Mutex: coordinates concurrent access to the single transaction slot.
    /// - Option: None means no active transaction.
    txn_holder: Arc<Mutex<Option<TxnHolder>>>,
    /// Whether this Dbx instance is allowed to manage transactions.
    /// (Useful to create a read-only Dbx or a non-transactional ModelManager.)
    with_txn: bool,

    idle_timeout: Duration,
    force_rollback: bool,
}

impl Dbx {
    /// Create a new Dbx from a pool.
    /// `with_txn=false` means `begin_txn/commit_txn` will error if called.
    pub fn new(db: DbPool, with_txn: bool) -> Self {
        Self {
            db_pool: db,
            txn_holder: Arc::default(),
            with_txn,
            idle_timeout: Duration::from_secs(30),
            force_rollback: false,
        }
    }

    /// Borrow the underlying pool (used when no transaction is active).
    pub fn db(&self) -> &DbPool {
        &self.db_pool
    }

    // --- Transaction Methods

    /// Begin (or nest into) a transaction and return an RAII `TxnGuard` for this level.
    ///
    /// Behavior:
    /// - If a transaction is already active, this increments the nesting `counter`.
    /// - Otherwise, it starts a new sqlx transaction, stores it in `txn_holder`,
    ///   and spawns the idle-timeout watchdog.
    /// - The returned `TxnGuard` will, on drop, decrement one level; if that
    ///   brings the counter to 0 **and nothing committed**, it will roll back
    ///   the physical transaction (subject to `force_rollback` policy).
    ///
    /// Tip: Mark `TxnGuard` with `#[must_use]` (already done) and consider
    /// `#![deny(unused_must_use)]` to make ignoring it a compile error.
    pub async fn begin_txn(&self) -> Result<TxnGuard> {
        if !self.with_txn {
            return Err(Error::CantBeginTxnWithTxnFalse);
        }

        let mut txh_g = self.txn_holder.lock().await;

        if let Some(txh) = txh_g.as_mut() {
            // Already have a transaction: increase nesting level
            txh.inc();
        } else {
            // No active transaction: start one and attach idle watchdog
            let txn = self.db_pool.begin().await?;
            let mut holder = TxnHolder::new(txn, self.idle_timeout, self.force_rollback);
            holder.spawn_idle_watchdog(self.txn_holder.clone());
            let _ = txh_g.insert(holder);
        }

        // Return a guard bound to the same holder; if the caller forgets to commit,
        // dropping this guard will consume one level and (if it reaches 0) rollback.
        Ok(TxnGuard::new(self.txn_holder.clone(), self.force_rollback))
    }

    /// Roll back ONE nesting level.
    /// - If `counter > 1`, just decrement and keep txn open.
    /// - If `counter == 1`, actually roll back the physical txn and clear the holder.
    pub async fn rollback_txn(&self) -> Result<()> {
        let mut txh_g = self.txn_holder.lock().await;

        if let Some(mut txh) = txh_g.take() {
            if txh.counter > 1 {
                txh.dec();
                let _ = txh_g.replace(txh);
            } else {
                // stop watchdog, then rollback
                // txh.cancel_watchdog();
                let mut txn = txh.txn;
                drop(txh_g);
                txn.rollback().await?;
            }
            Ok(())
        } else {
            Err(Error::NoTxn)
        }
    }

    /// Commit ONE nesting level.
    /// - Decrements the counter; if it reaches 0, commits the physical txn and clears the holder.
    pub async fn commit_txn(&self) -> Result<()> {
        if !self.with_txn {
            return Err(Error::CantCommitTxtWithTxnFalse);
        }

        let mut txh_g = self.txn_holder.lock().await;
        if let Some(txh) = txh_g.as_mut() {
            txh.dec();
            // empty TxnHolder if count is 0
            if txh.counter == 0 {
                if let Some(txh) = txh_g.take() {
                    // stop watchdog, then commit
                    // txh.cancel_watchdog();
                    let mut txn = txh.txn;
                    drop(txh_g);
                    txn.commit().await?;
                }
            }
            Ok(())
        } else {
            Err(Error::TxnCantCommitNoOpenTxn)
        }
    }

    // --- Query Execution methods

    /// Execute a `query_as` and fetch exactly one row.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    pub async fn fetch_one<'q, O, A>(&self, query: QueryAs<'q, Postgres, O, A>) -> Result<O>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        let data = if self.with_txn {
            let mut txn_g = self.txn_holder.lock().await;
            if let Some(txn) = txn_g.as_deref_mut() {
                query.fetch_one(txn.as_mut()).await?
            } else {
                query.fetch_one(self.db()).await?
            }
        } else {
            query.fetch_one(self.db()).await?
        };

        Ok(data)
    }

    /// Execute a `query_as` and fetch an optional row.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    pub async fn fetch_optional<'q, O, A>(
        &self,
        query: QueryAs<'q, Postgres, O, A>,
    ) -> Result<Option<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        let data = if self.with_txn {
            let mut txn_g = self.txn_holder.lock().await;
            if let Some(txn) = txn_g.as_deref_mut() {
                query.fetch_optional(txn.as_mut()).await?
            } else {
                query.fetch_optional(self.db()).await?
            }
        } else {
            query.fetch_optional(self.db()).await?
        };

        Ok(data)
    }

    /// Execute a `query_as` and fetch all rows.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    pub async fn fetch_all<'q, O, A>(&self, query: QueryAs<'q, Postgres, O, A>) -> Result<Vec<O>>
    where
        O: for<'r> FromRow<'r, <Postgres as sqlx::Database>::Row> + Send + Unpin,
        A: IntoArguments<'q, Postgres> + 'q,
    {
        let data = if self.with_txn {
            let mut txn_g = self.txn_holder.lock().await;
            if let Some(txn) = txn_g.as_deref_mut() {
                query.fetch_all(txn.as_mut()).await?
            } else {
                query.fetch_all(self.db()).await?
            }
        } else {
            query.fetch_all(self.db()).await?
        };

        Ok(data)
    }

    /// Execute a `query` (no mapping) and return rows affected.
    /// If a transaction is active, runs against it; otherwise uses the pool.
    pub async fn execute<'q, A>(&self, query: Query<'q, Postgres, A>) -> Result<u64>
    where
        A: IntoArguments<'q, Postgres> + 'q,
    {
        let rows_affected = if self.with_txn {
            let mut txn_g = self.txn_holder.lock().await;
            if let Some(txn) = txn_g.as_deref_mut() {
                query.execute(txn.as_mut()).await?.rows_affected()
            } else {
                query.execute(self.db()).await?.rows_affected()
            }
        } else {
            query.execute(self.db()).await?.rows_affected()
        };

        Ok(rows_affected)
    }
}

/// Holds a single physical sqlx `Transaction` plus a nesting `counter`.
/// `counter` == total number of logical `begin_txn` levels currently open.
#[derive(Debug)]
pub struct TxnHolder {
    txn: Transaction<'static, Postgres>,
    counter: i32,

    // --- idle-timeout metadata
    pub created_at: Instant,
    pub last_touch: Instant,
    pub idle_timeout: Duration, // e.g. 30s of *inactivity*
    pub force_rollback: bool,   // false = soft (log only), true = hard (rollback)

    // watchdog control
    cancel_flag: Arc<AtomicBool>,
    watchdog: Option<JoinHandle<()>>,
}

impl TxnHolder {
    /// New holder starts at counter=1 (first begin).
    pub fn new(
        txn: Transaction<'static, Postgres>,
        idle_timeout: Duration,
        force_rollback: bool,
    ) -> Self {
        Self {
            txn,
            counter: 1,
            created_at: Instant::now(),
            last_touch: Instant::now(),
            idle_timeout,
            force_rollback,
            cancel_flag: Arc::new(AtomicBool::new(false)),
            watchdog: None,
        }
    }

    /// Increment nesting counter (new logical begin).
    pub fn inc(&mut self) {
        self.counter += 1;
        self.last_touch = Instant::now();
    }

    /// Decrement nesting counter, returning the new value.
    /// When it reaches 0, the *outermost* layer has been consumed.
    pub fn dec(&mut self) -> i32 {
        self.counter -= 1;
        self.last_touch = Instant::now();
        self.counter
    }

    /// Start an idle-timeout watchdog that wakes up periodically and checks
    /// Start an idle-timeout watchdog that wakes up every `tick` and checks inactivity.
    pub fn spawn_idle_watchdog(&mut self, holder_arc: Arc<Mutex<Option<TxnHolder>>>) {
        if self.watchdog.is_some() {
            return;
        }

        let cancel = self.cancel_flag.clone();
        let hard = self.force_rollback;
        let idle_limit = self.idle_timeout;
        let tick = Duration::from_secs(1);

        self.watchdog = Some(tokio::spawn(async move {
            loop {
                // stop requested?
                if cancel.load(Ordering::Relaxed) {
                    break;
                }

                // check holder state
                let mut guard = holder_arc.lock().await;
                match guard.take() {
                    Some(mut txh) => {
                        let idle_for = Instant::now().saturating_duration_since(txh.last_touch);

                        if idle_for > idle_limit {
                            if hard {
                                error!(
                                    "TX idle watchdog: idle {:?} exceeded {:?}; force-rollback",
                                    idle_for, idle_limit
                                );
                                let mut txn = txh.txn;
                                drop(guard);
                                let _ = txn.rollback().await;
                                break; // finished
                            } else {
                                error!(
                                    "TX idle watchdog: idle {:?} exceeded {:?}; txn still open (counter = {})",
                                    idle_for, idle_limit, txh.counter
                                );
                                // Put it back, keep running
                                let _ = holder_arc.lock().await.insert(txh);
                            }
                        } else {
                            // Not idle enough yet — put back
                            let _ = guard.insert(txh);
                        }
                    }
                    None => {
                        // No active transaction anymore — done
                        break;
                    }
                }

                // sleep until next tick
                sleep(tick).await;
            }
        }));
    }

    /// Signal the watchdog to stop. Call when counter will reach 0.
    pub fn cancel_watchdog(&mut self) {
        self.cancel_flag.store(true, Ordering::Relaxed);
        // We can optionally `abort` the task after setting the flag if you want it to stop immediately:
        if let Some(handle) = self.watchdog.take() {
            // Let it finish gracefully on next tick; or uncomment to force-stop:
            // handle.abort();
            let _ = handle; // drop handle
        }
    }
}

/// Allow treating `&TxnHolder` as `&Transaction` for convenience.
impl Deref for TxnHolder {
    type Target = Transaction<'static, Postgres>;

    fn deref(&self) -> &Self::Target {
        &self.txn
    }
}

/// Allow treating `&mut TxnHolder` as `&mut Transaction` for convenience.
impl DerefMut for TxnHolder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.txn
    }
}

// --- The guard representing ONE begin() level ---

/// RAII guard for **one** logical `begin_txn` level.
/// If dropped without a matching `commit_txn`/`rollback_txn`, it will:
///   - decrement the nesting counter, and
///   - if it reaches 0, ROLLBACK the physical transaction and clear the holder.
///
/// Marked `#[must_use]` so ignoring it (not binding to a variable) warns.
/// You can upgrade the warning to an error with `#![deny(unused_must_use)]`.
#[derive(Debug)]
#[must_use = "TxnGuard must be held until commit/rollback"]
pub struct TxnGuard {
    /// Shared access to the same holder used by Dbx.
    txn_holder: Arc<Mutex<Option<TxnHolder>>>,
    force_rollback: bool,
}

impl TxnGuard {
    /// Construct a guard from an existing holder.
    /// Typically you’ll want Dbx::begin_txn() to *return* this.
    fn new(txn_holder: Arc<Mutex<Option<TxnHolder>>>, force_rollback: bool) -> Self {
        Self {
            txn_holder,
            force_rollback,
        }
    }
}

impl Drop for TxnGuard {
    fn drop(&mut self) {
        // If still open, consume ONE level. If that reaches 0, rollback.
        let txn_holder = self.txn_holder.clone();
        let force_rollback = self.force_rollback;

        tokio::spawn(async move {
            let mut txh_g = txn_holder.lock().await;
            if let Some(mut txh) = txh_g.take() {
                let new_counter = txh.dec();
                if new_counter > 0 {
                    // still nested -> put it back
                    let _ = txh_g.insert(txh);
                } else {
                    error!("TxnGuard dropped without commit -> performing rollback");
                    if force_rollback {
                        // last uncommitted level: stop watchdog, then rollback
                        // txh.cancel_watchdog();
                        // we were the last uncommitted level -> rollback & clear
                        let mut txn = txh.txn;
                        drop(txh_g);
                        let _ = txn.rollback().await;
                    }
                }
            }
            // else: already committed/rolled back -> nothing to do
        });
    }
}
