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
use tracing::error;

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

    pub(crate) idle_timeout: Duration,
    pub(crate) force_rollback: bool,
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
            return Err(Error::WithTxnFalse);
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
            return Err(Error::WithTxnFalse);
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
            Err(Error::NoTxn)
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
    pub(crate) counter: i32,

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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serial_test::serial;
    use sqlx::{query, query_as};

    use crate::{
        db::stores::account::AccountRow,
        dev::{
            db::init_dev_db,
            init::{init_dev, init_test},
        },
    };

    use super::*;

    use uuid::Uuid;

    #[tokio::test]
    #[serial]
    async fn test_dbx_with_txn() {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), true);

        assert_eq!(dbx.with_txn, true);
    }

    #[tokio::test]
    #[serial]
    async fn test_begin_txn_fail() {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), false);

        let res = dbx.begin_txn().await;

        assert!(matches!(res, Err(Error::WithTxnFalse)));
    }

    #[tokio::test]
    #[serial]
    async fn test_begin_txn() {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), true);

        let txn_g = dbx.begin_txn().await.unwrap();

        let mut holder = txn_g.txn_holder.lock().await;

        if let Some(holder) = holder.take() {
            assert_eq!(holder.counter, 1)
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_rollback_fail() {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), true);

        let res = dbx.rollback_txn().await;

        assert!(matches!(res, Err(Error::NoTxn)))
    }

    #[tokio::test]
    #[serial]
    async fn test_commit_txn_fail() {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), true);

        let res = dbx.commit_txn().await;

        assert!(matches!(res, Err(Error::NoTxn)))
    }

    #[tokio::test]
    #[serial]
    async fn test_commit_txn() -> Result<()> {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), true);

        let _ = dbx.begin_txn().await?;

        let q = query_as::<_, AccountRow>("SELECT * FROM accounts");
        let fetch = dbx.fetch_all(q).await?;

        let q = query("DELETE FROM accounts WHERE name = $1").bind("TEST User");

        let affected_rows = dbx.execute(q).await?;

        assert_eq!(affected_rows, 1);

        let q = query_as::<_, AccountRow>("SELECT * FROM accounts");
        let fetch_again = dbx.fetch_all(q).await?;

        assert_ne!(fetch.len(), fetch_again.len());

        Ok(())
    }

    // --- fetch_one / fetch_optional without active txn ----------------------

    #[tokio::test]
    #[serial]
    async fn test_fetch_one_and_optional_no_txn() -> Result<()> {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), false);

        let email = format!("u+{}@example.com", Uuid::new_v4());
        let name = "FetchOne User";
        let id = insert_test_account_raw(&app.db, name, &email).await?;

        // fetch_one by email
        let q = query_as::<_, AccountRow>("SELECT * FROM accounts WHERE email = $1").bind(&email);
        let row = dbx.fetch_one(q).await?;
        assert_eq!(row.id, id);
        assert_eq!(row.email, email);

        // fetch_optional for a non-existent email
        let q_none = query_as::<_, AccountRow>("SELECT * FROM accounts WHERE email = $1")
            .bind("does-not-exist@example.com");
        let opt = dbx.fetch_optional(q_none).await?;
        assert!(opt.is_none());

        // cleanup
        let _ = query("DELETE FROM accounts WHERE id = $1")
            .bind(id)
            .execute(&app.db)
            .await?;
        Ok(())
    }

    // --- execute without txn (directly against pool) ------------------------

    #[tokio::test]
    #[serial]
    async fn test_execute_no_txn() -> Result<()> {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), false);

        let email = format!("u+{}@example.com", Uuid::new_v4());
        let name = "ExecNoTxn User";
        let id = insert_test_account_raw(&app.db, name, &email).await?;

        // delete using dbx.execute (no txn path)
        let q = query("DELETE FROM accounts WHERE id = $1").bind(id);
        let rows = dbx.execute(q).await?;
        assert_eq!(rows, 1);

        // ensure gone
        assert!(!account_exists(&Dbx::new(app.db.clone(), false), id).await?);
        Ok(())
    }

    // --- nested begin/commit flow -------------------------------------------

    #[tokio::test]
    #[serial]
    async fn test_nested_txn_commit_persists() -> Result<()> {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), true);

        // begin level 1
        let _g1 = dbx.begin_txn().await?;
        // begin level 2 (nested)
        let _g2 = dbx.begin_txn().await?;

        let email = format!("u+{}@example.com", Uuid::new_v4());
        let name = "NestedCommit User";
        let id = Uuid::new_v4();

        let q_ins = query(
            r#"
            INSERT INTO accounts
              (id, email, password_hash, name, acc_type, provider, verified, enabled)
            VALUES ($1, $2, 'hashed', $3, 'user', 'local', true, true)
            "#,
        )
        .bind(id)
        .bind(&email)
        .bind(name);

        let rows = dbx.execute(q_ins).await?;
        assert_eq!(rows, 1);

        // commit inner, then outer -> physical commit happens at outer
        dbx.commit_txn().await?;
        dbx.commit_txn().await?;

        // verify persisted outside any txn
        let exists = account_exists(&Dbx::new(app.db.clone(), false), id).await?;
        assert!(exists);

        // cleanup
        let _ = query("DELETE FROM accounts WHERE id = $1")
            .bind(id)
            .execute(&app.db)
            .await?;
        Ok(())
    }

    // --- nested rollback one level only decrements counter ------------------
    // NOTE: There is no SAVEPOINT logic; rolling back one level does NOT undo writes.

    #[tokio::test]
    #[serial]
    async fn test_nested_rollback_then_commit() -> Result<()> {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), true);

        let _g1 = dbx.begin_txn().await?;
        let _g2 = dbx.begin_txn().await?;

        let id = Uuid::new_v4();
        let email = format!("u+{}@example.com", Uuid::new_v4());

        let q_ins = query(
            "INSERT INTO accounts (id, email, password_hash, name, acc_type, provider, verified, enabled)
             VALUES ($1, $2, 'hashed', 'NestedRollback User', 'user', 'local', true, true)",
        )
        .bind(id)
        .bind(&email);

        dbx.execute(q_ins).await?;

        // Roll back ONE level (counter--), physical txn should remain open
        dbx.rollback_txn().await?;

        // Commit remaining outer level -> persists since no SAVEPOINT rollback exists
        dbx.commit_txn().await?;

        let exists = account_exists(&Dbx::new(app.db.clone(), false), id).await?;
        assert!(
            exists,
            "row should persist because partial rollback does not undo writes"
        );

        // cleanup
        let _ = query("DELETE FROM accounts WHERE id = $1")
            .bind(id)
            .execute(&app.db)
            .await?;
        Ok(())
    }

    // --- full rollback path (two levels -> rollback twice) ------------------

    #[tokio::test]
    #[serial]
    async fn test_full_rollback_discards() -> Result<()> {
        let app = init_test().await;
        let dbx = Dbx::new(app.db.clone(), true);

        let _g1 = dbx.begin_txn().await?;
        let _g2 = dbx.begin_txn().await?;

        let id = Uuid::new_v4();
        let email = format!("u+{}@example.com", Uuid::new_v4());

        let q_ins = query(
            "INSERT INTO accounts (id, email, password_hash, name, acc_type, provider, verified, enabled)
             VALUES ($1, $2, 'hashed', 'FullRollback User', 'user', 'local', true, true)",
        )
        .bind(id)
        .bind(&email);

        dbx.execute(q_ins).await?;

        // Roll back twice to close physical txn
        dbx.rollback_txn().await?;
        dbx.rollback_txn().await?;

        let exists = account_exists(&Dbx::new(app.db.clone(), false), id).await?;
        assert!(!exists, "row should be discarded after full rollback");
        Ok(())
    }

    // --- guard drop triggers rollback when force_rollback=true ---------------

    #[tokio::test]
    #[serial]
    async fn test_guard_drop_rollback_on_drop() -> Result<()> {
        let app = init_test().await;

        let mut dbx = Dbx::new(app.db.clone(), true);

        // tune watchdog for a fast test
        dbx.force_rollback = true;

        let id = Uuid::new_v4();
        let email = format!("u+{}@example.com", Uuid::new_v4());

        {
            let _g = dbx.begin_txn().await?;
            let q_ins = query(
                "INSERT INTO accounts (id, email, password_hash, name, acc_type, provider, verified, enabled)
                 VALUES ($1, $2, 'hashed', 'DropRollback User', 'user', 'local', true, true)",
            )
            .bind(id)
            .bind(&email);
            dbx.execute(q_ins).await?;
            // scope ends -> _g dropped -> rollback happens asynchronously
        }

        // Give the spawned drop task a moment to run
        tokio::time::sleep(Duration::from_millis(50)).await;

        let exists = account_exists(&Dbx::new(app.db.clone(), false), id).await?;
        assert!(
            !exists,
            "row should be rolled back when TxnGuard is dropped"
        );
        Ok(())
    }

    // --- idle watchdog rolls back after timeout when force_rollback=true -----

    #[tokio::test]
    #[serial]
    async fn test_idle_watchdog_force_rollback() -> Result<()> {
        let app = init_test().await;
        let mut dbx = Dbx::new(app.db.clone(), true);

        // tune watchdog for a fast test
        dbx.idle_timeout = Duration::from_millis(200);
        dbx.force_rollback = true;

        let id = Uuid::new_v4();
        let email = format!("u+{}@example.com", Uuid::new_v4());

        let _g = dbx.begin_txn().await?;
        let q_ins = query(
            "INSERT INTO accounts (id, email, password_hash, name, acc_type, provider, verified, enabled)
             VALUES ($1, $2, 'hashed', 'Watchdog User', 'user', 'local', true, true)",
        )
        .bind(id)
        .bind(&email);
        dbx.execute(q_ins).await?;

        // drop(_g);

        tokio::time::sleep(Duration::from_millis(2000)).await;

        // holder should be cleared by watchdog; commit should now fail with NoTxn
        let commit_res = dbx.commit_txn().await;
        assert!(matches!(commit_res, Err(Error::NoTxn)));

        let exists = account_exists(&dbx, id).await?;
        assert!(
            !exists,
            "row should be rolled back by idle watchdog with force_rollback"
        );
        Ok(())
    }

    // --- utils ---

    async fn insert_test_account_raw(db: &DbPool, name: &str, email: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        query(
            r#"
            INSERT INTO accounts
              (id, email, password_hash, name, acc_type, provider, verified, enabled)
            VALUES ($1, $2, $3, $4, 'user', 'local', true, true)
            "#,
        )
        .bind(id)
        .bind(email)
        .bind("hashed")
        .bind(name)
        .execute(db)
        .await?;
        Ok(id)
    }

    async fn account_exists(dbx: &Dbx, id: Uuid) -> Result<bool> {
        let q =
            query_as::<_, (i64,)>("SELECT COUNT(*)::bigint FROM accounts WHERE id = $1").bind(id);
        let (cnt,) = dbx.fetch_one(q).await?;
        Ok(cnt > 0)
    }
}
