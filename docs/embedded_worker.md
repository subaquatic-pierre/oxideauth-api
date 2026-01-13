# Architecture Decision Record: Background Task Management

## Context

The application requires a mechanism to handle recurring maintenance tasks, specifically the revocation of expired security tokens (Token Blacklist cleanup).

## Options Evaluated

### 1. Embedded Tokio Task (Current Choice)

A background loop spawned within the Axum process using `tokio::spawn` and `tokio::time::interval`.

- **Pros:**
  - **Simplicity:** No extra infrastructure (Redis/Queues).
  - **Efficiency:** Shared memory access to the database pool.
  - **Zero Latency:** Immediate execution within the existing runtime.
- **Cons:**
  - **Volatility:** If the process crashes, the "timer" state is lost.
  - **Scalability:** In a multi-node deployment, every instance runs the task simultaneously (requires idempotent SQL).
- **Best For:** Lightweight, idempotent cleanup tasks.

---

### 2. Distributed Worker (River/Sidekiq Pattern)

A job-queue system where a "Producer" inserts tasks into a table/Redis, and a "Worker" consumes them.

- **Pros:**
  - **Reliability:** Tasks are persistent in the database. If a worker fails, the job remains in the queue.
  - **Observability:** Ability to track job status, retries, and failures in a `jobs` table.
  - **Isolation:** Heavy tasks don't compete with the Web API for CPU/RAM.
- **Cons:**
  - **Complexity:** Requires managing job schemas and worker lifecycle.
  - **Database Load:** Constant (though optimized) interaction with the jobs table.
- **Best For:** Critical tasks that _must_ succeed (e.g., Billing, Emails, Webhooks).

---

## Technical Deep Dive: Postgres as a Queue

When moving to a distributed model in Postgres, we utilize the following primitives to avoid "Polling" (constantly querying the DB):

### LISTEN / NOTIFY

Postgres acts as a message broker.

1. **Workers** issue `LISTEN channel_name`.
2. **Producers** issue `NOTIFY channel_name, 'payload'`.
3. Postgres pushes a notification to the worker, waking it from a low-power state.

### FOR UPDATE SKIP LOCKED

To prevent multiple workers from picking up the same job, we use this specific locking strategy:

```sql
SELECT * FROM jobs
WHERE status = 'pending'
  AND run_at <= NOW()
ORDER BY priority DESC
FOR UPDATE SKIP LOCKED
LIMIT 1;
```
