-- migrations/10_token_blacklist.sql
-- Purpose: Store blacklisted (revoked) tokens and purge them automatically after expiry.
-- Notes:
--   - Store ONLY a cryptographic hash of the token (e.g., SHA-256) in token_hash (BYTEA).
--   - Rows are immediately removed when inserted/updated with an already-expired timestamp.
--   - A sweep function is provided to delete expired rows; an optional pg_cron schedule
--     is attempted (best-effort) to run the sweep periodically if pg_cron is installed.
--   - Indexes support fast lookups by token_hash and efficient expiry sweeps.
--   - Aligns with existing schema style: audit fields, tags/meta JSONB, FK references.
--
-- Usage in application code (example query for checks):
--   SELECT 1
--   FROM token_blacklist
--   WHERE token_hash = $1 AND now() < expires_at
--   LIMIT 1;
--   -- If a row exists, the token is blacklisted and still active.
--
-- Security:
--   - Always hash tokens in the app before inserting (never store raw tokens).
--   - Consider enabling RLS matching your tenant model (example policies stubbed below).
CREATE TABLE IF NOT EXISTS
  token_blacklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    -- Store a binary hash of the token (e.g., digest(token, 'sha256') from app code).
    token_hash BYTEA NOT NULL,
    -- Optional scoping for faster purges/analytics
    account_id UUID,
    namespace_id UUID,
    -- Expiry time of the token (when it naturally becomes invalid).
    expires_at TIMESTAMPTZ NOT NULL,
    -- Optional reason/context for auditing (e.g., "manual-revoke", "password-rotate").
    reason TEXT,
    -- START Meta & Tags
    tags TEXT[] NOT NULL DEFAULT '{}',
    meta JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- END Meta & Tags
    -- START Audit
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID,
    updated_at TIMESTAMPTZ,
    audit JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- END Audit
    -- ---------- Constraints ----------
    CONSTRAINT token_blacklist_audit_is_object CHECK (jsonb_typeof(audit) = 'object'),
    CONSTRAINT token_blacklist_meta_is_object CHECK (jsonb_typeof(meta) = 'object'),
    -- Enforce 32 bytes for SHA-256 if you standardize on it (adjust if using another algo)
    CONSTRAINT token_blacklist_token_hash_len CHECK (octet_length(token_hash) = 32),
    -- FKs (ON DELETE SET NULL to retain historical context)
    CONSTRAINT token_blacklist_account_fk FOREIGN KEY (account_id) REFERENCES account (id) ON UPDATE CASCADE ON DELETE SET NULL,
    CONSTRAINT token_blacklist_namespace_fk FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE SET NULL
  );

-- Disallow duplicate entries for the exact same token hash.
-- If you want to allow multiple records (e.g., different reasons), drop this.
CREATE UNIQUE INDEX IF NOT EXISTS token_blacklist_token_hash_key ON token_blacklist (token_hash);

-- Speed up active blacklist lookups.
CREATE INDEX IF NOT EXISTS token_blacklist_active_idx ON token_blacklist (token_hash)
WHERE
  (now() < expires_at);

-- Speed up expiry sweeps.
CREATE INDEX IF NOT EXISTS token_blacklist_expires_at_idx ON token_blacklist (expires_at);

-- =========================================
-- Immediate cleanup trigger (already-expired)
-- =========================================
CREATE
OR REPLACE FUNCTION token_blacklist_delete_if_expired () RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.expires_at <= now() THEN
    -- Immediately drop rows that are already expired.
    DELETE FROM token_blacklist WHERE id = NEW.id;
    RETURN NULL;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS token_blacklist_delete_if_expired_trg ON token_blacklist;

CREATE TRIGGER token_blacklist_delete_if_expired_trg BEFORE INSERT
OR
UPDATE ON token_blacklist FOR EACH ROW
EXECUTE FUNCTION token_blacklist_delete_if_expired ();

-- ==========================
-- Periodic sweep (best-effort)
-- ==========================
-- Deletes rows that have since expired. Returns deleted count.
CREATE
OR REPLACE FUNCTION token_blacklist_sweep () RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_deleted BIGINT;
BEGIN
  DELETE FROM token_blacklist
  WHERE expires_at <= now();
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;

-- Try to schedule a periodic sweep if pg_cron is available.
-- This DO block is defensive: it won't fail the migration if pg_cron isn't installed.
DO $$
BEGIN
  -- Check if pg_cron extension exists
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    -- Ensure schema is in search_path (pg_cron usually creates 'cron' schema)
    -- Schedule every 10 minutes; adjust as needed.
    BEGIN
      PERFORM cron.schedule('token_blacklist_sweep_every_10m',
                            '*/10 * * * *',
                            $$
SELECT
  token_blacklist_sweep ();

$$);
    EXCEPTION
      WHEN duplicate_object THEN
        -- Update existing job’s schedule/command if desired
        PERFORM 1;
      WHEN undefined_table OR undefined_function THEN
        -- Older pg_cron versions may expose a different API; ignore silently.
        PERFORM 1;
      WHEN others THEN
        -- Do not break migration if scheduling fails.
        PERFORM 1;
    END;
  END IF;
END
$$;

-- ==================
-- RLS (stub/example)
-- ==================
-- ALTER TABLE token_blacklist ENABLE ROW LEVEL SECURITY;
-- -- Example policy: allow service role to manage rows; tenants see only their namespace.
-- CREATE POLICY token_blacklist_tenant_isolation ON token_blacklist
--   USING (namespace_id = current_setting('app.namespace_id', true)::uuid);
-- ==================
-- Helpful comments
-- ==================
-- Insert example (app-side hashing with SHA-256, shown here for clarity only):
--   INSERT INTO token_blacklist (token_hash, account_id, namespace_id, expires_at, reason, created_by)
--   VALUES (decode('...32-byte-sha256-hex...', 'hex'), 'acc-uuid', 'ns-uuid', now() + interval '30 days', 'manual-revoke', 'actor-uuid');
--
-- Manual sweep (if pg_cron not present):
--   SELECT token_blacklist_sweep();