-- migrations/10_token_blacklist.sql
-- Purpose: Store blacklisted (revoked) tokens.
-- Notes:
--   - Store ONLY a cryptographic hash of the token (e.g., SHA-256) in token_hash (BYTEA).
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
    tags TEXT[] NOT NULL DEFAULT '{}', -- lightweight labels
    meta JSONB NOT NULL DEFAULT '{}'::jsonb, -- structured metadata
    -- START Audit
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID,
    updated_at TIMESTAMPTZ,
    -- Enforce 32 bytes for SHA-256 if you standardize on it (adjust if using another algo)
    CONSTRAINT token_blacklist_token_hash_len CHECK (octet_length(token_hash) = 32),
    -- FKs (ON DELETE SET NULL to retain historical context)
    CONSTRAINT token_blacklist_account_fk FOREIGN KEY (account_id) REFERENCES account (id) ON UPDATE CASCADE ON DELETE SET NULL,
    CONSTRAINT token_blacklist_namespace_fk FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE SET NULL
  );

-- Disallow duplicate entries for the exact same token hash.
-- If you want to allow multiple records (e.g., different reasons), drop this.
CREATE UNIQUE INDEX IF NOT EXISTS token_blacklist_token_hash_key ON token_blacklist (token_hash);

-- Speed up expiry sweeps.
CREATE INDEX IF NOT EXISTS token_blacklist_expires_at_idx ON token_blacklist (expires_at);

CREATE INDEX IF NOT EXISTS token_blacklist_namespace_hash_idx ON token_blacklist (namespace_id, token_hash);