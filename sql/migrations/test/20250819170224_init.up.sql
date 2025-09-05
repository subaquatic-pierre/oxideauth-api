-- migrations/20250819120000_init.up.sql
-- EXTENSIONS
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================
-- START: account
-- =========================
CREATE TABLE
  IF NOT EXISTS account (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    -- Identity
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    acc_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_id TEXT,
    description TEXT,
    image_url TEXT,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- Audit
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
    updated_by UUID,
    updated_at TIMESTAMPTZ,
    -- Concurrency (optimistic locking)
    version INT NOT NULL DEFAULT 1,
    -- ---------- Constraints ----------
    CONSTRAINT account_email_key UNIQUE (email),
    CONSTRAINT account_created_by_fkey FOREIGN KEY (created_by) REFERENCES account (id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT account_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES account (id) ON UPDATE CASCADE ON DELETE SET NULL
  );

-- Helpful indexes
CREATE INDEX IF NOT EXISTS account_created_by_idx ON account (created_by);

CREATE INDEX IF NOT EXISTS account_updated_by_idx ON account (updated_by);

CREATE INDEX IF NOT EXISTS account_created_at_desc_idx ON account (created_at DESC);

CREATE INDEX IF NOT EXISTS account_updated_at_desc_idx ON account (updated_at DESC);

-- If you use OAuth-style logins, this is usually desirable:
-- CREATE UNIQUE INDEX IF NOT EXISTS account_provider_provider_id_key
--   ON account (provider, provider_id) WHERE provider_id IS NOT NULL;
-- =========================
-- START: role / permission
-- =========================
CREATE TABLE
  IF NOT EXISTS role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    name TEXT NOT NULL,
    description TEXT
  );

-- Optional uniqueness on role name:
-- CREATE UNIQUE INDEX IF NOT EXISTS role_name_key ON role(name);
CREATE TABLE
  IF NOT EXISTS permission (
    -- Using name as the PK keeps permissions human-readable
    name TEXT PRIMARY KEY,
    -- If you don't need a UUID here, drop this column entirely.
    id UUID DEFAULT gen_random_uuid (),
    description TEXT
  );

-- Role <-> Permission (many-to-many)
CREATE TABLE
  IF NOT EXISTS permission_role (
    role_id UUID NOT NULL,
    permission_name TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_name),
    CONSTRAINT permission_role_role_id_fkey FOREIGN KEY (role_id) REFERENCES role (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT permission_role_permission_name_fkey FOREIGN KEY (permission_name) REFERENCES permission (name) ON UPDATE CASCADE ON DELETE CASCADE
  );

-- Role <-> Account (many-to-many)
CREATE TABLE
  IF NOT EXISTS role_account (
    account_id UUID NOT NULL,
    role_id UUID NOT NULL,
    PRIMARY KEY (account_id, role_id),
    CONSTRAINT role_account_account_id_fkey FOREIGN KEY (account_id) REFERENCES account (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT role_account_role_id_fkey FOREIGN KEY (role_id) REFERENCES role (id) ON UPDATE CASCADE ON DELETE CASCADE
  );

-- =========================
-- START: service
-- =========================
CREATE TABLE
  IF NOT EXISTS service (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    name TEXT UNIQUE NOT NULL,
    endpoint TEXT,
    description TEXT
  );