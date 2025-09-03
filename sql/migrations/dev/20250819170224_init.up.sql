-- migrations/20250819120000_init.up.sql
-- one-time setup (per database)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  acc_type TEXT NOT NULL,
  provider TEXT NOT NULL,
  provider_id TEXT,
  description TEXT,
  image_url TEXT,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  cid UUID NOT NULL,
  ctime TIMESTAMPTZ NOT NULL DEFAULT now(),
  mid UUID NOT NULL,
  mtime TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT accounts_cid_fkey FOREIGN KEY (cid) REFERENCES accounts(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT accounts_mid_fkey FOREIGN KEY (mid) REFERENCES accounts(id) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_accounts_cid ON accounts (cid);

CREATE INDEX IF NOT EXISTS idx_accounts_mid ON accounts (mid);

-- Timelines (common for recent-first queries)
CREATE INDEX IF NOT EXISTS idx_accounts_ctime_desc ON accounts (ctime DESC);

CREATE INDEX IF NOT EXISTS idx_accounts_mtime_desc ON accounts (mtime DESC);

-- START ROLES
CREATE TABLE IF NOT EXISTS roles (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT
);

CREATE TABLE IF NOT EXISTS permissions (
  id UUID,
  name TEXT PRIMARY KEY,
  description TEXT
);

CREATE TABLE IF NOT EXISTS permission_bindings (
  role_id UUID NOT NULL,
  permission_name TEXT NOT NULL,
  PRIMARY KEY (role_id, permission_name),
  FOREIGN KEY (role_id) REFERENCES roles(id),
  FOREIGN KEY (permission_name) REFERENCES permissions(name)
);

CREATE TABLE IF NOT EXISTS role_bindings (
  account_id UUID NOT NULL,
  role_id UUID NOT NULL,
  PRIMARY KEY (account_id, role_id),
  FOREIGN KEY (account_id) REFERENCES accounts(id),
  FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE IF NOT EXISTS services (
  id UUID PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  endpoint TEXT,
  description TEXT
);