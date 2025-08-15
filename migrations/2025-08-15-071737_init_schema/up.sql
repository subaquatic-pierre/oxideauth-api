-- Enable UUID generation (choose one of these; pgcrypto is common on modern PG)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- ACCOUNTS
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
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ROLES
CREATE TABLE IF NOT EXISTS roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PERMISSIONS (name is the PK because bindings reference permission_name)
CREATE TABLE IF NOT EXISTS permissions (
  id UUID DEFAULT gen_random_uuid(),
  name TEXT PRIMARY KEY,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PERMISSION BINDINGS (role ↔ permission)
CREATE TABLE IF NOT EXISTS permission_bindings (
  role_id UUID NOT NULL,
  permission_name TEXT NOT NULL,
  PRIMARY KEY (role_id, permission_name),
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_name) REFERENCES permissions(name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_permission_bindings_role_id ON permission_bindings(role_id);

CREATE INDEX IF NOT EXISTS idx_permission_bindings_permission_name ON permission_bindings(permission_name);

-- ROLE BINDINGS (account ↔ role)
CREATE TABLE IF NOT EXISTS role_bindings (
  account_id UUID NOT NULL,
  role_id UUID NOT NULL,
  PRIMARY KEY (account_id, role_id),
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_role_bindings_account_id ON role_bindings(account_id);

CREATE INDEX IF NOT EXISTS idx_role_bindings_role_id ON role_bindings(role_id);

-- SERVICES CATALOG
CREATE TABLE IF NOT EXISTS services (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT UNIQUE NOT NULL,
  endpoint TEXT,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);