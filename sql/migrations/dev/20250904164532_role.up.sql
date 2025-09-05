-- =========================
-- START: role / permission
-- =========================
CREATE TABLE IF NOT EXISTS
  role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    name TEXT NOT NULL,
    description TEXT
  );

-- Optional uniqueness on role name:
-- CREATE UNIQUE INDEX IF NOT EXISTS role_name_key ON role(name);
CREATE TABLE IF NOT EXISTS
  permission (
    -- Using name as the PK keeps permissions human-readable
    name TEXT PRIMARY KEY,
    -- If you don't need a UUID here, drop this column entirely.
    id UUID DEFAULT gen_random_uuid (),
    description TEXT
  );

-- Role <-> Permission (many-to-many)
CREATE TABLE IF NOT EXISTS
  permission_role (
    role_id UUID NOT NULL,
    permission_name TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_name),
    CONSTRAINT permission_role_role_id_fkey FOREIGN KEY (role_id) REFERENCES role (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT permission_role_permission_name_fkey FOREIGN KEY (permission_name) REFERENCES permission (name) ON UPDATE CASCADE ON DELETE CASCADE
  );

-- Role <-> Account (many-to-many)
CREATE TABLE IF NOT EXISTS
  role_account (
    account_id UUID NOT NULL,
    role_id UUID NOT NULL,
    PRIMARY KEY (account_id, role_id),
    CONSTRAINT role_account_account_id_fkey FOREIGN KEY (account_id) REFERENCES account (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT role_account_role_id_fkey FOREIGN KEY (role_id) REFERENCES role (id) ON UPDATE CASCADE ON DELETE CASCADE
  );

-- =========================
-- START: service
-- =========================
CREATE TABLE IF NOT EXISTS
  service (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    name TEXT UNIQUE NOT NULL,
    endpoint TEXT,
    description TEXT
  );