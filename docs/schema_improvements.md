# Database Schema

How the Entities Connect
Accounts

An Account represents a person or system user.

Each account can:

Have multiple Credentials (passwords, OAuth logins, API keys).

Hold multiple Memberships (which define their access inside different Workspaces or Projects).

## Schema Improvements

### Account

1. Email canonicalization:

- Normalize on write (lowercase + trim) via BEFORE INSERT/UPDATE trigger.
- Optional CHECK: disallow leading/trailing spaces.
- Keep/adjust unique index on lower(email).

```sql
-- [3] Email canonicalization (lower+trim), plus optional CHECK
-- 1) Optional CHECK: disallow surrounding spaces (defense-in-depth)
ALTER TABLE account
  ADD CONSTRAINT account_email_no_surrounding_space
  CHECK (email = btrim(email));

-- 2) BEFORE triggers to normalize on write
CREATE OR REPLACE FUNCTION account_email_canonicalize()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.email IS NULL THEN
    RAISE EXCEPTION 'email cannot be NULL';
  END IF;
  NEW.email := lower(btrim(NEW.email));
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_account_email_canonicalize_ins ON account;
CREATE TRIGGER trg_account_email_canonicalize_ins
BEFORE INSERT ON account
FOR EACH ROW
EXECUTE FUNCTION account_email_canonicalize();

DROP TRIGGER IF EXISTS trg_account_email_canonicalize_upd ON account;
CREATE TRIGGER trg_account_email_canonicalize_upd
BEFORE UPDATE OF email ON account
FOR EACH ROW
EXECUTE FUNCTION account_email_canonicalize();

-- 3) (If needed) Recreate unique index to be sure it matches strategy
DROP INDEX IF EXISTS account_email_lower_key;
CREATE UNIQUE INDEX account_email_lower_key
  ON account (lower(email))
  WHERE email IS NOT NULL;
```

3. Indexes for common lookups:

- Partial btree on enabled/verified.
- (Optional) GIN on tags.

```sql
-- [5] Indexes for common lookups
-- Fast path for "enabled accounts" scans
CREATE INDEX IF NOT EXISTS idx_account_enabled_true
  ON account (id)
  WHERE enabled = TRUE;

-- Fast path for "verified accounts" scans
CREATE INDEX IF NOT EXISTS idx_account_verified_true
  ON account (id)
  WHERE verified = TRUE;

-- Optional: if you often filter by both flags together
CREATE INDEX IF NOT EXISTS idx_account_enabled_verified_true
  ON account (id)
  WHERE enabled = TRUE AND verified = TRUE;

-- Optional: GIN on tags (array ops like @>)
CREATE INDEX IF NOT EXISTS idx_account_tags_gin
  ON account USING GIN (tags);
```

4. Security checks:

- Provide a convenience VIEW for active accounts (enabled & verified) to reduce footguns.
- (Optional) Enable RLS on `account` and add policies if you plan multi-tenant reads from this table.

```sql
-- [6] Security checks helpers
-- Convenience VIEW to reduce accidental bypass of enabled/verified checks
CREATE OR REPLACE VIEW account_active AS
SELECT *
FROM account
WHERE enabled = TRUE
  AND verified = TRUE;

-- Optional: Row Level Security (RLS) scaffolding (enable only if you need it)
-- ALTER TABLE account ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY account_read_active_only
--   ON account FOR SELECT
--   USING (enabled = TRUE AND verified = TRUE);
```

5. Data hygiene:

- CHECK for `avatar_url` scheme (http/https) or keep NULL.
- (Optional) Add stricter JSON schema validation using an extension (pg_jsonschema) later.

```sql
-- [7] Data hygiene
-- Ensure avatar_url is either NULL or http/https (basic sanity check, adjust regex as needed)
ALTER TABLE account
  ADD CONSTRAINT account_avatar_url_scheme
  CHECK (
    avatar_url IS NULL
    OR avatar_url ~* '^(https?)://'
  );

-- (Optional) If you adopt pg_jsonschema later for stricter JSON validation:
-- SELECT pg_catalog.pg_extension_config_dump('pg_jsonschema', '');
-- -- Then define a function + CHECK using jsonschema_validation(meta, '<schema>')
```

### Workspace

1. Slug hygiene & canonicalization:

- Enforce lowercase + trimmed slug values via BEFORE INSERT/UPDATE trigger.
- Optional CHECK: restrict to alphanumeric and dashes only.
- Ensure uniqueness on slug is preserved (already has a unique constraint).

```sql
-- [1] Slug canonicalization (lower+trim), plus optional CHECK
-- Optional: enforce regex for slug (lowercase letters, numbers, dash only)
ALTER TABLE workspace
  ADD CONSTRAINT workspace_slug_format
  CHECK (slug ~ '^[a-z0-9-]+$');

-- BEFORE triggers to normalize slug
CREATE OR REPLACE FUNCTION workspace_slug_canonicalize()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.slug IS NULL THEN
    RAISE EXCEPTION 'slug cannot be NULL';
  END IF;
  NEW.slug := lower(btrim(NEW.slug));
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_workspace_slug_canonicalize_ins ON workspace;
CREATE TRIGGER trg_workspace_slug_canonicalize_ins
BEFORE INSERT ON workspace
FOR EACH ROW
EXECUTE FUNCTION workspace_slug_canonicalize();

DROP TRIGGER IF EXISTS trg_workspace_slug_canonicalize_upd ON workspace;
CREATE TRIGGER trg_workspace_slug_canonicalize_upd
BEFORE UPDATE OF slug ON workspace
FOR EACH ROW
EXECUTE FUNCTION workspace_slug_canonicalize();
```

2. Indexes for common lookups:

- `slug` should already be unique, but add btree index for fast lookups.
- Add GIN indexes for tags/meta if filtering or searching by them is frequent.

```sql
-- [2] Indexes for workspace
-- Ensure fast lookups by slug
CREATE INDEX IF NOT EXISTS idx_workspace_slug ON workspace(slug);

-- Optional: enable search/filtering by tags and meta
CREATE INDEX IF NOT EXISTS idx_workspace_tags_gin ON workspace USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_workspace_meta_gin ON workspace USING GIN(meta);
```

3. Audit triggers:

- Auto-update `updated_at` on row changes.
- (Optional) Fill `updated_by` if you want database-driven attribution.

```sql
-- [3] Audit maintenance
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_workspace_set_updated_at ON workspace;
CREATE TRIGGER trg_workspace_set_updated_at
BEFORE UPDATE ON workspace
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
```

4. Security scaffolding:

- Enable Row-Level Security (RLS) for tenant isolation.
- Default SELECT policies to restrict access by workspace membership.

```sql
-- [4] Security scaffolding
ALTER TABLE workspace ENABLE ROW LEVEL SECURITY;

-- Example: allow row access only if current user is in the workspace
-- (replace with actual membership check function/policy)
-- CREATE POLICY workspace_tenant_isolation
--   ON workspace FOR SELECT
--   USING (auth_workspace_id() = id);
```

5. Data hygiene:

- Ensure `config` and `meta` are always JSON objects (already CHECK’d).
- (Optional) Add pg_jsonschema for stricter schema enforcement later.

```sql
-- [5] Data hygiene
-- Already enforced: config and meta are JSON objects.
-- Optional stricter schema validation (requires pg_jsonschema extension):
-- ALTER TABLE workspace
--   ADD CONSTRAINT workspace_config_schema
--   CHECK (jsonb_matches_schema(config, '<json schema>'));
```

### Project

1. Code hygiene & canonicalization:

- If `code` is standardized (slug-like), enforce lowercase + trimmed values via BEFORE INSERT/UPDATE trigger.
- Optional CHECK: restrict to alphanumeric and dashes only.
- Enforce per-workspace uniqueness once usage is consistent.

```sql
-- [1] Code canonicalization (lower+trim), plus optional CHECK
ALTER TABLE project
  ADD CONSTRAINT project_code_format
  CHECK (code IS NULL OR code ~ '^[a-z0-9-]+$');

CREATE OR REPLACE FUNCTION project_code_canonicalize()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.code IS NOT NULL THEN
    NEW.code := lower(btrim(NEW.code));
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_project_code_canonicalize_ins ON project;
CREATE TRIGGER trg_project_code_canonicalize_ins
BEFORE INSERT ON project
FOR EACH ROW
EXECUTE FUNCTION project_code_canonicalize();

DROP TRIGGER IF EXISTS trg_project_code_canonicalize_upd ON project;
CREATE TRIGGER trg_project_code_canonicalize_upd
BEFORE UPDATE OF code ON project
FOR EACH ROW
EXECUTE FUNCTION project_code_canonicalize();
```

2. Indexes for common lookups:

- Uniqueness on `(workspace_id, name)` already enforced.
- Optional: uniqueness on `(workspace_id, code)` if adopted.
- Add GIN indexes for tags/meta if filtering/searching is frequent.

```sql
-- [2] Indexes for project
-- Enforce per-workspace uniqueness of code
CREATE UNIQUE INDEX IF NOT EXISTS project_workspace_code_key
  ON project (workspace_id, code);

-- Optional: indexes for tags/meta
CREATE INDEX IF NOT EXISTS idx_project_tags_gin ON project USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_project_meta_gin ON project USING GIN(meta);
```

3. Audit triggers:

- Auto-update `updated_at` on row changes.
- (Optional) Populate `updated_by` if database-driven attribution desired.

```sql
-- [3] Audit maintenance
CREATE OR REPLACE FUNCTION set_project_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_project_set_updated_at ON project;
CREATE TRIGGER trg_project_set_updated_at
BEFORE UPDATE ON project
FOR EACH ROW
EXECUTE FUNCTION set_project_updated_at();
```

4. Security scaffolding:

- Enable Row-Level Security (RLS) for tenant isolation by workspace_id.
- Add SELECT policies to restrict access to projects only within the user’s workspace(s).

```sql
-- [4] Security scaffolding
ALTER TABLE project ENABLE ROW LEVEL SECURITY;

-- Example: restrict to projects inside the current workspace
-- CREATE POLICY project_tenant_isolation
--   ON project FOR SELECT
--   USING (auth_workspace_id() = workspace_id);
```

5. Data hygiene:

- Ensure `config` and `meta` remain JSON objects (already CHECK’d).
- (Optional) Enforce stricter JSON schema validation with pg_jsonschema.

```sql
-- [5] Data hygiene
-- Already enforced: config and meta must be JSON objects.
-- Optional stricter validation with pg_jsonschema:
-- ALTER TABLE project
--   ADD CONSTRAINT project_config_schema
--   CHECK (jsonb_matches_schema(config, '<json schema>'));
```

### Credential

3. Provider fields hygiene:

- Trim `provider` and `provider_id`; lower `provider` for consistency.
- Add a CHECK for allowed provider name pattern (alphanum, dash, underscore).

```sql
-- [3] Provider hygiene
ALTER TABLE credential
  ADD CONSTRAINT credential_provider_format
  CHECK (provider IS NULL OR provider ~* '^[a-z0-9_-]+$');

CREATE OR REPLACE FUNCTION credential_provider_canonicalize()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.provider IS NOT NULL THEN
    NEW.provider := lower(btrim(NEW.provider));
  END IF;
  IF NEW.provider_id IS NOT NULL THEN
    NEW.provider_id := btrim(NEW.provider_id);
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_credential_provider_ins ON credential;
CREATE TRIGGER trg_credential_provider_ins
BEFORE INSERT ON credential
FOR EACH ROW
EXECUTE FUNCTION credential_provider_canonicalize();

DROP TRIGGER IF EXISTS trg_credential_provider_upd ON credential;
CREATE TRIGGER trg_credential_provider_upd
BEFORE UPDATE OF provider, provider_id ON credential
FOR EACH ROW
EXECUTE FUNCTION credential_provider_canonicalize();
```

4. Kind-specific invariants:

- If `kind='password'`: `password_hash` must be NOT NULL and `login_email` should be NOT NULL.
- If `kind IN ('oauth','sso')`: `provider` and `provider_id` must be NOT NULL; `password_hash` must be NULL.
- If `kind='api_key'`: consider requiring `provider='local'` and store hash only.

```sql
-- [4] Kind-specific CHECK constraints
ALTER TABLE credential
  ADD CONSTRAINT credential_password_requirements
  CHECK (
    kind <> 'password'
    OR (login_email IS NOT NULL AND password_hash IS NOT NULL)
  );

ALTER TABLE credential
  ADD CONSTRAINT credential_oauth_requirements
  CHECK (
    kind NOT IN ('oauth','sso')
    OR (provider IS NOT NULL AND provider_id IS NOT NULL AND password_hash IS NULL)
  );

ALTER TABLE credential
  ADD CONSTRAINT credential_apikey_requirements
  CHECK (
    kind <> 'api_key'
    OR (password_hash IS NOT NULL AND provider IS DISTINCT FROM ''::text)
  );
```

5. Uniqueness & lookup indexes (per workspace):

- Keep **one active password credential per (workspace, login_email)**.
- Keep **one oauth/sso credential per (workspace, provider, provider_id)**.
- Add supporting non-unique filtered indexes for fast auth-path lookups.

```sql
-- [5] Lookup/uniqueness (already in your migration, included for completeness)
-- Active password uniqueness
CREATE UNIQUE INDEX IF NOT EXISTS cred_pw_unique_ns_email
  ON credential (workspace_id, lower(login_email))
  WHERE kind = 'password'
    AND status = 'active'
    AND login_email IS NOT NULL;

-- OAuth/SSO uniqueness
CREATE UNIQUE INDEX IF NOT EXISTS cred_oauth_unique_ns
  ON credential (workspace_id, provider, provider_id)
  WHERE kind IN ('oauth','sso')
    AND provider_id IS NOT NULL;

-- Lookup helpers
CREATE INDEX IF NOT EXISTS cred_password_lookup_idx
  ON credential (workspace_id, lower(login_email))
  WHERE kind = 'password'
    AND status = 'active'
    AND login_email IS NOT NULL;

CREATE INDEX IF NOT EXISTS cred_oauth_lookup_idx
  ON credential (workspace_id, provider, provider_id)
  WHERE kind IN ('oauth','sso')
    AND status = 'active'
    AND provider_id IS NOT NULL;
```

7. RLS scaffolding (per-tenant isolation):

- Enable RLS; restrict SELECT/UPDATE/DELETE to users operating within their `workspace_id`.
- Replace `auth_workspace_id()` with your session-resolved function/view for current tenant.

```sql
-- [7] Row-Level Security (RLS) scaffolding
ALTER TABLE credential ENABLE ROW LEVEL SECURITY;

-- Example SELECT policy by tenant
-- CREATE POLICY credential_tenant_select
--   ON credential FOR SELECT
--   USING (workspace_id = auth_workspace_id());

-- Example UPDATE/DELETE policy by tenant (and optionally by owner account)
-- CREATE POLICY credential_tenant_write
--   ON credential FOR UPDATE USING (workspace_id = auth_workspace_id())
--   WITH CHECK (workspace_id = auth_workspace_id());
```

8. Sensitive data hygiene:

- Never store raw API keys or passwords; store **hashes** only.
- Consider a CHECK to ensure `password_hash` meets a minimum length or prefix (e.g., `$argon2id$`).

```sql
-- [8] Hash-format sanity checks (adjust to your hashing scheme)
ALTER TABLE credential
  ADD CONSTRAINT credential_password_hash_format
  CHECK (
    password_hash IS NULL
    OR password_hash ~ '^\$argon2(id|i|d)\$'
  );
```

10. Introspection & maintenance helpers:

- Find potentially inconsistent rows (e.g., password kind without hash, oauth without provider_id).
- Periodic cleanup queries for revoked/abandoned credentials.

```sql
-- [10] Health checks
-- Password without hash or email
SELECT id FROM credential
WHERE kind = 'password' AND (password_hash IS NULL OR login_email IS NULL);

-- OAuth/SSO missing provider info
SELECT id FROM credential
WHERE kind IN ('oauth','sso') AND (provider IS NULL OR provider_id IS NULL);

-- Stale pending credentials (example: older than 14 days)
SELECT id FROM credential
WHERE status = 'pending' AND created_at < now() - interval '14 days';
```

### Role

1. Name hygiene & canonicalization:

- Enforce lowercase + trimmed role names via BEFORE INSERT/UPDATE trigger.
- Optional CHECK: restrict to alphanumeric, dash, underscore, and dot (for hierarchies like `project.editor`).

```sql
-- [1] Role name canonicalization
ALTER TABLE role
  ADD CONSTRAINT role_name_format
  CHECK (name ~ '^[a-z0-9._-]+$');

CREATE OR REPLACE FUNCTION role_name_canonicalize()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.name IS NULL THEN
    RAISE EXCEPTION 'role.name cannot be NULL';
  END IF;
  NEW.name := lower(btrim(NEW.name));
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_role_name_canonicalize_ins ON role;
CREATE TRIGGER trg_role_name_canonicalize_ins
BEFORE INSERT ON role
FOR EACH ROW
EXECUTE FUNCTION role_name_canonicalize();

DROP TRIGGER IF EXISTS trg_role_name_canonicalize_upd ON role;
CREATE TRIGGER trg_role_name_canonicalize_upd
BEFORE UPDATE OF name ON role
FOR EACH ROW
EXECUTE FUNCTION role_name_canonicalize();
```

2. Reserved names guard (optional):

- Prevent overriding core/system roles in non-global workspaces (e.g., `owner`, `editor`, `viewer`).
- Replace `is_global_workspace(id)` with your actual function/flag.

```sql
-- [2] Reserved names (example)
CREATE OR REPLACE FUNCTION role_reserved_name_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_reserved text[] := ARRAY['owner','editor','viewer'];
BEGIN
  IF lower(NEW.name) = ANY (v_reserved) AND NOT is_global_workspace(NEW.workspace_id) THEN
    RAISE EXCEPTION 'Reserved role "%" may only exist in global workspace', NEW.name;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_role_reserved_guard_ins ON role;
CREATE TRIGGER trg_role_reserved_guard_ins
BEFORE INSERT ON role
FOR EACH ROW
EXECUTE FUNCTION role_reserved_name_guard();

DROP TRIGGER IF EXISTS trg_role_reserved_guard_upd ON role;
CREATE TRIGGER trg_role_reserved_guard_upd
BEFORE UPDATE OF name, workspace_id ON role
FOR EACH ROW
EXECUTE FUNCTION role_reserved_name_guard();
```

3. Indexes for common lookups:

- Uniqueness `(workspace_id, name)` already ensures fast equality lookups.
- Add GIN indexes for tags/meta if used in filters or search.

```sql
-- [3] Indexes
CREATE INDEX IF NOT EXISTS idx_role_tags_gin ON role USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_role_meta_gin ON role USING GIN(meta);
```

4. Audit triggers:

- Auto-update `updated_at` on row changes.
- Consider DB-driven attribution for `updated_by` if you maintain session info server-side.

```sql
-- [4] Audit maintenance
CREATE OR REPLACE FUNCTION set_role_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_role_set_updated_at ON role;
CREATE TRIGGER trg_role_set_updated_at
BEFORE UPDATE ON role
FOR EACH ROW
EXECUTE FUNCTION set_role_updated_at();
```

5. RLS scaffolding:

- Enable RLS; restrict access by `workspace_id`.
- Replace `auth_workspace_id()` with your actual tenant resolver.

```sql
-- [5] Row-Level Security
ALTER TABLE role ENABLE ROW LEVEL SECURITY;

-- Example: allow select within tenant
-- CREATE POLICY role_tenant_select
--   ON role FOR SELECT
--   USING (workspace_id = auth_workspace_id());

-- Example: allow write only within tenant
-- CREATE POLICY role_tenant_write
--   ON role FOR INSERT WITH CHECK (workspace_id = auth_workspace_id());
-- CREATE POLICY role_tenant_update
--   ON role FOR UPDATE USING (workspace_id = auth_workspace_id())
--   WITH CHECK (workspace_id = auth_workspace_id());
-- CREATE POLICY role_tenant_delete
--   ON role FOR DELETE USING (workspace_id = auth_workspace_id());
```

6. Data hygiene:

- Enforce meta as JSON object (already checked). Optionally clamp description length.
- Optionally ensure `tags` deduplication in application layer or via a canonicalization trigger.

```sql
-- [6] Optional hygiene
ALTER TABLE role
  ADD CONSTRAINT role_description_maxlen CHECK (description IS NULL OR length(description) <= 1000);
```

7. Migration helpers & seeding:

- Seed baseline roles in the global workspace, then allow tenant-level overrides.
- Provide idempotent upserts for standard roles.

```sql
-- [7] Seeding helpers (example; adapt to your bootstrap approach)
-- INSERT INTO role (workspace_id, name, description, created_by)
-- VALUES (global_workspace_id(), 'owner', 'Full control', system_account_id())
-- ON CONFLICT (workspace_id, name) DO UPDATE SET description = EXCLUDED.description;
```

8. Future: role immutability flags (optional):

- Add `locked BOOLEAN` to prevent edits/deletes of system roles.
- Add CHECK to restrict edits when locked.

```sql
-- [8] Optional: locked/system roles
ALTER TABLE role ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE role
  ADD CONSTRAINT role_locked_no_delete CHECK (NOT locked);

-- Enforce in triggers (example)
CREATE OR REPLACE FUNCTION role_block_mutation_if_locked()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.locked AND (TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND (OLD.name IS DISTINCT FROM NEW.name OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id))) THEN
    RAISE EXCEPTION 'System role "%" is locked', OLD.name;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_role_block_locked_update ON role;
CREATE TRIGGER trg_role_block_locked_update
BEFORE UPDATE ON role
FOR EACH ROW
EXECUTE FUNCTION role_block_mutation_if_locked();
```

### Permission

1. Name hygiene & canonicalization:

- Enforce lowercase + trimmed permission names via BEFORE INSERT/UPDATE trigger.
- Convention: use dot-separated identifiers (e.g., `project.read`, `project.write`).
- Optional CHECK: restrict to lowercase letters, digits, dot, dash, and underscore.

```sql
-- [1] Permission name canonicalization
ALTER TABLE permission
  ADD CONSTRAINT permission_name_format
  CHECK (name ~ '^[a-z0-9._-]+$');

CREATE OR REPLACE FUNCTION permission_name_canonicalize()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.name IS NULL THEN
    RAISE EXCEPTION 'permission.name cannot be NULL';
  END IF;
  NEW.name := lower(btrim(NEW.name));
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_permission_name_canonicalize_ins ON permission;
CREATE TRIGGER trg_permission_name_canonicalize_ins
BEFORE INSERT ON permission
FOR EACH ROW
EXECUTE FUNCTION permission_name_canonicalize();

DROP TRIGGER IF EXISTS trg_permission_name_canonicalize_upd ON permission;
CREATE TRIGGER trg_permission_name_canonicalize_upd
BEFORE UPDATE OF name ON permission
FOR EACH ROW
EXECUTE FUNCTION permission_name_canonicalize();
```

2. Code field hygiene:

- If `code` is used, normalize to lowercase + trim as well.
- Optional uniqueness `(workspace_id, code)` if treated as alternative identifier.

```sql
-- [2] Code hygiene
ALTER TABLE permission
  ADD CONSTRAINT permission_code_format
  CHECK (code IS NULL OR code ~ '^[a-z0-9._-]+$');

CREATE OR REPLACE FUNCTION permission_code_canonicalize()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.code IS NOT NULL THEN
    NEW.code := lower(btrim(NEW.code));
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_permission_code_ins ON permission;
CREATE TRIGGER trg_permission_code_ins
BEFORE INSERT ON permission
FOR EACH ROW
EXECUTE FUNCTION permission_code_canonicalize();

DROP TRIGGER IF EXISTS trg_permission_code_upd ON permission;
CREATE TRIGGER trg_permission_code_upd
BEFORE UPDATE OF code ON permission
FOR EACH ROW
EXECUTE FUNCTION permission_code_canonicalize();

-- Optional: enforce uniqueness per workspace
-- CREATE UNIQUE INDEX IF NOT EXISTS permission_workspace_code_key
--   ON permission (workspace_id, code);
```

3. Indexes for common lookups:

- `(workspace_id, name)` uniqueness already ensures fast lookups.
- Add `(workspace_id, code)` if used.
- Add GIN indexes for tags/meta if filtered frequently.

```sql
-- [3] Indexes
CREATE INDEX IF NOT EXISTS idx_permission_tags_gin ON permission USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_permission_meta_gin ON permission USING GIN(meta);
```

5. RLS scaffolding:

- Enable Row-Level Security to isolate by `workspace_id`.
- Replace `auth_workspace_id()` with your tenant resolver.

```sql
-- [5] Row-Level Security
ALTER TABLE permission ENABLE ROW LEVEL SECURITY;

-- Example: allow tenant-scoped reads
-- CREATE POLICY permission_tenant_select
--   ON permission FOR SELECT
--   USING (workspace_id = auth_workspace_id());

-- Example: allow tenant writes
-- CREATE POLICY permission_tenant_write
--   ON permission FOR INSERT WITH CHECK (workspace_id = auth_workspace_id());
-- CREATE POLICY permission_tenant_update
--   ON permission FOR UPDATE USING (workspace_id = auth_workspace_id())
--   WITH CHECK (workspace_id = auth_workspace_id());
-- CREATE POLICY permission_tenant_delete
--   ON permission FOR DELETE USING (workspace_id = auth_workspace_id());
```

6. Reserved names guard (optional):

- Prevent accidental overrides of system-critical permissions (e.g., `system.admin`, `auth.login`).

```sql
-- [6] Reserved permissions (example)
CREATE OR REPLACE FUNCTION permission_reserved_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_reserved text[] := ARRAY['system.admin','auth.login'];
BEGIN
  IF lower(NEW.name) = ANY (v_reserved) AND NOT is_global_workspace(NEW.workspace_id) THEN
    RAISE EXCEPTION 'Reserved permission "%" may only exist in global workspace', NEW.name;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_permission_reserved_ins ON permission;
CREATE TRIGGER trg_permission_reserved_ins
BEFORE INSERT ON permission
FOR EACH ROW
EXECUTE FUNCTION permission_reserved_guard();

DROP TRIGGER IF EXISTS trg_permission_reserved_upd ON permission;
CREATE TRIGGER trg_permission_reserved_upd
BEFORE UPDATE OF name, workspace_id ON permission
FOR EACH ROW
EXECUTE FUNCTION permission_reserved_guard();
```

7. Data hygiene:

- Already enforced: `meta` must be JSON object.
- Optionally clamp description length.

```sql
-- [7] Optional hygiene
ALTER TABLE permission
  ADD CONSTRAINT permission_description_maxlen
  CHECK (description IS NULL OR length(description) <= 1000);
```

8. Seeding & migrations:

- Seed baseline permissions in global workspace for core features.
- Provide idempotent upsert patterns.

```sql
-- [8] Seeding helpers (example)
-- INSERT INTO permission (workspace_id, name, description, created_by)
-- VALUES (global_workspace_id(), 'project.read', 'Read project data', system_account_id())
-- ON CONFLICT (workspace_id, name) DO UPDATE SET description = EXCLUDED.description;
```

### Role ↔ Permission (Join Table)

1. Enforce workspace consistency (`role.workspace_id = permission.workspace_id`):

- Prevent cross-workspace bindings by validating during INSERT/UPDATE.
- Use a BEFORE trigger for immediate feedback (simple and fast). Optionally add a CONSTRAINT TRIGGER DEFERRABLE INITIALLY DEFERRED if bulk loads need deferred checks.

SQL:

    -- [1] Workspace consistency guard
    CREATE OR REPLACE FUNCTION rp_workspace_guard()
    RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
      v_role_ns uuid;
      v_perm_ns uuid;
    BEGIN
      SELECT workspace_id INTO v_role_ns FROM role WHERE id = NEW.role_id;
      IF v_role_ns IS NULL THEN
        RAISE EXCEPTION 'role "%" not found', NEW.role_id;
      END IF;

      SELECT workspace_id INTO v_perm_ns FROM permission WHERE id = NEW.permission_id;
      IF v_perm_ns IS NULL THEN
        RAISE EXCEPTION 'permission "%" not found', NEW.permission_id;
      END IF;

      IF v_role_ns <> v_perm_ns THEN
        RAISE EXCEPTION 'Workspace mismatch: role(%) and permission(%)', v_role_ns, v_perm_ns;
      END IF;
      RETURN NEW;
    END;
    $$;

    DROP TRIGGER IF EXISTS trg_rp_workspace_guard_ins ON role_permission;
    CREATE TRIGGER trg_rp_workspace_guard_ins
    BEFORE INSERT ON role_permission
    FOR EACH ROW
    EXECUTE FUNCTION rp_workspace_guard();

    DROP TRIGGER IF EXISTS trg_rp_workspace_guard_upd ON role_permission;
    CREATE TRIGGER trg_rp_workspace_guard_upd
    BEFORE UPDATE OF role_id, permission_id ON role_permission
    FOR EACH ROW
    EXECUTE FUNCTION rp_workspace_guard();

    -- Alternative (deferred, uncomment to use instead of BEFORE triggers):
    -- CREATE CONSTRAINT TRIGGER rp_workspace_guard_def
    -- AFTER INSERT OR UPDATE OF role_id, permission_id ON role_permission
    -- DEFERRABLE INITIALLY DEFERRED
    -- FOR EACH ROW EXECUTE FUNCTION rp_workspace_guard();

2. RLS scaffolding (tenant isolation by workspace via role/permission join):

- Enable RLS on the join table and use subqueries to tie rows to a tenant workspace.
- Replace auth_workspace_id() with your resolver.

SQL:

    -- [2] Row-Level Security
    ALTER TABLE role_permission ENABLE ROW LEVEL SECURITY;

    -- SELECT allowed if the linked role (or permission) is in the current workspace
    -- (pick one predicate style; role-based is typical)
    -- CREATE POLICY rp_tenant_select
    --   ON role_permission FOR SELECT
    --   USING (
    --     EXISTS (
    --       SELECT 1 FROM role r
    --       WHERE r.id = role_permission.role_id
    --         AND r.workspace_id = auth_workspace_id()
    --     )
    --   );

    -- INSERT allowed only if role is in-tenant
    -- CREATE POLICY rp_tenant_insert
    --   ON role_permission FOR INSERT
    --   WITH CHECK (
    --     EXISTS (
    --       SELECT 1 FROM role r
    --       WHERE r.id = role_permission.role_id
    --         AND r.workspace_id = auth_workspace_id()
    --     )
    --   );

    -- UPDATE/DELETE similarly constrained
    -- CREATE POLICY rp_tenant_update
    --   ON role_permission FOR UPDATE
    --   USING (EXISTS (SELECT 1 FROM role r WHERE r.id = role_permission.role_id AND r.workspace_id = auth_workspace_id()))
    --   WITH CHECK (EXISTS (SELECT 1 FROM role r WHERE r.id = role_permission.role_id AND r.workspace_id = auth_workspace_id()));

    -- CREATE POLICY rp_tenant_delete
    --   ON role_permission FOR DELETE
    --   USING (EXISTS (SELECT 1 FROM role r WHERE r.id = role_permission.role_id AND r.workspace_id = auth_workspace_id()));

3. Auditability (optional lightweight history):

- If you want to track who bound/unbound permissions, add created_by, created_at columns and a tiny trigger to set them.
- Alternatively, maintain bindings via an application-level audit log.

SQL:

    -- [3] Optional audit columns
    -- ALTER TABLE role_permission
    --   ADD COLUMN created_by uuid,
    --   ADD COLUMN created_at timestamptz DEFAULT now();

    -- CREATE OR REPLACE FUNCTION set_rp_created_at()
    -- RETURNS trigger LANGUAGE plpgsql AS $$
    -- BEGIN
    --   IF TG_OP = 'INSERT' AND NEW.created_at IS NULL THEN
    --     NEW.created_at := now();
    --   END IF;
    --   RETURN NEW;
    -- END;
    -- $$;

    -- DROP TRIGGER IF EXISTS trg_rp_set_created_at ON role_permission;
    -- CREATE TRIGGER trg_rp_set_created_at
    -- BEFORE INSERT ON role_permission
    -- FOR EACH ROW
    -- EXECUTE FUNCTION set_rp_created_at();

4. Integrity & maintenance helpers:

- Unique PK (role_id, permission_id) already prevents duplicates.
- Provide convenience delete and diagnostic queries.

SQL:

    -- [4] Maintenance snippets
    -- Remove all permissions from a role (careful!)
    -- DELETE FROM role_permission WHERE role_id = :role_id;

    -- List permissions for a role (with names)
    -- SELECT p.id, p.name
    -- FROM role_permission rp
    -- JOIN permission p ON p.id = rp.permission_id
    -- WHERE rp.role_id = :role_id
    -- ORDER BY p.name;

    -- List roles that include a permission
    -- SELECT r.id, r.name
    -- FROM role_permission rp
    -- JOIN role r ON r.id = rp.role_id
    -- WHERE rp.permission_id = :permission_id
    -- ORDER BY r.name;

5. Seeding patterns:

- Seed baseline role/permission bindings in the global workspace.
- Use idempotent upserts to avoid duplicates on re-run.

SQL:

    -- [5] Seeding example (adjust to your bootstrap helpers)
    -- WITH perm AS (
    --   SELECT id FROM permission WHERE workspace_id = global_workspace_id() AND name = 'project.read'
    -- ), role_row AS (
    --   SELECT id FROM role WHERE workspace_id = global_workspace_id() AND name = 'viewer'
    -- )
    -- INSERT INTO role_permission (role_id, permission_id)
    -- SELECT role_row.id, perm.id FROM role_row, perm
    -- ON CONFLICT (role_id, permission_id) DO NOTHING;

6. Performance notes:

- Existing indexes (role_id) and (permission_id) are adequate for join paths.
- If you frequently query by both, a covering index on (role_id, permission_id) is redundant with the PK, so no need to add one.

### Token Blacklist

### Data Integrity and Enforcement

This section is for enforcing constraints on the data to ensure its validity. The `hash` length check is crucial for security.

```sql
-- [1] Data Integrity
-- Enforce 32 bytes for SHA-256 hash.
ALTER TABLE token
  ADD CONSTRAINT token_blacklist_hash_len
  CHECK (octet_length(hash) = 32);

-- Ensure the reason field is not an empty string if it's provided.
ALTER TABLE token
  ADD CONSTRAINT token_blacklist_reason_not_empty
  CHECK (reason IS NULL OR reason <> '');

-- Check for valid JSONB objects in the meta and audit fields.
ALTER TABLE token
  ADD CONSTRAINT token_blacklist_audit_is_object CHECK (jsonb_typeof(audit) = 'object');
ALTER TABLE token
  ADD CONSTRAINT token_blacklist_meta_is_object CHECK (jsonb_typeof(meta) = 'object');
```

### Indexes for Common Lookups

These indexes are optimized for the most frequent queries on this table: checking for a blacklisted token and sweeping expired entries.

```sql
-- [2] Indexes for common lookups
-- The primary index for fast lookup of a token hash within a specific workspace.
-- This is used for the most common check: is this token blacklisted for this user/workspace?
CREATE INDEX IF NOT EXISTS token_blacklist_workspace_hash_idx
  ON token (workspace_id, hash);

-- Index to optimize the application-level sweep function.
-- This allows the scheduled job to quickly find and delete all expired tokens.
CREATE INDEX IF NOT EXISTS token_blacklist_expires_at_idx
  ON token (expires_at);
```

### Security Checks (RLS & Views)

This provides Row-Level Security for multi-tenant isolation and a convenience view for queries.

```sql
-- [3] Security Checks
-- Convenience VIEW to simplify queries for active, non-expired tokens.
CREATE OR REPLACE VIEW token_blacklist_active AS
SELECT *
FROM token
WHERE
  now() < expires_at;

-- Row Level Security (RLS) policies for multi-tenant isolation.
-- 1. Enable RLS on the table.
ALTER TABLE token ENABLE ROW LEVEL SECURITY;

-- 2. Define a policy to allow tenants to only see rows in their own workspace.
CREATE POLICY token_blacklist_tenant_isolation ON token
  FOR ALL
  USING (workspace_id = current_setting('app.workspace_id', TRUE)::uuid)
  WITH CHECK (workspace_id = current_setting('app.workspace_id', TRUE)::uuid);
```
