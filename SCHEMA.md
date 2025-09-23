# Database Schema

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

### Namespace

1. Slug hygiene & canonicalization:

- Enforce lowercase + trimmed slug values via BEFORE INSERT/UPDATE trigger.
- Optional CHECK: restrict to alphanumeric and dashes only.
- Ensure uniqueness on slug is preserved (already has a unique constraint).

```sql
-- [1] Slug canonicalization (lower+trim), plus optional CHECK
-- Optional: enforce regex for slug (lowercase letters, numbers, dash only)
ALTER TABLE namespace
  ADD CONSTRAINT namespace_slug_format
  CHECK (slug ~ '^[a-z0-9-]+$');

-- BEFORE triggers to normalize slug
CREATE OR REPLACE FUNCTION namespace_slug_canonicalize()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.slug IS NULL THEN
    RAISE EXCEPTION 'slug cannot be NULL';
  END IF;
  NEW.slug := lower(btrim(NEW.slug));
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_namespace_slug_canonicalize_ins ON namespace;
CREATE TRIGGER trg_namespace_slug_canonicalize_ins
BEFORE INSERT ON namespace
FOR EACH ROW
EXECUTE FUNCTION namespace_slug_canonicalize();

DROP TRIGGER IF EXISTS trg_namespace_slug_canonicalize_upd ON namespace;
CREATE TRIGGER trg_namespace_slug_canonicalize_upd
BEFORE UPDATE OF slug ON namespace
FOR EACH ROW
EXECUTE FUNCTION namespace_slug_canonicalize();
```

2. Indexes for common lookups:

- `slug` should already be unique, but add btree index for fast lookups.
- Add GIN indexes for tags/meta if filtering or searching by them is frequent.

```sql
-- [2] Indexes for namespace
-- Ensure fast lookups by slug
CREATE INDEX IF NOT EXISTS idx_namespace_slug ON namespace(slug);

-- Optional: enable search/filtering by tags and meta
CREATE INDEX IF NOT EXISTS idx_namespace_tags_gin ON namespace USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_namespace_meta_gin ON namespace USING GIN(meta);
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

DROP TRIGGER IF EXISTS trg_namespace_set_updated_at ON namespace;
CREATE TRIGGER trg_namespace_set_updated_at
BEFORE UPDATE ON namespace
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
```

4. Security scaffolding:

- Enable Row-Level Security (RLS) for tenant isolation.
- Default SELECT policies to restrict access by namespace membership.

```sql
-- [4] Security scaffolding
ALTER TABLE namespace ENABLE ROW LEVEL SECURITY;

-- Example: allow row access only if current user is in the namespace
-- (replace with actual membership check function/policy)
-- CREATE POLICY namespace_tenant_isolation
--   ON namespace FOR SELECT
--   USING (auth_namespace_id() = id);
```

5. Data hygiene:

- Ensure `config` and `meta` are always JSON objects (already CHECK’d).
- (Optional) Add pg_jsonschema for stricter schema enforcement later.

```sql
-- [5] Data hygiene
-- Already enforced: config and meta are JSON objects.
-- Optional stricter schema validation (requires pg_jsonschema extension):
-- ALTER TABLE namespace
--   ADD CONSTRAINT namespace_config_schema
--   CHECK (jsonb_matches_schema(config, '<json schema>'));
```

### Project

1. Code hygiene & canonicalization:

- If `code` is standardized (slug-like), enforce lowercase + trimmed values via BEFORE INSERT/UPDATE trigger.
- Optional CHECK: restrict to alphanumeric and dashes only.
- Enforce per-namespace uniqueness once usage is consistent.

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

- Uniqueness on `(namespace_id, name)` already enforced.
- Optional: uniqueness on `(namespace_id, code)` if adopted.
- Add GIN indexes for tags/meta if filtering/searching is frequent.

```sql
-- [2] Indexes for project
-- Enforce per-namespace uniqueness of code
CREATE UNIQUE INDEX IF NOT EXISTS project_namespace_code_key
  ON project (namespace_id, code);

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

- Enable Row-Level Security (RLS) for tenant isolation by namespace_id.
- Add SELECT policies to restrict access to projects only within the user’s namespace(s).

```sql
-- [4] Security scaffolding
ALTER TABLE project ENABLE ROW LEVEL SECURITY;

-- Example: restrict to projects inside the current namespace
-- CREATE POLICY project_tenant_isolation
--   ON project FOR SELECT
--   USING (auth_namespace_id() = namespace_id);
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

5. Uniqueness & lookup indexes (per namespace):

- Keep **one active password credential per (namespace, login_email)**.
- Keep **one oauth/sso credential per (namespace, provider, provider_id)**.
- Add supporting non-unique filtered indexes for fast auth-path lookups.

```sql
-- [5] Lookup/uniqueness (already in your migration, included for completeness)
-- Active password uniqueness
CREATE UNIQUE INDEX IF NOT EXISTS cred_pw_unique_ns_email
  ON credential (namespace_id, lower(login_email))
  WHERE kind = 'password'
    AND status = 'active'
    AND login_email IS NOT NULL;

-- OAuth/SSO uniqueness
CREATE UNIQUE INDEX IF NOT EXISTS cred_oauth_unique_ns
  ON credential (namespace_id, provider, provider_id)
  WHERE kind IN ('oauth','sso')
    AND provider_id IS NOT NULL;

-- Lookup helpers
CREATE INDEX IF NOT EXISTS cred_password_lookup_idx
  ON credential (namespace_id, lower(login_email))
  WHERE kind = 'password'
    AND status = 'active'
    AND login_email IS NOT NULL;

CREATE INDEX IF NOT EXISTS cred_oauth_lookup_idx
  ON credential (namespace_id, provider, provider_id)
  WHERE kind IN ('oauth','sso')
    AND status = 'active'
    AND provider_id IS NOT NULL;
```

7. RLS scaffolding (per-tenant isolation):

- Enable RLS; restrict SELECT/UPDATE/DELETE to users operating within their `namespace_id`.
- Replace `auth_namespace_id()` with your session-resolved function/view for current tenant.

```sql
-- [7] Row-Level Security (RLS) scaffolding
ALTER TABLE credential ENABLE ROW LEVEL SECURITY;

-- Example SELECT policy by tenant
-- CREATE POLICY credential_tenant_select
--   ON credential FOR SELECT
--   USING (namespace_id = auth_namespace_id());

-- Example UPDATE/DELETE policy by tenant (and optionally by owner account)
-- CREATE POLICY credential_tenant_write
--   ON credential FOR UPDATE USING (namespace_id = auth_namespace_id())
--   WITH CHECK (namespace_id = auth_namespace_id());
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

- Prevent overriding core/system roles in non-global namespaces (e.g., `owner`, `editor`, `viewer`).
- Replace `is_global_namespace(id)` with your actual function/flag.

```sql
-- [2] Reserved names (example)
CREATE OR REPLACE FUNCTION role_reserved_name_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_reserved text[] := ARRAY['owner','editor','viewer'];
BEGIN
  IF lower(NEW.name) = ANY (v_reserved) AND NOT is_global_namespace(NEW.namespace_id) THEN
    RAISE EXCEPTION 'Reserved role "%" may only exist in global namespace', NEW.name;
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
BEFORE UPDATE OF name, namespace_id ON role
FOR EACH ROW
EXECUTE FUNCTION role_reserved_name_guard();
```

3. Indexes for common lookups:

- Uniqueness `(namespace_id, name)` already ensures fast equality lookups.
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

- Enable RLS; restrict access by `namespace_id`.
- Replace `auth_namespace_id()` with your actual tenant resolver.

```sql
-- [5] Row-Level Security
ALTER TABLE role ENABLE ROW LEVEL SECURITY;

-- Example: allow select within tenant
-- CREATE POLICY role_tenant_select
--   ON role FOR SELECT
--   USING (namespace_id = auth_namespace_id());

-- Example: allow write only within tenant
-- CREATE POLICY role_tenant_write
--   ON role FOR INSERT WITH CHECK (namespace_id = auth_namespace_id());
-- CREATE POLICY role_tenant_update
--   ON role FOR UPDATE USING (namespace_id = auth_namespace_id())
--   WITH CHECK (namespace_id = auth_namespace_id());
-- CREATE POLICY role_tenant_delete
--   ON role FOR DELETE USING (namespace_id = auth_namespace_id());
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

- Seed baseline roles in the global namespace, then allow tenant-level overrides.
- Provide idempotent upserts for standard roles.

```sql
-- [7] Seeding helpers (example; adapt to your bootstrap approach)
-- INSERT INTO role (namespace_id, name, description, created_by)
-- VALUES (global_namespace_id(), 'owner', 'Full control', system_account_id())
-- ON CONFLICT (namespace_id, name) DO UPDATE SET description = EXCLUDED.description;
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
  IF OLD.locked AND (TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND (OLD.name IS DISTINCT FROM NEW.name OR OLD.namespace_id IS DISTINCT FROM NEW.namespace_id))) THEN
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
- Optional uniqueness `(namespace_id, code)` if treated as alternative identifier.

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

-- Optional: enforce uniqueness per namespace
-- CREATE UNIQUE INDEX IF NOT EXISTS permission_namespace_code_key
--   ON permission (namespace_id, code);
```

3. Indexes for common lookups:

- `(namespace_id, name)` uniqueness already ensures fast lookups.
- Add `(namespace_id, code)` if used.
- Add GIN indexes for tags/meta if filtered frequently.

```sql
-- [3] Indexes
CREATE INDEX IF NOT EXISTS idx_permission_tags_gin ON permission USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_permission_meta_gin ON permission USING GIN(meta);
```

5. RLS scaffolding:

- Enable Row-Level Security to isolate by `namespace_id`.
- Replace `auth_namespace_id()` with your tenant resolver.

```sql
-- [5] Row-Level Security
ALTER TABLE permission ENABLE ROW LEVEL SECURITY;

-- Example: allow tenant-scoped reads
-- CREATE POLICY permission_tenant_select
--   ON permission FOR SELECT
--   USING (namespace_id = auth_namespace_id());

-- Example: allow tenant writes
-- CREATE POLICY permission_tenant_write
--   ON permission FOR INSERT WITH CHECK (namespace_id = auth_namespace_id());
-- CREATE POLICY permission_tenant_update
--   ON permission FOR UPDATE USING (namespace_id = auth_namespace_id())
--   WITH CHECK (namespace_id = auth_namespace_id());
-- CREATE POLICY permission_tenant_delete
--   ON permission FOR DELETE USING (namespace_id = auth_namespace_id());
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
  IF lower(NEW.name) = ANY (v_reserved) AND NOT is_global_namespace(NEW.namespace_id) THEN
    RAISE EXCEPTION 'Reserved permission "%" may only exist in global namespace', NEW.name;
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
BEFORE UPDATE OF name, namespace_id ON permission
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

- Seed baseline permissions in global namespace for core features.
- Provide idempotent upsert patterns.

```sql
-- [8] Seeding helpers (example)
-- INSERT INTO permission (namespace_id, name, description, created_by)
-- VALUES (global_namespace_id(), 'project.read', 'Read project data', system_account_id())
-- ON CONFLICT (namespace_id, name) DO UPDATE SET description = EXCLUDED.description;
```

### Role ↔ Permission (Join Table)

1. Enforce namespace consistency (`role.namespace_id = permission.namespace_id`):

- Prevent cross-namespace bindings by validating during INSERT/UPDATE.
- Use a BEFORE trigger for immediate feedback (simple and fast). Optionally add a CONSTRAINT TRIGGER DEFERRABLE INITIALLY DEFERRED if bulk loads need deferred checks.

SQL:

    -- [1] Namespace consistency guard
    CREATE OR REPLACE FUNCTION rp_namespace_guard()
    RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
      v_role_ns uuid;
      v_perm_ns uuid;
    BEGIN
      SELECT namespace_id INTO v_role_ns FROM role WHERE id = NEW.role_id;
      IF v_role_ns IS NULL THEN
        RAISE EXCEPTION 'role "%" not found', NEW.role_id;
      END IF;

      SELECT namespace_id INTO v_perm_ns FROM permission WHERE id = NEW.permission_id;
      IF v_perm_ns IS NULL THEN
        RAISE EXCEPTION 'permission "%" not found', NEW.permission_id;
      END IF;

      IF v_role_ns <> v_perm_ns THEN
        RAISE EXCEPTION 'Namespace mismatch: role(%) and permission(%)', v_role_ns, v_perm_ns;
      END IF;
      RETURN NEW;
    END;
    $$;

    DROP TRIGGER IF EXISTS trg_rp_namespace_guard_ins ON role_permission;
    CREATE TRIGGER trg_rp_namespace_guard_ins
    BEFORE INSERT ON role_permission
    FOR EACH ROW
    EXECUTE FUNCTION rp_namespace_guard();

    DROP TRIGGER IF EXISTS trg_rp_namespace_guard_upd ON role_permission;
    CREATE TRIGGER trg_rp_namespace_guard_upd
    BEFORE UPDATE OF role_id, permission_id ON role_permission
    FOR EACH ROW
    EXECUTE FUNCTION rp_namespace_guard();

    -- Alternative (deferred, uncomment to use instead of BEFORE triggers):
    -- CREATE CONSTRAINT TRIGGER rp_namespace_guard_def
    -- AFTER INSERT OR UPDATE OF role_id, permission_id ON role_permission
    -- DEFERRABLE INITIALLY DEFERRED
    -- FOR EACH ROW EXECUTE FUNCTION rp_namespace_guard();

2. RLS scaffolding (tenant isolation by namespace via role/permission join):

- Enable RLS on the join table and use subqueries to tie rows to a tenant namespace.
- Replace auth_namespace_id() with your resolver.

SQL:

    -- [2] Row-Level Security
    ALTER TABLE role_permission ENABLE ROW LEVEL SECURITY;

    -- SELECT allowed if the linked role (or permission) is in the current namespace
    -- (pick one predicate style; role-based is typical)
    -- CREATE POLICY rp_tenant_select
    --   ON role_permission FOR SELECT
    --   USING (
    --     EXISTS (
    --       SELECT 1 FROM role r
    --       WHERE r.id = role_permission.role_id
    --         AND r.namespace_id = auth_namespace_id()
    --     )
    --   );

    -- INSERT allowed only if role is in-tenant
    -- CREATE POLICY rp_tenant_insert
    --   ON role_permission FOR INSERT
    --   WITH CHECK (
    --     EXISTS (
    --       SELECT 1 FROM role r
    --       WHERE r.id = role_permission.role_id
    --         AND r.namespace_id = auth_namespace_id()
    --     )
    --   );

    -- UPDATE/DELETE similarly constrained
    -- CREATE POLICY rp_tenant_update
    --   ON role_permission FOR UPDATE
    --   USING (EXISTS (SELECT 1 FROM role r WHERE r.id = role_permission.role_id AND r.namespace_id = auth_namespace_id()))
    --   WITH CHECK (EXISTS (SELECT 1 FROM role r WHERE r.id = role_permission.role_id AND r.namespace_id = auth_namespace_id()));

    -- CREATE POLICY rp_tenant_delete
    --   ON role_permission FOR DELETE
    --   USING (EXISTS (SELECT 1 FROM role r WHERE r.id = role_permission.role_id AND r.namespace_id = auth_namespace_id()));

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

- Seed baseline role/permission bindings in the global namespace.
- Use idempotent upserts to avoid duplicates on re-run.

SQL:

    -- [5] Seeding example (adjust to your bootstrap helpers)
    -- WITH perm AS (
    --   SELECT id FROM permission WHERE namespace_id = global_namespace_id() AND name = 'project.read'
    -- ), role_row AS (
    --   SELECT id FROM role WHERE namespace_id = global_namespace_id() AND name = 'viewer'
    -- )
    -- INSERT INTO role_permission (role_id, permission_id)
    -- SELECT role_row.id, perm.id FROM role_row, perm
    -- ON CONFLICT (role_id, permission_id) DO NOTHING;

6. Performance notes:

- Existing indexes (role_id) and (permission_id) are adequate for join paths.
- If you frequently query by both, a covering index on (role_id, permission_id) is redundant with the PK, so no need to add one.
