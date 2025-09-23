-- migrations/03_project.sql
-- Purpose: Define projects as child entities within a namespace. Projects act as
--   logical containers for resources, tasks, memberships, and roles scoped below a namespace.
-- Notes:
--   - Each project belongs to exactly one namespace (`namespace_id` FK).
--   - `name` is human-readable; uniqueness is enforced per namespace.
--   - `code` is an optional short identifier (slug-like) and can be made unique within
--     a namespace if standardized (see TODOs).
--   - `config` is a JSONB object for per-project settings (feature flags, metadata).
--   - `created_by` / `updated_by` are audit fields; FK constraints can be added later
--     to avoid bootstrap issues (see TODOs).
CREATE TABLE IF NOT EXISTS
  project (
    -- Primary key
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    -- Parent namespace (cascades on delete to clean up child projects automatically)
    namespace_id UUID NOT NULL,
    -- Project identity
    name TEXT NOT NULL,
    -- Optional short identifier (slug/code). Uniqueness per-namespace can be enforced separately.
    code TEXT,
    description TEXT,
    -- Config blob for project-specific structured settings (validated below as JSON object)
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- START Meta & Tags
    -- Lightweight labels for search/segments
    tags TEXT[] NOT NULL DEFAULT '{}',
    -- Freeform structured metadata; validated as JSON object
    meta JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- END Meta & Tags
    -- START Audit
    -- Who created this row and when. `created_by` is NOT NULL to maintain audit trail.
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Who last updated this row and when. `updated_by` may be NULL if never updated.
    updated_by UUID,
    updated_at TIMESTAMPTZ,
    -- Flexible audit payload for origin/IP/UA/etc; enforced to be a JSON object.
    audit JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- END Audit
    -- ---------- Constraints ----------
    CONSTRAINT project_namespace_id_fkey FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE CASCADE,
    -- Enforce JSON object shape
    CONSTRAINT project_audit_is_object CHECK (jsonb_typeof(audit) = 'object'),
    CONSTRAINT project_config_is_object CHECK (jsonb_typeof(config) = 'object')
    -- (FKs for created_by/updated_by → account(id) can be added in later migration;
    --  avoid circular bootstrap problems initially.)
  );

-- =========================
-- Indexes
-- =========================
-- Ensure per-namespace uniqueness of project names
CREATE UNIQUE INDEX IF NOT EXISTS project_namespace_name_key ON project (namespace_id, name);

-- Optional: enforce per-namespace uniqueness of code
-- CREATE UNIQUE INDEX IF NOT EXISTS project_namespace_code_key
--   ON project (namespace_id, code);