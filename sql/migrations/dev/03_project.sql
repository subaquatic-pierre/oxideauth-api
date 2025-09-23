-- migrations/03_project.sql
CREATE TABLE IF NOT EXISTS
  project (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    namespace_id UUID NOT NULL,
    name TEXT NOT NULL,
    code TEXT, -- optional short identifier/slug
    description TEXT,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
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
    -- constraints
    CONSTRAINT project_namespace_id_fkey FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT project_audit_is_object CHECK (jsonb_typeof(audit) = 'object'),
    CONSTRAINT project_config_is_object CHECK (jsonb_typeof(config) = 'object')
  );

-- Minimal helpful index:
CREATE UNIQUE INDEX IF NOT EXISTS project_namespace_name_key ON project (namespace_id, name);

-- (Add UNIQUE(namespace_id, code) later if you standardize `code`.)