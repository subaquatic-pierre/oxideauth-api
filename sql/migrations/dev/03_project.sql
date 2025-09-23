-- =========================
-- START: namespace
-- =========================
CREATE TABLE IF NOT EXISTS
  namespace (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    -- audit
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID,
    updated_at TIMESTAMPTZ,
    -- flexible settings
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- (Optional) guard the JSON shape
    CONSTRAINT namespace_config_is_object CHECK (jsonb_typeof(config) = 'object')
  );

-- =========================
-- START: project
-- =========================
CREATE TABLE IF NOT EXISTS
  project (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    namespace_id UUID NOT NULL,
    name TEXT NOT NULL,
    code TEXT, -- short identifier, optional
    description TEXT,
    -- audit
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID,
    updated_at TIMESTAMPTZ,
    -- per-project settings (override namespace.defaults in app layer)
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Free-form
    tags TEXT[] NOT NULL DEFAULT '{}',
    CONSTRAINT project_namespace_id_fkey FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT project_config_is_object CHECK (jsonb_typeof(config) = 'object')
  );