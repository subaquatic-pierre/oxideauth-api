-- migrations/02_namespace.sql
CREATE TABLE IF NOT EXISTS
  namespace (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    name TEXT UNIQUE NOT NULL,
    slug TEXT UNIQUE NOT NULL,
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
    CONSTRAINT namespace_audit_is_object CHECK (jsonb_typeof(audit) = 'object'),
    CONSTRAINT namespace_config_is_object CHECK (jsonb_typeof(config) = 'object')
  );