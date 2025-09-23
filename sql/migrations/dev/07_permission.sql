-- migrations/07_permission.sql
CREATE TABLE IF NOT EXISTS
  permission (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    namespace_id UUID NOT NULL, -- permission scope matches namespace
    name TEXT NOT NULL, -- e.g. 'project.read', 'project.write'
    code TEXT, -- optional short key
    description TEXT,
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
    CONSTRAINT perm_namespace_fk FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT perm_meta_is_object CHECK (jsonb_typeof(meta) = 'object'),
    CONSTRAINT perm_audit_is_object CHECK (jsonb_typeof(audit) = 'object'),
    CONSTRAINT permission_namespace_name_key UNIQUE (namespace_id, name)
    -- Optional alternative/additional:
    -- , CONSTRAINT permission_namespace_code_key UNIQUE (namespace_id, code)
  );