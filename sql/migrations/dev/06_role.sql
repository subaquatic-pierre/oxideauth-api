-- migrations/06_role.sql
CREATE TABLE IF NOT EXISTS
  role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    namespace_id UUID NOT NULL, -- catalog is per namespace (incl. global)
    name TEXT NOT NULL, -- 'owner','editor','viewer',...
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
    CONSTRAINT role_namespace_fk FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT role_meta_is_object CHECK (jsonb_typeof(meta) = 'object'),
    CONSTRAINT role_audit_is_object CHECK (jsonb_typeof(audit) = 'object'),
    CONSTRAINT role_namespace_name_key UNIQUE (namespace_id, name)
  );