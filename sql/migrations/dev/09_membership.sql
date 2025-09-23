-- migrations/09_membership.sql
CREATE TABLE IF NOT EXISTS
  membership (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    account_id UUID NOT NULL,
    namespace_id UUID NOT NULL,
    scope membership_scope NOT NULL, -- 'namespace' | 'project'
    project_id UUID, -- set only when scope='project'
    status membership_status NOT NULL DEFAULT 'active', -- 'invited'|'active'|'suspended'
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
    CONSTRAINT mem_account_fk FOREIGN KEY (account_id) REFERENCES account (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT mem_namespace_fk FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT mem_project_fk FOREIGN KEY (project_id) REFERENCES project (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT membership_meta_is_object CHECK (jsonb_typeof(meta) = 'object'),
    CONSTRAINT membership_audit_is_object CHECK (jsonb_typeof(audit) = 'object'),
    -- Shape guard: project_id presence matches scope
    CONSTRAINT membership_scope_shape_chk CHECK (
      (
        scope = 'namespace'
        AND project_id IS NULL
      )
      OR (
        scope = 'project'
        AND project_id IS NOT NULL
      )
    )
  );

-- Intent-expressing partial uniques (enable when ready)
CREATE UNIQUE INDEX IF NOT EXISTS membership_ns_unique ON membership (account_id, namespace_id)
WHERE
  scope = 'namespace';

CREATE UNIQUE INDEX IF NOT EXISTS membership_proj_unique ON membership (account_id, project_id)
WHERE
  scope = 'project';

-- Lookups used in auth
CREATE INDEX IF NOT EXISTS membership_by_ns ON membership (namespace_id, account_id)
WHERE
  scope = 'namespace'
  AND status = 'active';

CREATE INDEX IF NOT EXISTS membership_by_proj ON membership (project_id, account_id)
WHERE
  scope = 'project'
  AND status = 'active';