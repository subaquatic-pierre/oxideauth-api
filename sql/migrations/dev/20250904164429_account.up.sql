-- =========================
-- START: account
-- =========================
CREATE TABLE IF NOT EXISTS
  account (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    -- Identity
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    acc_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_id TEXT,
    description TEXT,
    image_url TEXT,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- Scope
    -- TODO: MUST ADD NOT NULL CONSTRAINT
    namespace_id UUID,
    project_id UUID,
    -- Free-form
    tags TEXT[] NOT NULL DEFAULT '{}',
    meta JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Audit
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID,
    updated_at TIMESTAMPTZ,
    -- ---------- Constraints ----------
    CONSTRAINT account_email_key UNIQUE (email),
    CONSTRAINT account_namespace_id_fkey FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT account_project_id_fkey FOREIGN KEY (project_id) REFERENCES project (id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT account_created_by_fkey FOREIGN KEY (created_by) REFERENCES account (id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT account_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES account (id) ON UPDATE CASCADE ON DELETE SET NULL,
    CONSTRAINT account_meta_is_object CHECK (jsonb_typeof(meta) = 'object')
  );

-- Helpful indexes
CREATE INDEX IF NOT EXISTS account_namespace_id_idx ON account (namespace_id);

CREATE INDEX IF NOT EXISTS account_project_id_idx ON account (project_id);

CREATE INDEX IF NOT EXISTS account_created_by_idx ON account (created_by);

CREATE INDEX IF NOT EXISTS account_updated_by_idx ON account (updated_by);

CREATE INDEX IF NOT EXISTS account_created_at_desc_idx ON account (created_at DESC);

CREATE INDEX IF NOT EXISTS account_updated_at_desc_idx ON account (updated_at DESC);

-- Tags containment (tags @> ARRAY['foo'])
CREATE INDEX IF NOT EXISTS account_tags_gin ON account USING GIN (tags);

-- Meta containment (meta @> '{"k":"v"}')
CREATE INDEX IF NOT EXISTS account_meta_gin ON account USING GIN (meta jsonb_path_ops);

-- Optional provider pair uniqueness (uncomment if desired)
-- CREATE UNIQUE INDEX IF NOT EXISTS account_provider_provider_id_key
--   ON account (provider, provider_id) WHERE provider_id IS NOT NULL;
-- Ensure namespace_id matches project.namespace_id when project_id is set
DROP TRIGGER IF EXISTS account_ns_project_chk ON account;

CREATE TRIGGER account_ns_project_chk BEFORE INSERT
OR
UPDATE ON account FOR EACH ROW
EXECUTE FUNCTION enforce_ns_matches_project ();

-- If you use OAuth-style logins, this is usually desirable:
-- CREATE UNIQUE INDEX IF NOT EXISTS account_provider_provider_id_key
--   ON account (provider, provider_id) WHERE provider_id IS NOT NULL;