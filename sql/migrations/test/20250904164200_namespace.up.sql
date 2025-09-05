-- BOOTSTRAP MIGRATION
-- EXTENSIONS
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- FUNCTIONS
CREATE
OR REPLACE FUNCTION enforce_ns_matches_project () RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.project_id IS NOT NULL THEN
    PERFORM 1
      FROM project p
     WHERE p.id = NEW.project_id
       AND p.namespace_id = NEW.namespace_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION
        'namespace_id (%) does not match project.namespace_id for project_id (%)',
        NEW.namespace_id, NEW.project_id
        USING ERRCODE = '23514'; -- check_violation
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

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

-- Helpful indexes
CREATE INDEX IF NOT EXISTS namespace_created_at_desc_idx ON namespace (created_at DESC);

CREATE INDEX IF NOT EXISTS namespace_updated_at_desc_idx ON namespace (updated_at DESC);

-- If you’ll sometimes search inside config, add GIN; otherwise skip:
CREATE INDEX IF NOT EXISTS namespace_config_gin ON namespace USING GIN (config);

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
    CONSTRAINT project_namespace_id_fkey FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT project_config_is_object CHECK (jsonb_typeof(config) = 'object')
  );

-- Common indexes
CREATE UNIQUE INDEX IF NOT EXISTS project_namespace_name_key ON project (namespace_id, name);

CREATE INDEX IF NOT EXISTS project_namespace_id_idx ON project (namespace_id);

CREATE INDEX IF NOT EXISTS project_created_at_desc_idx ON project (created_at DESC);

CREATE INDEX IF NOT EXISTS project_updated_at_desc_idx ON project (updated_at DESC);

-- Optional if you’ll occasionally search JSON:
-- CREATE INDEX IF NOT EXISTS project_config_gin ON project USING GIN (config);
-- Ensures NEW.namespace_id matches the namespace of NEW.project_id (when set)
-- TODO: NEED TO APPLY CONSTRAINS ON namespace TABLE
-- CONSTRAINT namespace_created_by_fkey FOREIGN KEY (created_by) REFERENCES account (id) ON UPDATE CASCADE ON DELETE RESTRICT,
-- CONSTRAINT namespace_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES account (id) ON UPDATE CASCADE ON DELETE SET NULL,
-- TODO: NEED TO APPLY CONSTRAINS ON project TABLE
-- CONSTRAINT project_created_by_fkey FOREIGN KEY (created_by) REFERENCES account (id) ON UPDATE CASCADE ON DELETE RESTRICT,
--     CONSTRAINT project_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES account (id) ON UPDATE CASCADE ON DELETE SET NULL,