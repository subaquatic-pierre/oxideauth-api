-- fixtures/01_account.sql
CREATE TABLE IF NOT EXISTS
  account (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    avatar_url TEXT,
    description TEXT,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
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
    CONSTRAINT account_audit_is_object CHECK (jsonb_typeof(audit) = 'object'),
    CONSTRAINT account_meta_is_object CHECK (jsonb_typeof(meta) = 'object')
  );

-- Optional global uniqueness (case-insensitive) 
CREATE UNIQUE INDEX IF NOT EXISTS account_email_lower_key ON account (lower(email))
WHERE
  email IS NOT NULL;