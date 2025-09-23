-- migrations/05_credential.sql
CREATE TABLE IF NOT EXISTS
  credential (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    account_id UUID NOT NULL, -- who
    namespace_id UUID NOT NULL, -- where (tenant)
    kind credential_kind NOT NULL, -- how
    provider TEXT, -- 'local','google','github','saml',...
    provider_id TEXT, -- external subject/user id (for oauth/sso)
    login_email TEXT, -- email for password or IdP email
    password_hash TEXT, -- only for kind='password'
    status TEXT NOT NULL DEFAULT 'active', -- 'active'|'revoked'|'pending'
    last_used_at TIMESTAMPTZ,
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
    CONSTRAINT cred_account_fk FOREIGN KEY (account_id) REFERENCES account (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT cred_namespace_fk FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT cred_audit_is_object CHECK (jsonb_typeof(audit) = 'object')
  );

-- Auth-path indexes 
-- only one 'password' kind credential per namespace
CREATE INDEX IF NOT EXISTS cred_password_lookup_idx ON credential (namespace_id, lower(login_email))
WHERE
  kind = 'password'
  AND status = 'active'
  AND login_email IS NOT NULL;

CREATE INDEX IF NOT EXISTS cred_oauth_lookup_idx ON credential (namespace_id, provider, provider_id)
WHERE
  kind IN ('oauth', 'sso')
  AND status = 'active'
  AND provider_id IS NOT NULL;

CREATE UNIQUE INDEX cred_pw_unique_ns_email ON credential (namespace_id, lower(login_email))
WHERE
  kind = 'password'
  AND status = 'active'
  AND login_email IS NOT NULL;

CREATE UNIQUE INDEX cred_oauth_unique_ns ON credential (namespace_id, provider, provider_id)
WHERE
  kind IN ('oauth', 'sso')
  AND provider_id IS NOT NULL;