-- fixtures/08_membership.sql
-- Purpose: Seed memberships linking accounts to namespaces and projects.
-- Notes:
--   - Membership ties an account to a namespace or project.
--   - Scope is either 'namespace' or 'project'.
--   - Status defaults to 'active'.
--   - Roles will be attached later via membership_role (09).
INSERT INTO
  membership (
    id,
    account_id,
    namespace_id,
    scope,
    project_id,
    status,
    created_by
  )
VALUES
  -- Root account as sysadmin in global namespace
  (
    '60000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001', -- root account
    '10000000-0000-0000-0000-000000000001', -- global namespace
    'namespace',
    NULL,
    'active',
    '00000000-0000-0000-0000-000000000001'
  ),
  -- Owner account in global namespace
  (
    '60000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000002', -- owner account
    '10000000-0000-0000-0000-000000000001', -- global namespace
    'namespace',
    NULL,
    'active',
    '00000000-0000-0000-0000-000000000001'
  ),
  -- Owner account in acme namespace
  (
    '60000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000002', -- owner account
    '10000000-0000-0000-0000-000000000002', -- acme namespace
    'namespace',
    NULL,
    'active',
    '00000000-0000-0000-0000-000000000001'
  ),
  -- Test account in acme-demo project
  (
    '60000000-0000-0000-0000-000000000004',
    '00000000-0000-0000-0000-000000000003', -- test account
    '10000000-0000-0000-0000-000000000002', -- acme namespace
    'project',
    '20000000-0000-0000-0000-000000000002', -- acme-demo project
    'active',
    '00000000-0000-0000-0000-000000000002'
  );