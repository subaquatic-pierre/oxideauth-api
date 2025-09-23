-- fixtures/03_project.sql
-- Purpose: Seed initial projects under namespaces.
-- Notes:
--   - Projects are children of namespaces.
--   - Linked to the namespaces created in 02_namespace.sql.
--   - Created_by must reference a valid account (01_account.sql).
INSERT INTO
  project (id, namespace_id, name, description, created_by)
VALUES
  -- System bootstrap project inside the global namespace
  (
    '20000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000001', -- global namespace
    'system',
    'System bootstrap project (reserved)',
    '00000000-0000-0000-0000-000000000001'
  ),
  -- Example Acme project inside the Acme namespace
  (
    '20000000-0000-0000-0000-000000000002',
    '10000000-0000-0000-0000-000000000002', -- acme namespace
    'acme-demo',
    'Demo project for Acme Corp',
    '00000000-0000-0000-0000-000000000002'
  ) ON CONFLICT (id)
DO NOTHING;