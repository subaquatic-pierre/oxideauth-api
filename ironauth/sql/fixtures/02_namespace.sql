-- fixtures/02_namespace.sql
-- Purpose: Seed initial namespaces for system bootstrap.
-- Notes:
--   - Namespaces represent tenants/domains.
--   - The global namespace (id=...001) acts as the system root.
--   - Owned by root or owner accounts from fixtures/01_account.sql.
INSERT INTO
  namespace (id, name, slug, description, created_by)
VALUES
  -- Global/system namespace
  (
    '10000000-0000-0000-0000-000000000001',
    'global',
    'global',
    'System-wide global namespace',
    '00000000-0000-0000-0000-000000000001'
  ),
  -- Example tenant namespace (owned by owner account)
  (
    '10000000-0000-0000-0000-000000000002',
    'registrar',
    'registrar',
    'Registrar Domain To List all Namespaces',
    '00000000-0000-0000-0000-000000000002'
  ),
  (
    '10000000-0000-0000-0000-000000000003',
    'acme',
    'acme',
    'Example tenant namespace for Acme Corp',
    '00000000-0000-0000-0000-000000000002'
  ) ON CONFLICT (id)
DO NOTHING;