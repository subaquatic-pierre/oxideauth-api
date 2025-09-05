-- Roles
INSERT INTO
  role (id, name, description)
VALUES
  (
    '10000000-0000-0000-0000-000000000001',
    'owner',
    'System owner with full access'
  ),
  (
    '10000000-0000-0000-0000-000000000002',
    'admin',
    'Administrator role'
  ),
  (
    '10000000-0000-0000-0000-000000000003',
    'user',
    'Standard user role'
  );

-- Permissions
INSERT INTO
  permission (id, name, description)
VALUES
  (
    '20000000-0000-0000-0000-000000000001',
    'account:read',
    'Can read accounts'
  ),
  (
    '20000000-0000-0000-0000-000000000002',
    'account:write',
    'Can modify accounts'
  ),
  (
    '20000000-0000-0000-0000-000000000003',
    'service:use',
    'Can use services'
  );

INSERT INTO
  permission_role (role_id, permission_name)
VALUES
  (
    '10000000-0000-0000-0000-000000000001',
    'account:read'
  ),
  (
    '10000000-0000-0000-0000-000000000001',
    'account:write'
  ),
  (
    '10000000-0000-0000-0000-000000000001',
    'service:use'
  ),
  (
    '10000000-0000-0000-0000-000000000002',
    'account:read'
  ),
  (
    '10000000-0000-0000-0000-000000000002',
    'service:use'
  ),
  (
    '10000000-0000-0000-0000-000000000003',
    'service:use'
  );

-- Role bindings (accounts → roles)
INSERT INTO
  role_account (account_id, role_id)
VALUES
  (
    '00000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000001'
  ),
  (
    '00000000-0000-0000-0000-000000000002',
    '10000000-0000-0000-0000-000000000002'
  ),
  (
    '00000000-0000-0000-0000-000000000003',
    '10000000-0000-0000-0000-000000000003'
  );