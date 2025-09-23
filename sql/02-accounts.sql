-- Accounts
INSERT INTO
  account (
    id,
    email,
    password_hash,
    name,
    acc_type,
    provider,
    verified,
    enabled,
    created_by,
    updated_by,
    created_at,
    updated_at
  )
VALUES
  (
    '00000000-0000-0000-0000-000000000001',
    'owner@example.com',
    'hash_owner',
    'Owner User',
    'owner',
    'local',
    TRUE,
    TRUE,
    '00000000-0000-0000-0000-000000000001',
    NULL,
    now(),
    NULL
  ),
  (
    '00000000-0000-0000-0000-000000000002',
    'admin@example.com',
    'hash_admin',
    'Admin User',
    'admin',
    'local',
    TRUE,
    TRUE,
    '00000000-0000-0000-0000-000000000001',
    NULL,
    now(),
    NULL
  ),
  (
    '00000000-0000-0000-0000-000000000003',
    'user@example.com',
    'hash_user',
    'Normal User',
    'user',
    'local',
    TRUE,
    TRUE,
    '00000000-0000-0000-0000-000000000001',
    NULL,
    now(),
    NULL
  );