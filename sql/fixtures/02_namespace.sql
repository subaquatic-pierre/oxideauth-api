-- fixtures/02_namespace.sql
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM namespace WHERE name = 'global'
  ) THEN
    INSERT INTO namespace (id, name, description,  audit, config)
    VALUES ('00000000-0000-0000-0000-000000000001','global', 'Global/Platform namespace', '{}'::jsonb, '{}'::jsonb);
  END IF;
END$$;