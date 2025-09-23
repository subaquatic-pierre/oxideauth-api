-- migrations/04_enums.sql
DO $$ BEGIN
  CREATE TYPE credential_kind AS ENUM ('password','oauth','sso','api_key');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE membership_scope AS ENUM ('namespace','project');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE credential_status AS ENUM ('active','revoked','pending');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE membership_status AS ENUM ('invited','active','suspended');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;