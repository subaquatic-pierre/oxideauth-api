SELECT
  pg_terminate_backend(pid)
FROM
  pg_stat_activity
WHERE
  usename = 'test_user'
  OR datname = 'test_db';

DROP DATABASE IF EXISTS test_db;

DROP USER IF EXISTS test_user;

CREATE USER test_user PASSWORD 'password';

CREATE DATABASE test_db owner test_user ENCODING = 'UTF-8';