# OxideAuth

Rust - Actix Web authorization server

## Psql Commands

- reset database: `sqlx database reset`
- connets: `psql -h localhost -p 5432 -W -U test_user -d test_db`
- list databases: `\l`
- list tables: `\dt`
- show table columns: `dS {tablename}`

## TODO:

### Accounts

- add `verified` field to account
- add `enabled` field to account

### API Error response

- limit auth error response information
- return correct error codes
- return correct error messages

### Default Roles

- prevent default `roles` and `permissions` from being edited or deleted

### Authorization

- validate account is enabled and verified
- validate token expiry
- check token_type claims against returned account type from database, ie. if claim is `service` then `Account::acc_type` should also be `service`
- create validate permissions endpoint for services to check permissions again given user token
- check reset password token on `update_self` endpoint for `accounts` collection

### OAuth

- ensure cannot login with password if password_hash is empty in database
- add provider field to account: `local` | `github` | `facebook` | `google` ...
- create oath endpoints

### Caching

- create Redis cache to store tokens/permissions in cache to return faster on permission/role requests from services

### Token

- add token_type to TokenClaims, `user`|`service`|`reset_password`|`register`
- create reset password token
- create token in database
- save/revoke tokens on login and logout in database/redis
- check provided tokens against database/redis
- implement refresh token endpoint
- implement reset password token endpoint, write token to database

### DB query optimizations

### Pagination

- paginate Role list, LIMIT on db query
- paginate Account list, LIMIT on db query

### Tests

#### Run Tests

##### All query methods

```sh
cargo test --  --test-threads=1 store::queries --no-capture
```

- database query integration tests
- actix web endpoints integration tests
- unit tests
- utils
- models

### Database & Migration Workflow

This project uses sqlx-cli with Cargo aliases for managing development, test, and production databases. All configuration is defined in `.cargo/config.toml`.

1. Setup

---

- Copy the example config into place:
  cp .cargo/config.example.toml .cargo/config.toml

- Fill in the empty values with your real database URLs, AWS credentials, and secrets.

- IMPORTANT: `.cargo/config.toml` is gitignored — never commit secrets to the repository.

2. Migration directories

---

Each environment has its own migration history to prevent conflicts:

    sql/migrations/dev/
    sql/migrations/test/
    sql/migrations/prod/

- Development and Test: safe to reset or revert.
- Production: only run forward migrations. Reset or revert here risks data loss.

3. Aliases

---

The following Cargo aliases are provided in `.cargo/config.toml`:

Development
cargo db-dev-add create_users # create new migration in dev/
cargo db-dev-run # run pending migrations
cargo db-dev-info # show applied/pending migrations
cargo db-dev-revert # revert the last migration
cargo db-dev-reset # drop & recreate db_dev

Test
cargo db-test-add init_schema
cargo db-test-run
cargo db-test-info
cargo db-test-revert
cargo db-test-reset

Production
cargo db-prod-add add_index_to_accounts -r # reversible template
cargo db-prod-run
cargo db-prod-info
cargo db-prod-revert # USE ONLY IN EMERGENCIES

5. Notes

---

- The [env] section in `.cargo/config.toml` provides variables to your Rust application (`cargo run`, `cargo test`, etc.), but sqlx-cli ignores them.
- That is why aliases explicitly include the `--database-url`.
- Keep your actual secrets local; only `config.example.toml` is shared.

## Database Dump

```sh
pg_dump -h localhost -U oxideauth -d db_dev -F p > db_bak.sql
```

## Schema Dump

```sh
pg_dump -h localhost -U oxideauth -d db_dev -s > schema.sql
```

## Database Dump

```sh
pg_dump -h localhost -U oxideauth -d db_dev -F p > db_bak.sql
```

## Write DBML

```sh
db2dbml postgres 'postgresql://oxideauth:password@localhost:5432/db_dev?schemas=public' -o schema.dbml
```

##
