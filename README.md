# OxideAuth

Rust - Actix Web authorization server

## Psql Commands

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

- database query integration tests
- actix web endpoints integration tests
- unit tests
- utils
- models
