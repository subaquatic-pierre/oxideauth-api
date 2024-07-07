# OxideAuth

Rust - Actix Web authorization server

## Psql Commands

- connets: `psql -h localhost -p 5432 -W -U test_user -d test_db`
- list databases: `\l`
- list tables: `\dt`
- show table columns: `dS {tablename}`

## TODO:

### API Error response

- limit auth error response information
- return correct error codes

### Default Roles

- prevent default roles and permission deletes

### Authorization

- validate token expiry
- check token_type claims against returned account type from database, ie. if claim is `service` then `Account::acc_type` should also be `service`
- create validate permissions endpoint for services to check permissions again given user token
- check reset password token on `update_self` endpoint for `accounts` collection

### OAuth

- add provider field to account: `local` | `github` | `facebook` | `google` ...
- create oath endpoints

### Services

- create service struct
- implement services endpoints
  - register/delete service
  - list permissions from list of roles

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
