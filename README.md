# OxideAuth

Rust - Actix Web authorization server

## Psql Commands

- connets: `psql -h localhost -p 5432 -W -U test_user -d test_db`
- list databases: `\l`
- list tables: `\dt`
- show table columns: `dS {tablename}`

## TODO:

### Models

- update models to have crud functions on struct to abstract away database queries
- create ApiError generic Http response to respond to model errors

### API Error response

- limit auth error response information
- return correct error codes
- update return messages
  - `roles/delete-role`

### Default Roles

- prevent default roles and permission deletes

### Authorization

- create Auth struct which holds jwt secret that can be added to AppData
- add auth component to Data<AppData>, which can be accessed on each route
- create authorize method which takes Vec<String> to validate token has correct permissions for given endpoint

### Users

- implement users endpoints
  - user list

### Services

- create service struct
- implement services endpoints
  - register/delete service
  - list permissions from list of roles

### Caching

- create Redis cache to store tokens/permissions in cache to return faster on permission/role requests from services

### Token

- create token in database
- save/revoke tokens on login and logout in database/redis
- check provided tokens against database/redis

### OAuth

- add provider field to account: `local` | `github` | `facebook` | `google` ...
- create oath endpoints

### Database Updates

- change all pool: SqlitePool parameters to accept PgPool
- change all query methods that contain multiple queries to group all queries and run one transaction against the database

### DB query optimizations

### Pagination

- paginate Role list, LIMIT on db query
- paginate Account list, LIMIT on db query

#### Permission Bindings

- create db optimizations for permission_bindings, query should take Vec<String>, combine transactions and run only once to assign permission bindings for all permission to a single role

#### Role Bindings

- create db optimizations for role_bindings, query should take Vec<Role>, combine transactions and run only once to assign role binding for all roles to a single account

### Tests

- database query integration tests
- actix web endpoints integration tests
- unit tests
- utils
- models
