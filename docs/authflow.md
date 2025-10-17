# Authentication -> Authorization Flow

- request comes into http handler
- Authentication::init_context() -> CoreContext middle ware is applied to each request
- context is passed as first argument to each service method
- within service methods context is Authorized against AuthorizationService

TODO:

- define context struct
  -- membership on context
  -- multiple Roles per membership
  -- should aggregate permissions
- define JWT token struct
