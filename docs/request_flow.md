High-level request flow (summary)

Client sends request with JWT (claims sub = membership_id).

HTTP middleware/auth layer:

Verify JWT signature and expiry.

Extract membership_id from sub.

Load the membership row from membership store (including workspace_id, scope, project_id, status).

Optionally load the membership’s roles → permissions (or load lazily on-demand).

Build a CoreCtx (request-level context) that contains the authenticated Membership and a StoreCtx projection (contains workspace_id / project_id / membership_id / permission set).

Pass that CoreCtx into service methods.

Service calls store methods with &ctx.store (or ctx.into() if you already convert CoreCtx→StoreCtx).

Store query helpers (get, list, etc.) use StoreCtx scope values to inject WHERE conditions (workspace_id / project_id filters) automatically in SQL query generation.

Service may call ctx.ensure_permission("project.write") before mutating data.

This keeps enforcement centralized and prevents leaking cross-tenant data.
