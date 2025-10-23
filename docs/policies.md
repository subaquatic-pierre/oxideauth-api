# Roles, Permissions, and Policies — Keeping It Simple

## Roles and Permissions as the Foundation

- **Role = named bundle of permissions**  
  Example: `Editor` → `["task:create", "task:update"]`
- **Membership = account + role assignment**  
  Applied at the workspace or project level.
- This forms the baseline RBAC everyone understands.

## Policy as a Filter/Overlay

- Policies do **not** grant new actions.
- They only **constrain or refine** what is already allowed by RBAC.
- Conceptually:

Allowed? = (Role grants permission) AND (Policy doesn’t block it)

- A user never _gains_ something from a policy, only loses it (or occasionally gets a scoped exception).

## Explicit Scope

- **Workspace policies** apply to all projects in the workspace.
- **Project policies** apply only to that project.
- **Membership policies** apply only to a single member.

## Keep the Policy Language Simple

- Avoid a heavy DSL like AWS IAM.
- Start with simple JSON or key-value conditions.
- Examples:
- `owner_only: true`
- `time_window: "09:00–18:00"`
- `status != archived`

## Summary

- **Roles & permissions = structural access.**
- **Policies = contextual constraints.**
- This avoids the AWS-style complexity where policies feel like a second, parallel permission system.

So the mental model becomes:

RBAC (Role + Permissions) = the ceiling of what a member could do.

Policy (scoped constraints) = limitations that bring that ceiling down in certain contexts.

That way, you always know:

If RBAC says “no” → it’s no (policy can’t give more).

If RBAC says “yes” → check policies → it may still become no under certain conditions.

### AWS Policy Pitfall

Nice and clean, no AWS-style “roles vs policies vs attached policies” spaghetti.

## Example

### Without Policy (RBAC only)

- Role: **Editor**
- Permissions: `["task:create", "task:update"]`

➡️ Result:  
Any user with the **Editor** role can create or update **any** task in the project.

### With Policy (Scoped Constraint)

- Role: **Editor**
- Permissions: `["task:create", "task:update"]`
- Policy (project scope):
- Target: `task:update`
- Condition: `resource.owner_id == subject.id`
- Effect: `allow`

➡️ Result:  
Editors can still create tasks, but they can **only update tasks they personally created**.
