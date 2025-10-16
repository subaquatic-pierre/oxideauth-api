# Roles, Permissions — Keeping It Simple

## Roles and Permissions as the Foundation

- **Role = named bundle of permissions**  
  Example: `Editor` → `["task:create", "task:update"]`
- **Membership = account + role assignment**  
  Applied at the namespace or project level.
- This forms the baseline RBAC everyone understands.

## Example

- Role: **Editor**
- Permissions: `["task:create", "task:update"]`

➡️ Result:  
Any user with the **Editor** role can create or update **any** task in the project.
