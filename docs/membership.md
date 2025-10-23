# Workspace and Project Membership Behavior

## Default Membership

- Every user must have a **workspace-level membership** in order to act inside a workspace.
- This membership is unique per `(account_id, workspace_id)`.
- A **default membership** is created when a user first joins a workspace.
- This default membership is automatically assigned the **`Member` role** (or whatever base role name you choose).

## Default Role: `Member`

- The `Member` role represents **minimal access** inside a workspace.
- Typical permissions:
  - Can see workspace metadata (name, description).
  - Can view a list of projects inside the workspace.
  - Cannot create, update, or delete anything without further role assignments.
- This ensures that _registering_ to a workspace always results in a valid membership, but with only safe, non-destructive access.

## Role Scoping

- **Workspace-level role assignment**

  - Attaches directly to the workspace membership.
  - Grants permissions across **all projects** in that workspace.
  - Example: `Editor` at workspace scope → user can edit tasks in any project in the workspace.

- **Project-level role assignment**
  - Attaches to a project membership (which itself hangs off the workspace membership).
  - Grants permissions only for that **specific project**.
  - Example: `Editor` at project scope → user can edit tasks in **that one project**, but not others.

## Effective Permissions

1. **Default**: User joins → gets workspace membership with `Member` role.
2. **Workspace role**: If given `Editor` (workspace scope), applies to all projects.
3. **Project role**: If user only has `Member` workspace role, you can assign `Editor` at project scope to grant elevated permissions **only in that project**.
4. **Policies**: May constrain or override permissions, but never add new ones.

## Benefits of Default Membership

- Ensures all users have a **hard scope** by default.
- Simplifies registration: "join workspace" → you’re a member, but with minimal access.
- Makes it explicit when additional project-specific access is needed.
- Prevents dangling access (no project membership without workspace membership).

# Unified Roles and Membership Model

## Core Idea

- **One `roles` table** for everything.
- **Permissions** attached to roles as usual.
- **Memberships** are **workspace-level** (required).
- **ProjectMemberships** hang off a workspace membership for per-project scoping.
- **Role assignments** use a single table that can point to **either** a workspace membership **or** a project membership (but not both).

## Schema

```sql
-- Roles & permissions
CREATE TABLE roles (
  id          UUID PRIMARY KEY,
  name        TEXT UNIQUE NOT NULL,
  description TEXT
);

CREATE TABLE permissions (
  name        TEXT PRIMARY KEY,
  description TEXT
);

CREATE TABLE permission_bindings (
  role_id        UUID REFERENCES roles(id) ON DELETE CASCADE,
  permission_name TEXT REFERENCES permissions(name) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_name)
);

-- Workspace membership (required to act inside a workspace)
CREATE TABLE memberships (
  id           UUID PRIMARY KEY,
  account_id   UUID NOT NULL,      -- → accounts(id)
  workspace_id UUID NOT NULL,      -- → workspaces(id)
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (account_id, workspace_id)
);

-- Optional per-project scoping
CREATE TABLE project_memberships (
  id              UUID PRIMARY KEY,
  membership_id   UUID NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
  project_id      UUID NOT NULL,   -- → projects(id)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (membership_id, project_id)
);

-- Unified role assignment (either workspace OR project scope)
CREATE TABLE role_assignments (
  id                     UUID PRIMARY KEY,
  role_id                UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  membership_id          UUID     REFERENCES memberships(id) ON DELETE CASCADE,
  project_membership_id  UUID     REFERENCES project_memberships(id) ON DELETE CASCADE,

  -- Exactly one of the two must be set
  CHECK (
    (membership_id IS NOT NULL AND project_membership_id IS NULL) OR
    (membership_id IS NULL AND project_membership_id IS NOT NULL)
  ),

  -- Prevent duplicate assignments at the same scope
  UNIQUE (role_id, membership_id),
  UNIQUE (role_id, project_membership_id)
);
```

## Benefits

- **One roles catalog** for the whole system (no split roles).
- Assign a role:
  - **to a workspace** → set `membership_id`.
  - **to a project** → set `project_membership_id`.
- No “immortal main project.” Admin lives at **workspace** by assigning an admin role at the workspace scope.

## Auth Resolution

1. Ensure user has a **membership** in `resource.workspace_id`. If not → **deny**.
2. Gather **workspace roles** from `role_assignments` where `membership_id = user.membership.id`.
3. If a workspace role grants the action → **allow** (unless a policy later denies).
4. Else, if a **project_membership** exists for `resource.project_id`, gather roles from `role_assignments` where `project_membership_id = that.id`.
5. If a project role grants the action → **allow**, else **deny**.

## Example Queries

```sql
-- Workspace-scoped effective permissions
SELECT pb.permission_name
FROM role_assignments ra
JOIN permission_bindings pb ON pb.role_id = ra.role_id
WHERE ra.membership_id = $1;

-- Project-scoped effective permissions
SELECT pb.permission_name
FROM role_assignments ra
JOIN permission_bindings pb ON pb.role_id = ra.role_id
WHERE ra.project_membership_id = $1;
```

## Notes & Guardrails

- Keep **role names** generic (e.g., `WorkspaceAdmin`, `Editor`, `Viewer`) since scope is determined by _where_ you assign them.
- If you need “applies to all projects in workspace,” just **assign at workspace scope** (no special flag needed).
- Add indexes on `role_assignments(membership_id)` and `(project_membership_id)` for fast lookups.
- Policies (later) remain **constraints only** on top of these grants.
