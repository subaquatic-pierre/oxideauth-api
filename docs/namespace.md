# Workspace and Project Model

## Workspace Types

- **GLOBAL** (the one special workspace)

  - Singleton (exactly one).
  - Only **Owner** membership(s) live here.
  - Has full system control (bootstrap, manage registry, override).
  - Not deletable, slug reserved (e.g. `global`).

- **REGISTRY** (the “domain workspace”)

  - Purpose: **list/organize all other workspaces**.
  - Holds discovery/index metadata, not business data.
  - Access is controlled (e.g., Owners + Auditors can list; others may only see their memberships).
  - Not deletable, slug reserved (e.g. `registry`).

- **STANDARD** (all “real” team/workspaces)
  - Isolated scope for memberships, roles, policies, projects.
  - Can be created/deleted by authorized users.
  - Slug unique per system.

## Relationship: Workspace ↔ Project

- A **Project belongs to exactly one Workspace**.
- No cross-workspace projects (clean isolation).
- Membership is **scoped**: to act in a project, you must be a member of its workspace (or have project-level membership, if supported).

## Membership & Role Rules

- **Global Owner** is the system superuser. Keep it small and auditable.
- **Registry access (REGISTRY):**
  - Typical roles: `RegistryViewer` (read-only list), `RegistryAdmin` (create/delete workspaces).
  - Registry visibility controls who can **discover** workspaces.
- **Standard workspaces (STANDARD):**
  - Normal roles live here (e.g., `Admin`, `Editor`, `Viewer`).

## Inheritance & Precedence

- **No implicit inheritance** of roles from GLOBAL/REGISTRY into STANDARD.
  - Exception: **Global Owner** bypass.
- **Project inherits workspace RBAC** by default (simplest mental model).
  - If project-specific memberships exist, they are **in addition**, not instead.

## Visibility Rules

- **GLOBAL**: Owners see everything.
- **REGISTRY**:
  - `RegistryViewer` can list all workspaces and metadata.
  - Non-registry users see only workspaces where they hold membership (default).
- **STANDARD**:
  - Fully isolated. Users see it only if they’re members (or global owner).

## Bootstrapping Sequence

1. Create **GLOBAL** workspace (id/slug reserved).
2. Create first **Owner** membership under GLOBAL.
3. Create **REGISTRY** workspace (id/slug reserved).
4. From GLOBAL/REGISTRY, create first **STANDARD** workspaces and seed initial admins.

## Guardrails & Constraints

- Reserved slugs: `global`, `registry`.
- **GLOBAL** and **REGISTRY** not deletable; name/slug immutable.
- Workspace slug globally unique; project slug unique within its workspace.
- Cross-workspace actions denied by default.
- Moving a project between workspaces: disallowed (or treat as clone+archive if ever needed).

## Minimal Fields

**workspace**

- `id (uuid)`
- `type (GLOBAL|REGISTRY|STANDARD)`
- `slug (text, unique)`
- `name`
- `description`
- `created_at`, `updated_at`
- `enabled (bool)`

**project**

- `id (uuid)`
- `workspace_id (uuid fk)`
- `slug (text unique within workspace)`
- `name`
- `description`
- `created_at`, `updated_at`
- `enabled (bool)`

**membership**

- `id (uuid)`
- `account_id (uuid)`
- `workspace_id (uuid)`
- _(optional `project_id` if project-level memberships are supported)_
- `created_at`, `updated_at`
- Bind roles via `role_bindings`

## Mental Model in One Line

- **GLOBAL** = root control
- **REGISTRY** = index/discovery of workspaces
- **STANDARD** = real workspaces with projects and isolated RBAC
