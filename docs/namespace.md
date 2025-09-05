# Namespace and Project Model

## Namespace Types

- **GLOBAL** (the one special namespace)

  - Singleton (exactly one).
  - Only **Owner** membership(s) live here.
  - Has full system control (bootstrap, manage registry, override).
  - Not deletable, slug reserved (e.g. `global`).

- **REGISTRY** (the “domain namespace”)

  - Purpose: **list/organize all other namespaces**.
  - Holds discovery/index metadata, not business data.
  - Access is controlled (e.g., Owners + Auditors can list; others may only see their memberships).
  - Not deletable, slug reserved (e.g. `registry`).

- **STANDARD** (all “real” team/workspaces)
  - Isolated scope for memberships, roles, policies, projects.
  - Can be created/deleted by authorized users.
  - Slug unique per system.

## Relationship: Namespace ↔ Project

- A **Project belongs to exactly one Namespace**.
- No cross-namespace projects (clean isolation).
- Membership is **scoped**: to act in a project, you must be a member of its namespace (or have project-level membership, if supported).

## Membership & Role Rules

- **Global Owner** is the system superuser. Keep it small and auditable.
- **Registry access (REGISTRY):**
  - Typical roles: `RegistryViewer` (read-only list), `RegistryAdmin` (create/delete namespaces).
  - Registry visibility controls who can **discover** namespaces.
- **Standard namespaces (STANDARD):**
  - Normal roles live here (e.g., `Admin`, `Editor`, `Viewer`).

## Inheritance & Precedence

- **No implicit inheritance** of roles from GLOBAL/REGISTRY into STANDARD.
  - Exception: **Global Owner** bypass.
- **Project inherits namespace RBAC** by default (simplest mental model).
  - If project-specific memberships exist, they are **in addition**, not instead.

## Visibility Rules

- **GLOBAL**: Owners see everything.
- **REGISTRY**:
  - `RegistryViewer` can list all namespaces and metadata.
  - Non-registry users see only namespaces where they hold membership (default).
- **STANDARD**:
  - Fully isolated. Users see it only if they’re members (or global owner).

## Bootstrapping Sequence

1. Create **GLOBAL** namespace (id/slug reserved).
2. Create first **Owner** membership under GLOBAL.
3. Create **REGISTRY** namespace (id/slug reserved).
4. From GLOBAL/REGISTRY, create first **STANDARD** namespaces and seed initial admins.

## Guardrails & Constraints

- Reserved slugs: `global`, `registry`.
- **GLOBAL** and **REGISTRY** not deletable; name/slug immutable.
- Namespace slug globally unique; project slug unique within its namespace.
- Cross-namespace actions denied by default.
- Moving a project between namespaces: disallowed (or treat as clone+archive if ever needed).

## Minimal Fields

**namespace**

- `id (uuid)`
- `type (GLOBAL|REGISTRY|STANDARD)`
- `slug (text, unique)`
- `name`
- `description`
- `created_at`, `updated_at`
- `enabled (bool)`

**project**

- `id (uuid)`
- `namespace_id (uuid fk)`
- `slug (text unique within namespace)`
- `name`
- `description`
- `created_at`, `updated_at`
- `enabled (bool)`

**membership**

- `id (uuid)`
- `account_id (uuid)`
- `namespace_id (uuid)`
- _(optional `project_id` if project-level memberships are supported)_
- `created_at`, `updated_at`
- Bind roles via `role_bindings`

## Mental Model in One Line

- **GLOBAL** = root control
- **REGISTRY** = index/discovery of namespaces
- **STANDARD** = real workspaces with projects and isolated RBAC
