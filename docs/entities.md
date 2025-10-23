# 🔗 How the Entities Connect

### Accounts

- An **Account** represents a person or system user.
- Each account can:
  - Have multiple **Credentials** (passwords, OAuth logins, API keys).
  - Hold multiple **Memberships** (which define their access inside different Workspaces or Projects).

---

### Workspaces

- A **Workspace** is the top-level container for everything (like a tenant, workspace, or organization).
- A Workspace can contain:
  - Many **Projects** (sub-areas inside the Workspace).
  - Many **Roles** (job definitions like “Admin” or “Viewer”).
  - Many **Permissions** (fine-grained actions like “edit_project”).
  - Many **Credentials** (scoped login methods).
  - Many **Memberships** (Accounts enrolled into the Workspace).

---

### Projects

- A **Project** belongs to exactly one Workspace.
- Memberships can be tied directly to a Project (project-level access).
- Projects are optional scope: a user can belong just to a Workspace, or also to specific Projects inside it.

---

### Memberships

- A **Membership** connects an **Account** to a **Workspace**, and optionally to a **Project** inside it.
- Think: “User X is a member of Workspace Y (and maybe Project Z).”
- Each membership can be assigned one or more **Roles**.

---

### Roles & Permissions

- A **Role** is a named bundle of access, defined inside a Workspace.
- A **Permission** is a single capability (like “read_reports” or “manage_users”), also defined inside a Workspace.
- Roles and Permissions are linked through **Role_Permission**:
  - A Role can include many Permissions.
  - A Permission can be part of many Roles.

---

### Membership Roles

- A **Membership_Role** links a specific membership (user in a workspace/project) to one or more Roles.
- This is how an Account actually gains permissions:
  - Account → Membership → Role → Permissions.

---

### Credentials

- A **Credential** connects an **Account** to a **Workspace** with a way to log in (password, Google OAuth, API key, etc.).
- They are scoped by Workspace, so the same Account can authenticate differently in different Workspaces.
- An **Account** can have many **Credentials**, ie. a password login or OAuth login, but more than one of the same kind of **Credential** cannot exist in the same workspace, meaning an **Account** cannot have two **Credentials** of the **kind=password**
- Examples:
  - `user@example.com` with a password in Workspace A.
  - Google OAuth login in Workspace B.

---

# 🗂 Summary in Plain English

- **Account** = who the user is.
- **Workspace** = the organization/tenant they belong to.
- **Project** = a sub-area inside a workspace.
- **Membership** = the link that says “this account is part of this workspace/project.”
- **Role** = a job title inside the workspace (Admin, Editor, Viewer).
- **Permission** = the atomic actions (read, write, delete).
- **Membership_Role** = assigns roles to a membership.
- **Role_Permission** = assigns permissions to a role.
- **Credential** = how the account logs in, scoped to a workspace.
