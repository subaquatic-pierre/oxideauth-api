# 🔗 How the Entities Connect

### Accounts

- An **Account** represents a person or system user.
- Each account can:
  - Have multiple **Credentials** (passwords, OAuth logins, API keys).
  - Hold multiple **Memberships** (which define their access inside different Namespaces or Projects).

---

### Namespaces

- A **Namespace** is the top-level container for everything (like a tenant, workspace, or organization).
- A Namespace can contain:
  - Many **Projects** (sub-areas inside the Namespace).
  - Many **Roles** (job definitions like “Admin” or “Viewer”).
  - Many **Permissions** (fine-grained actions like “edit_project”).
  - Many **Credentials** (scoped login methods).
  - Many **Memberships** (Accounts enrolled into the Namespace).

---

### Projects

- A **Project** belongs to exactly one Namespace.
- Memberships can be tied directly to a Project (project-level access).
- Projects are optional scope: a user can belong just to a Namespace, or also to specific Projects inside it.

---

### Memberships

- A **Membership** connects an **Account** to a **Namespace**, and optionally to a **Project** inside it.
- Think: “User X is a member of Namespace Y (and maybe Project Z).”
- Each membership can be assigned one or more **Roles**.

---

### Roles & Permissions

- A **Role** is a named bundle of access, defined inside a Namespace.
- A **Permission** is a single capability (like “read_reports” or “manage_users”), also defined inside a Namespace.
- Roles and Permissions are linked through **Role_Permission**:
  - A Role can include many Permissions.
  - A Permission can be part of many Roles.

---

### Membership Roles

- A **Membership_Role** links a specific membership (user in a namespace/project) to one or more Roles.
- This is how an Account actually gains permissions:
  - Account → Membership → Role → Permissions.

---

### Credentials

- A **Credential** connects an **Account** to a **Namespace** with a way to log in (password, Google OAuth, API key, etc.).
- They are scoped by Namespace, so the same Account can authenticate differently in different Namespaces.
- An **Account** can have many **Credentials**, ie. a password login or OAuth login, but more than one of the same kind of **Credential** cannot exist in the same namespace, meaning an **Account** cannot have two **Credentials** of the **kind=password**
- Examples:
  - `user@example.com` with a password in Namespace A.
  - Google OAuth login in Namespace B.

---

# 🗂 Summary in Plain English

- **Account** = who the user is.
- **Namespace** = the organization/tenant they belong to.
- **Project** = a sub-area inside a namespace.
- **Membership** = the link that says “this account is part of this namespace/project.”
- **Role** = a job title inside the namespace (Admin, Editor, Viewer).
- **Permission** = the atomic actions (read, write, delete).
- **Membership_Role** = assigns roles to a membership.
- **Role_Permission** = assigns permissions to a role.
- **Credential** = how the account logs in, scoped to a namespace.
