# 🔑 Workspace-Scoped Login and Membership Selection Flow

This document outlines the required inputs, the security checks, and the logic used to select the primary Membership ID for inclusion in the JSON Web Token (JWT) during a standard username/password (credential) login in a multi-tenant system.

---

## 1. Required Client Inputs (POST Data)

For a successful and unambiguous login, the client **must** provide the following information to the authentication endpoint:

| Input Field                | Purpose        | Rationale                                                                                                                |
| :------------------------- | :------------- | :----------------------------------------------------------------------------------------------------------------------- |
| **`email`**                | User Identity  | Used with `workspace_id` to uniquely locate the credential record.                                                       |
| **`password`**             | Authentication | Verified against the hashed secret in the `credential` table.                                                            |
| **`workspace_identifier`** | Tenant Scope   | **Mandatory** input (e.g., subdomain, slug, or UUID) to find the correct `workspace_id` and scope the credential lookup. |

---

## 2. Authentication and Scoping Logic

After the credential is verified against the password, the system follows a strict, sequential process to establish the user's scope.

### Step A: Credential Check

1.  **Find Credential:** Look up an active `credential` record matching the POSTed `email` AND the derived `workspace_id`.
2.  **Verify Password:** Verify the hashed password against the stored `secret`.
3.  **Result:** If successful, extract the authenticated **`account_id` (A)** and confirmed **`workspace_id` (W)**.

### Step B: Primary Membership Search (Workspace Scope Priority)

The system queries the `membership` table for the primary (broadest) context. **This step relies on the database enforcing only one active workspace-level membership per account.**

| Check                                                                                                                  | Action                                                                                                                                |
| :--------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| **1. Primary Search:** Query `membership` where `account_id = A`, `workspace_id = W`, and **`scope = 'workspace'`**.   | **If Found:** **SUCCESS.** Use this single **Workspace Membership ID** as the JWT claim (`mem`). Stop processing and issue the token. |
| **2. Fallback:** If NO workspace-scoped membership is found, the user is only a project member. **Proceed to Step C.** |                                                                                                                                       |

### Step C: Project-Only Fallback (Requires Client Context)

If the user has no top-level workspace membership, they must explicitly tell the system which project context they want to operate in to avoid ambiguity. **This step relies on the database enforcing only one active membership per project for that account.**

| Check                                                                                                                                          | Action                                                                                                                       |
| :--------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------- |
| **1. Project ID Provided?** Check if the login POST data included a **`project_id` (P)**.                                                      | **If NO:** **FAILURE.** Return an error (e.g., 400 Bad Request) requiring the client to specify the project ID for login.    |
| **2. Project Membership Check:** Query `membership` where `account_id = A`, `workspace_id = W`, `scope = 'project'`, and **`project_id = P`**. | **If Found:** **SUCCESS.** Use this **Project Membership ID** as the JWT claim (`mem`). Stop processing and issue the token. |
| **If NOT Found:** **FAILURE.** Return an error (e.g., 403 Forbidden). The user is not an active member of the specified project.               |

---

## 3. Resulting JWT Claims

Upon successful authentication, the resulting JWT includes the following critical claims to establish the user's security context for subsequent API calls:

| Claim     | Source                    | Purpose                                                                                    |
| :-------- | :------------------------ | :----------------------------------------------------------------------------------------- |
| **`sub`** | `account_id` (A)          | The unique user identity (Subject).                                                        |
| **`ws`**  | `workspace_id` (W)        | The specific tenant context the token is valid for.                                        |
| **`mem`** | **Primary Membership ID** | The specific ID of the membership record (workspace or project) chosen by the logic above. |

---

## 4. Data Integrity and Uniqueness Enforcement

The entire membership selection flow relies on database constraints to guarantee that the primary membership records are never ambiguous. Your existing schema enforces this through **partial unique indexes**.

### Required Uniqueness Rules:

1.  **Only ONE Workspace Membership:** An account can only have one active workspace-level membership (`scope = 'workspace'`) in a given workspace.

    - **Enforced By:** `membership_ns_unique ON membership (account_id, workspace_id) WHERE scope = 'workspace'`
    - **Guarantee:** Step B will always result in a maximum of one match.

2.  **Only ONE Project Membership:** An account can only have one active membership for a specific project (`scope = 'project'`).
    - **Enforced By:** `membership_proj_unique ON membership (account_id, project_id) WHERE scope = 'project'`
    - **Guarantee:** Step C will always result in a maximum of one match for the specified project.

The database engine prevents the creation of any data that would lead to ambiguity, making this selection logic safe.
