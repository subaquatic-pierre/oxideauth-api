# Ironstone Authorization & Permissions

This document outlines the standards for Role-Based Access Control (RBAC) within the Ironstone platform. It defines the structure of permissions, the default roles provided, and the specific permissions granted to those roles.

## Permission Naming Convention

All permissions follow a consistent `resource:action` format to ensure clarity and predictability.

- **Format**: `{resource}:{action}`
- **Delimiter**: A colon (`:`) always separates the resource from the action.
- **Casing**: The entire string is `lowercase`.

### Resource Naming (`resource`)

The resource is the "noun" of the permission. It represents a logical entity within the system.

- **Rule**: Resources are always **plural nouns**.
- **Examples**: `projects`, `members`, `roles`

### Action Naming (`action`)

The action is the "verb" of the permission. It represents what can be done to a resource.

- **Rule**: Actions are simple, **present-tense verbs**.
- **CRUD Standard**: For entities that can be created, read, updated, and deleted, the standard actions `create`, `read`, `update`, and `delete` are used.
- **Specific Actions**: For other operations, a specific and descriptive verb is used, such as `invite` or `assign`.

## Core Concepts

Our authorization model is built on three core entities:

1.  **Permission**: A single, granular permission that grants the ability to perform one specific action on one type of resource (e.g., `projects:create`).
2.  **Role**: A named collection of permissions. Roles are used to group permissions into logical sets that can be assigned to users (e.g., the "Administrator" role).
3.  **Membership**: The link that connects an `Account` to a `Workspace`. A user is granted `Roles` through their `Membership`.

A user's total set of abilities within a workspace is the sum of all permissions granted by all the roles they are assigned.

## Default Roles

When a new workspace is created, four default roles are automatically generated. These provide a sensible starting point for access control.

| Role Name   | Description                                                                                                     |
| :---------- | :-------------------------------------------------------------------------------------------------------------- |
| **Owner**   | Has full, unrestricted access to all resources. The only role that can delete the workspace and manage billing. |
| **Admin**   | Can manage all resources _except_ for workspace deletion and billing. Intended for technical administrators.    |
| **Member**  | A standard user role. Can view resources and manage the projects they are assigned to.                          |
| **Billing** | A specialized role that can only view members and manage billing settings. Cannot access project data.          |

## Default Permissions List

The following is a comprehensive list of all default permissions created for a new workspace. They are grouped by their `resource`.

### Workspace (`workspace`)

Permissions related to the management of the workspace itself.

| Permission Name    | Granted to (Default Roles)    | Description                                               |
| :----------------- | :---------------------------- | :-------------------------------------------------------- |
| `workspace:read`   | Owner, Admin, Member, Billing | Allows viewing the workspace's name and settings.         |
| `workspace:update` | Owner, Admin                  | Allows updating the workspace's name and settings.        |
| `workspace:delete` | Owner                         | **DANGEROUS**: Allows permanently deleting the workspace. |

### Members & Invitations (`members`)

Permissions for managing user membership and inviting new people to the workspace.

| Permission Name  | Granted to (Default Roles)    | Description                                          |
| :--------------- | :---------------------------- | :--------------------------------------------------- |
| `members:read`   | Owner, Admin, Member, Billing | Allows viewing the list of members in the workspace. |
| `members:invite` | Owner, Admin                  | Allows inviting new members to the workspace.        |
| `members:update` | Owner, Admin                  | Allows changing a member's roles.                    |
| `members:delete` | Owner, Admin                  | Allows removing a member from the workspace.         |

### Projects (`projects`)

Permissions for managing projects within the workspace.

| Permission Name   | Granted to (Default Roles) | Description                                              |
| :---------------- | :------------------------- | :------------------------------------------------------- |
| `projects:create` | Owner, Admin, Member       | Allows creating a new project.                           |
| `projects:read`   | Owner, Admin, Member       | Allows viewing project details and resources.            |
| `projects:update` | Owner, Admin               | Allows updating a project's name, code, and description. |
| `projects:delete` | Owner, Admin               | Allows permanently deleting a project.                   |

### Roles & Permissions (`roles`)

Permissions for managing the RBAC system itself. These are highly privileged.

| Permission Name | Granted to (Default Roles) | Description                                            |
| :-------------- | :------------------------- | :----------------------------------------------------- |
| `roles:create`  | Owner, Admin               | Allows creating a new custom role.                     |
| `roles:read`    | Owner, Admin               | Allows viewing roles and the permissions they contain. |
| `roles:update`  | Owner, Admin               | Allows modifying a custom role and its permissions.    |
| `roles:delete`  | Owner, Admin               | Allows deleting a custom role.                         |
| `roles:assign`  | Owner, Admin               | Allows assigning roles to members.                     |

### Billing (`billing`)

Permissions for managing the workspace's subscription and payment details.

| Permission Name  | Granted to (Default Roles) | Description                                                 |
| :--------------- | :------------------------- | :---------------------------------------------------------- |
| `billing:read`   | Owner, Billing             | Allows viewing current plan, invoices, and payment methods. |
| `billing:manage` | Owner, Billing             | Allows changing the plan and updating payment methods.      |

### Audit Logs (`audit-logs`)

Permissions for viewing the audit trail of activities within the workspace.

| Permission Name   | Granted to (Default Roles) | Description                                           |
| :---------------- | :------------------------- | :---------------------------------------------------- |
| `audit-logs:read` | Owner, Admin               | Allows viewing the log of all actions taken by users. |
