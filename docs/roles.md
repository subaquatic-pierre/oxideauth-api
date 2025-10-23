# Ironstone Roles Explained

## What is a Role?

A **Role** is a named collection of individual permissions. Think of it as a job title or a function within your organization, like "Administrator" or "Content Editor."

Instead of assigning dozens of specific permissions to each user one by one, you assign them a **Role**. The user then inherits all the permissions that belong to that role. This makes managing user access much simpler and less error-prone.

- **You manage Roles:** Define a role once and add all the necessary permissions to it (e.g., the `Admin` role gets `users:create`, `users:delete`, `projects:create`, etc.).
- **You assign Roles to Users:** When a new developer joins, you just assign them the `Member` role. They instantly get all the permissions they need, and none they don't.

If you need to change what all Members can do, you just update the `Member` role, and the change applies to everyone with that role instantly.

## Default Roles in a New Workspace

When you create a new workspace, four default roles are automatically set up. These provide a secure and logical starting point for managing access.

| Role Name      | Description                                                                                                                                                                                                                                          |
| :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 👑 **Owner**   | The highest-level role with **unrestricted access**. Owners can manage all resources, invite and manage members, configure billing, and are the only ones who can **delete the workspace**. This role should be assigned sparingly.                  |
| 🛠️ **Admin**   | A highly privileged role for technical administrators. Admins can manage all workspace settings, projects, and members, but **cannot** manage billing or delete the workspace.                                                                       |
| 👤 **Member**  | The standard role for most users. Members can view projects and other resources and can create new projects. Their permissions are focused on contributing to projects without being able to change critical workspace settings.                     |
| 💳 **Billing** | A specialized, limited role. Users with this role can only view the member list and manage the workspace's subscription and payment information. They **cannot** access any project data, making it a safe role for an accounting or finance person. |
