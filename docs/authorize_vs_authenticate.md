The Service Dependency Graph
This creates a clean, one-way flow of dependencies. Higher-level services that manage processes depend on lower-level services that manage data entities.

AuthService -> depends on -> RoleService, PermissionService

AuthenticateService -> depends on -> AccountService, CredentialService

RoleService, PermissionService, AccountService -> depend on -> StoreManager

Summary of the "Rules"
Coordinator, Not Owner: AuthService coordinates authorization checks. It does not own the role or permission data itself.

One-Way Dependencies: It depends on entity services (RoleService, etc.). Those services must never depend on AuthService. This prevents circular dependencies.

Simple Outcome: Its primary job is to return a simple Ok(()) (allowed) or Err (denied). It doesn't usually return data.

Use It Everywhere: Your web handlers (controllers) and other services will call authorize_service.can(...) as a guard before performing any protected action.

An Analogy: The Bouncer at a VIP Club
Authentication: The bouncer checks your ID at the main door to verify you are who you say you are. (AuthenticateService)

Authorization: Once you're inside, you try to enter the exclusive VIP lounge. The bouncer there doesn't need to see your ID again. They check your name against the VIP list. To do this, they might ask a manager ("Who is on the list for tonight?"). (AuthService delegating to RoleService). Based on that information, they either let you in or deny you access.
