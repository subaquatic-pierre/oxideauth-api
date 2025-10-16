# Ironstone: System Overview

## High-Level Concept

Ironstone is a **centralized, multi-tenant Identity and Access Management (IAM) platform** designed specifically for a microservices architecture. Its primary goal is to completely offload the complexities of authentication and authorization from individual services, allowing developers to focus on their core business logic.

---

## Core Architectural Principles

- **Multi-Tenancy via Namespaces:** The entire system is built around the concept of a `Namespace`. A `Namespace` is the top-level, isolated container for a single organization (tenant), ensuring that one tenant's users, roles, and configurations are completely segregated from another's.

- **Configuration Scoped to Namespaces:** Each tenant has full control over their own namespace and can configure:

  - External OIDC Providers (e.g., Google, Azure AD).
  - Security policies like token lifetimes and MFA rules.
  - Application-specific `Roles` and `Permissions`.

- **Centralized Control, Delegated Execution:** Ironstone acts as the central source of truth for identity and permissions, but the validation is initiated by the individual microservices via a secure API call.

---

## The Main Authentication & Authorization Flow

This is the primary interaction model and the core of the service. It uses a **Dual JWT Token system** to ensure that both the requesting service and the end-user are verified.

#### Actors:

- **End-User:** The person using the tenant's application.
- **Microservice:** The tenant's backend service that needs to authorize the End-User's request.
- **Ironstone:** The central auth service.

#### Tokens:

1.  **Service JWT (API Key):** A long-lived token that authenticates the _Microservice_ itself. This proves to Ironstone that a legitimate, registered service is making the request.
2.  **User JWT:** A standard, short-lived token that authenticates the _End-User_. This is obtained through a normal login flow (e.g., username/password, or OIDC social login).

#### Step-by-Step Flow:

1.  An **End-User** sends a request to a **Microservice**, including their `User JWT` (e.g., in the `Authorization` header).
2.  The **Microservice** receives the request. Before executing its business logic, it needs to verify if the user has the required permission (e.g., `can-delete-post`).
3.  The Microservice constructs a request to the Ironstone `/validate_jwt` endpoint.
    - It authenticates itself by providing its own `Service JWT`.
    - In the request body, it includes the `User JWT` it received and the list of `permissions` it needs to check.
4.  **Ironstone** performs a two-stage validation:
    - **Stage 1 (Service Authentication):** It validates the `Service JWT`. Is this a valid microservice, and is it allowed to use the validation endpoint? If not, the request is rejected immediately.
    - **Stage 2 (User Authorization):** If the service is valid, Ironstone then validates the `User JWT`. It checks the token's signature and expiry, and most importantly, it checks if the user's identity and assigned roles contain the `permissions` the microservice asked for.
5.  **Ironstone** returns a simple, definitive response to the Microservice. For example:
    ```json
    {
      "allowed": true
    }
    ```
6.  The **Microservice** receives the response. It now either proceeds with the business logic or returns an `HTTP 403 Forbidden` error to the End-User.

---

## Management and Administration

Ironstone provides two interfaces for its users (the developers building the microservices) to manage their namespaces:

- **Ironstone Dashboard (UI):** A web-based interface where developers can manually configure their namespace, create roles, invite team members, and manage their end-users.
- **Ironstone Web API:** A programmatic REST API that allows developers to automate user management, role assignment, and other administrative tasks directly from their own backend services, using a `Service JWT` for authentication.
