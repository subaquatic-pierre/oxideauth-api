# 🚀 API Structure Analysis: All-POST for High-Volume Services

This document summarizes the architectural decision and justification for implementing an API where all endpoints, including data retrieval, use the HTTP **POST** method. This structure is deemed appropriate given the context of complex filtering requirements and security-critical, high-volume operations (like an Authorization Microservice).

---

## 1. Justification for All-POST Structure

The decision to use an all-`POST` structure is a pragmatic choice driven by specific technical and security constraints, aligning the API with a **JSON-RPC style** rather than traditional REST.

| Rationale                        | Why POST is Necessary/Appropriate                                                                                                                                                                                                             | Consequence                                                                                                                                                           |
| :------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Complex Filters/Body Data**    | All requests require complex, nested, or large filter payloads (e.g., ModQL structures) that are unsuitable for transmission via URL query strings (due to length limits or complexity).                                                      | **POST** is the only reliable HTTP method for transmitting body data.                                                                                                 |
| **Security of Auth Checks**      | Security-critical data (tokens, unique credentials) must be transmitted in the **request body** to prevent exposure in server logs, browser history, and proxy logs.                                                                          | **POST** is the most secure method for sending sensitive parameters.                                                                                                  |
| **Loss of Caching is Desirable** | For real-time authentication and authorization, **HTTP caching is a security risk** (leading to stale permissions). Using `POST` explicitly bypasses standard HTTP caching mechanisms (CDNs, proxies), which is the correct security posture. | **Caching is intentionally disabled** at the HTTP layer, shifting caching responsibility to secure, application-level mechanisms (e.g., Redis for non-critical data). |
| **RPC Alignment**                | The API operates on commands and procedures (`validateToken`, `listAccounts(filters)`) rather than purely on resources, fitting the JSON-RPC pattern where the body dictates the function call.                                               | Structure is consistent and handler logic is simplified.                                                                                                              |

---

## 2. Structural Requirements

Since the HTTP verb is static (`POST`), the **URL path** must explicitly define the action being performed.

| Operation Type    | Recommended URL Path       | Example Body Content                       |
| :---------------- | :------------------------- | :----------------------------------------- |
| **List/Search**   | `POST /accounts/list`      | Complex filter object, pagination options. |
| **Detail/Get**    | `POST /accounts/get-by-id` | Primary key or unique identifier.          |
| **Create**        | `POST /accounts/create`    | Full data payload for the new entity.      |
| **Update/Modify** | `POST /accounts/update`    | Identifier and partial/full data payload.  |
| **Command/Auth**  | `POST /auth/validate`      | Token or credentials being checked.        |

### Status Codes are Critical

Despite using `POST`, the API must adhere to standard HTTP status code semantics to communicate the result:

- **200 OK:** Successful read, update, or delete.
- **201 Created:** Successful creation of a new resource.
- **400 Bad Request:** Validation failure (e.g., invalid filters, malformed input).
- **401 Unauthorized:** Authentication/JWT failure.
- **404 Not Found:** Resource specified in the body was not found.

---

## 3. Client-Side Consideration

For the client, the all-`POST` structure means:

- **No Automatic Caching:** The client cannot rely on the browser's native HTTP cache for read requests, requiring manual compensation via client-side state management (e.g., React Query or Redux store).
- **Complex Debugging:** Debugging relies on inspecting the non-shareable request payload in the network tab, rather than using simple, shareable URLs.
