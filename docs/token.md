# Token Architecture & Security Documentation

## 1. Philosophical Overview: Stateless JWT Auth

The system utilizes **Stateless JWTs** (JSON Web Tokens) for request authentication. Unlike traditional session-based systems, the server does not "look up" a session for every request. It trusts the token based on its cryptographic signature.

### The Revocation Problem

In a stateless system, tokens are valid until they expire ($exp$). To allow for manual logout or security lockouts, we implement a **Blacklist Pattern** rather than a **Whitelist Pattern**.

| Strategy      | Logic                                   | Performance                       | Standard       |
| :------------ | :-------------------------------------- | :-------------------------------- | :------------- |
| **Whitelist** | Only tokens in DB are valid.            | Slow (DB hit every request)       | Legacy/Banking |
| **Blacklist** | All signed tokens valid unless revoked. | Fast (Check cache for exceptions) | **Modern Web** |

---

## 2. Polymorphic Token Storage

To maintain a lean architecture, all token-related data is consolidated into a single unified table. This allows the `TokenService` to manage diverse lifecycles within one domain.

### Table Discriminators (Token Types)

The `token_type` field distinguishes the behavior and requirements of each entry:

- `BLACKLIST`: A `jti` (JWT ID) that has been revoked before its expiration.
- `REFRESH`: Long-lived tokens used to generate new access tokens.
- `API_KEY`: Permanent or long-lived tokens for programmatic access.
- `RESET_PASSWORD`: Short-lived, single-use tokens for recovery flows.

---

## 3. The Blacklist Life-cycle

### Revocation (Create)

When a user logs out, the `TokenService` extracts the `jti` and the $exp$ from the current JWT.

1. A record is created in the `TokenStore` with type `BLACKLIST`.
2. The `jti` is added to the `CacheManager` with a TTL equal to the remaining life of the token.

### Validation (Describe/Check)

For every incoming request, the Auth Middleware performs:

1. **Signature Check**: Is the JWT valid? (CPU only).
2. **Cache Check**: Is the key `bl:{jti}` in Redis? (Memory speed).
3. **Database Fallback**: If the cache is cold, check the `TokenStore` where `type = BLACKLIST`.

---

## 4. Resiliency & Cache Restoration

Since the Cache (Redis) is volatile memory, it is not treated as the "System of Record." The Database is the source of truth.

### Eager Restoration (Hydration)

In the event of a cache wipe or system restart, the `TokenService` provides a `prime_blacklist_cache` method. This method:

1. Queries the `TokenStore` for all `BLACKLIST` entries where `expires_at > NOW()`.
2. Iteratively restores these entries to the `CacheManager`.
3. Ensures the system "fails closed" (remains secure) even after a total infrastructure reboot.

---

## 5. Technical Implementation Guidelines

### Cache Key Namespacing

To avoid collisions in the unified table, the `CacheManager` must use prefixes:

- `bl:{jti}` -> Blacklist entries.
- `ref:{id}` -> Refresh token metadata.

### Automatic Pruning

A background "Janitor" task should run periodically (e.g., every 6 hours) to delete expired rows from the `TokenStore` across all types:

```sql
DELETE FROM token WHERE expires_at < NOW();
```

## 6. Security Trade-offs

1. **Fail-Open Strategy**: If both Cache and Database are unreachable, the system trusts the JWT signature. This ensures high availability.

2. **Window of Risk**: The window of risk is limited by the Access Token Lifetime (recommended 5-15 minutes). Even if revocation fails, the token expires shortly regardless.
