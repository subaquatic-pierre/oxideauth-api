# Registration and Authentication Model

## 1. Identity vs. Membership vs. Credentials

- **Account (global, unique)**  
  One row per human. Carries global invariants: `id`, `primary_email`, `email_verified`, `status`, audit.

- **Membership (per namespace, required to act)**  
  One row per `(account_id, namespace_id)`. Carries scope + default `Member` role.  
  Optionally has one or more **ProjectMemberships** hanging off it.

- **Credentials**
  - **Global credentials** — one password, WebAuthn key, etc.
  - **Membership-scoped credentials** — separate password/MFA per namespace membership.

Recommendation: **allow both**, with precedence rules. This keeps UX simple for most users while enabling different credentials per membership where required.

---

## 2. Tables

```sql
-- Global identity
accounts(id PK, primary_email UNIQUE, email_verified BOOL, status, created_at, ...)

-- Namespace membership (required)
memberships(id PK, account_id FK, namespace_id FK, UNIQUE(account_id, namespace_id), ...)

-- Project membership (optional)
project_memberships(id PK, membership_id FK, project_id FK, UNIQUE(membership_id, project_id), ...)

-- Role assignment (unified)
role_assignments(id PK, role_id FK, membership_id FK NULL, project_membership_id FK NULL, CHECK(exactly one set))

-- GLOBAL credentials (optional)
account_credentials(
  id PK, account_id FK,
  kind TEXT CHECK (kind IN ('password','webauthn','totp','recovery')),
  secret_hash / public_key / seed JSONB,
  enabled BOOL DEFAULT TRUE
)

-- MEMBERSHIP-scoped credentials
membership_credentials(
  id PK, membership_id FK,
  kind TEXT CHECK (kind IN ('password','webauthn','totp','recovery')),
  secret_hash / public_key / seed JSONB,
  enabled BOOL DEFAULT TRUE
)

-- External identity links (global or namespace-scoped)
external_identities(
  id PK,
  account_id FK,
  provider TEXT,          -- 'google','microsoft','github'
  subject TEXT,           -- stable sub from IdP
  namespace_id UUID NULL, -- NULL = global link; non-NULL = valid only for that namespace
  metadata JSONB,
  UNIQUE(provider, subject, COALESCE(namespace_id, '00000000-0000-0000-0000-000000000000'))
)

-- Namespace auth policy (controls login methods)
namespace_auth_policies(
  namespace_id PK FK,
  allow_local_password BOOL,
  allow_webauthn BOOL,
  allow_totp BOOL,
  allowed_providers TEXT[],        -- ['google','microsoft']
  mfa_required BOOL,
  invite_only BOOL,
  auto_approve_self_signup BOOL,
  default_role TEXT DEFAULT 'Member'
)
```

---

## 3. Registration Flows

### Invite flow (controlled)

1. Admin creates invite in Namespace N.
2. User follows invite link.
3. Resolve/create Account.
4. Create Membership in N with default or invited role.
5. Configure credentials (per policy).
6. Done.

### Self-serve join

1. User visits `/join` on namespace domain.
2. Resolve/create Account.
3. Create Membership with default `Member` role.
4. Configure credentials as allowed.
5. Done.

### External SSO (Google, etc.)

1. User chooses "Continue with Google" on namespace domain.
2. OIDC flow completes.
3. Resolve or create external identity link.
4. Ensure Membership exists (create if policy allows).
5. Done.

---

## 4. Login Resolution

At `https://N.yourapp.com/login`:

1. Resolve namespace and load policy.
2. Candidate credentials:
   - `membership_credentials` for `(account, N)`
   - `account_credentials` if policy allows global creds
   - `external_identities` if linked and allowed
3. Offer methods allowed by policy.
4. On success, ensure Membership is active.
5. Issue token with claims:
   - `sub`: account_id
   - `namespace_id`, `membership_id`
   - `roles_namespace`, `roles_projects`
   - `amr` (auth method), `mfa`, `provider`

---

## 5. MFA and Step-up

- Namespace policy can enforce MFA for all logins or step-up for sensitive actions.
- MFA secrets can be global or membership-scoped.
- Prefer membership-scoped MFA for namespaces with stricter compliance.

---

## 6. Credential Precedence

Resolution order:

1. `membership_credentials` (if exist).
2. External identity link (if allowed by policy).
3. `account_credentials` (if namespace allows global creds).
4. Else → block and prompt user to set up allowed credentials.

This enables scenarios like:

- Password A in Namespace X.
- Google SSO in Namespace Y.
- FIDO2-only in Namespace Z.

---

## 7. Security & Ops Notes

- **Per-namespace OIDC**: client IDs/secrets per namespace, subdomain in redirect URIs.
- **Email verification**: global at Account level; namespaces may enforce domain rules.
- **Lockouts**: track per Membership, not per Account, to avoid cross-tenant lockouts.
- **Audit logs**: include `auth_method`, `namespace_id`, `membership_id`.
- **Recovery**: store recovery codes per Membership if namespace forbids global creds.
- **Deprovisioning**: disabling a Membership invalidates sessions in that namespace.
