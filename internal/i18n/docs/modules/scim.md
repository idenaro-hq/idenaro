## scim-overview | SCIM | 

The SCIM module tests System for Cross-domain Identity Management endpoints for unauthenticated access. SCIM is used by enterprise directories and IdPs to provision, update, and deprovision user accounts and group memberships. Unauthenticated access allows full user directory enumeration and potentially user creation or takeover.

### Checks performed

- `/scim/v2/Users` and `/scim/v2/Groups` access without authentication
- SCIM `ServiceProviderConfig` endpoint exposure revealing capability details

---

## scim-exposed | SCIM Endpoint Accessible Without Authentication | CRITICAL

A SCIM provisioning endpoint is publicly accessible without authentication. SCIM provides full CRUD access to user and group identities. Unauthenticated access enables mass user enumeration, account creation, group manipulation, and privilege escalation.

### Remediation

- Require Bearer token authentication on all SCIM endpoints.
- Restrict SCIM access to your provisioning system's IP range.
- Rotate SCIM bearer tokens on a regular schedule (90 days or less).
- Enable audit logging for all SCIM operations.

---

## scim-config-exposed | SCIM ServiceProviderConfig Accessible | MEDIUM

The SCIM ServiceProviderConfig endpoint reveals the SCIM implementation details, supported features, and authentication schemes. While less sensitive than user data, it aids reconnaissance of the identity provisioning system.

### Remediation

- Require authentication for all SCIM endpoints including configuration and schema endpoints.
