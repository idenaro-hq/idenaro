## vendor-overview | Vendor-Specific | 

The Vendor-Specific module detects identity platform vendor signatures from HTTP responses and tests their management interfaces and proprietary endpoints for unauthenticated access. Each vendor exposes unique admin and API surfaces beyond standard protocols.

### Checks performed

- **Keycloak**: admin console, dynamic client registration endpoint, realm list API
- **ADFS**: IdP-initiated sign-on page, WS-Federation passive endpoint
- **PingFederate**: administrative console accessibility
- **Authentik**: users API endpoint without authentication
- **Azure AD**: legacy authentication endpoint (`/common/oauth2/token`)

---

## vendor-keycloak-admin | Keycloak Admin Console Accessible | HIGH

The Keycloak admin console is accessible from the public internet. The admin console provides complete control over all realms, clients, users, identity providers, and authentication flows. A single compromised admin credential grants full IdP control.

### Remediation

- Use `--hostname-admin` to serve the admin console on a separate internal hostname.
- Block the `/admin` path at the reverse proxy for external requests.
- Require MFA for all admin console authentication.

---

## vendor-keycloak-client-reg | Keycloak Dynamic Client Registration Open | HIGH

The Keycloak dynamic client registration endpoint accepts new client registrations without requiring an initial access token. Any unauthenticated party can register OAuth clients in this realm, potentially obtaining redirect URIs for authorization code theft.

### Remediation

- Require an initial access token for all client registrations.
- Keycloak: Clients → Client Registration → set "Client Registration Access Token Required".

---

## vendor-keycloak-realm-list | Keycloak Realm List Accessible | INFO

Keycloak exposes the names of all configured realms via the `/realms/` endpoint. Each realm name is a separate attack surface with its own OIDC/SAML configuration, and knowing realm names enables targeted enumeration of additional endpoints.

### Remediation

- This is expected Keycloak behaviour. Use non-obvious realm names in production.
- Ensure each realm is hardened individually - the master realm should restrict public client registration and token access.

---

## vendor-adfs-idp-initiated | ADFS IdP-Initiated Sign-On Page Exposed | HIGH

The ADFS IdP-initiated sign-on page is publicly accessible. This endpoint is commonly abused in phishing campaigns as it allows authentication to be initiated to arbitrary applications without SP involvement, bypassing SP-initiated flow controls and some Conditional Access policies.

### Remediation

- Disable IdP-initiated SSO: `Set-AdfsProperties -EnableIdPInitiatedSignonPage $false`
- If required for specific applications, restrict via Conditional Access policies.

---

## vendor-adfs-ws-fed | ADFS WS-Federation Passive Endpoint Exposed | HIGH

The ADFS WS-Federation passive endpoint is publicly accessible. This endpoint handles browser-based federated authentication and can be targeted for phishing attacks and session fixation via manipulated wauth/wctx parameters.

### Remediation

- Validate the `wreply` and `wctx` parameters against a registered allowlist.
- Monitor for unusual federation partner references in wauth parameters.

---

## vendor-pingfederate-admin | PingFederate Admin Console Accessible | CRITICAL

The PingFederate administrative console is publicly accessible. This interface controls all federation configurations, partner connections, OAuth clients, and authentication policies. Public exposure creates significant risk of unauthorized configuration changes.

### Remediation

- Restrict admin console access to internal management networks only.
- Place the admin interface behind VPN with MFA requirement.

---

## vendor-authentik-user-api | Authentik Users API Accessible | HIGH

The Authentik users API is accessible. If unauthenticated access is permitted, this enables full user enumeration and potentially account manipulation, group membership changes, and permission escalation.

### Remediation

- Authentik API requires a valid session or API token. Verify no anonymous access is permitted.
- Restrict API access to authorized service accounts only.

---

## vendor-azure-legacy-auth | Azure AD Legacy Authentication Endpoint Accessible | HIGH

The Azure AD legacy authentication endpoint (`/common/oauth2/token`) is accessible. This endpoint accepts username/password credentials directly (ROPC flow) and is a primary target for credential stuffing against Microsoft 365 environments, bypassing MFA and Conditional Access.

### Remediation

- Block legacy authentication in Entra ID Conditional Access: create a policy blocking all legacy auth client apps.
- Monitor sign-in logs for legacy authentication attempts.
- Migrate all applications to modern authentication protocols.
