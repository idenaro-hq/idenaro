## endpoints-overview | Endpoints | 

The Endpoints module probes for sensitive administrative, diagnostic, and infrastructure endpoints that are reachable without authentication on the target host. Exposure of these endpoints typically provides direct exploitation paths for privilege escalation, data extraction, or remote code execution.

### Checks performed

- Admin panel paths (`/admin`, `/administrator`, `/wp-admin`, etc.)
- Spring Boot Actuator endpoints: `env`, `heapdump`, `mappings`, `beans`
- Environment files: `.env`, `.env.production`, `.env.local`
- Debug and diagnostic endpoints
- ADFS WS-Trust endpoint (`/adfs/services/trust`)
- Exchange Web Services (EWS): `/ews/exchange.asmx`
- Kubernetes API server accessibility
- HashiCorp Vault HTTP API
- GraphQL introspection query enabled

---

## endpoints-admin | Admin Panel Publicly Accessible | HIGH

An administrative interface is accessible from the public internet. Admin panels are prime targets for credential stuffing, brute force attacks, and exploitation of known IdP vulnerabilities. A single compromised admin credential grants full system control.

### Remediation

- Restrict admin interfaces to internal networks or VPN-only access at the network perimeter.
- Keycloak: use `--hostname-admin` to serve the admin console on a separate internal hostname.
- Require MFA for all administrative authentication.

---

## endpoints-actuator-env | Spring Boot Environment Variables Exposed | CRITICAL

The Spring Boot Actuator `/actuator/env` endpoint is publicly accessible. This endpoint exposes all environment variables, including database passwords, API keys, OAuth secrets, and any other secrets configured as environment variables.

### Remediation

- Disable or restrict `/actuator/env` immediately.
- Rotate all secrets that may have been exposed.
- Bind the management server to an internal port: `management.server.address=127.0.0.1`

---

## endpoints-dotenv | Environment File (.env) Exposed | CRITICAL

The `/.env` file is publicly accessible. This file typically contains database credentials, API keys, OAuth client secrets, encryption keys, and other sensitive configuration. All secrets in this file must be considered compromised.

### Remediation

- Remove the .env file from the web root immediately.
- Rotate all secrets that appeared in the file.
- Configure the web server to deny access to dotfiles.
- Store secrets in a secrets manager (Vault, AWS Secrets Manager) instead of files.

---

## endpoints-debug | Debug Endpoint Exposed | HIGH

A debug endpoint (/debug, /debug/vars, /actuator) is publicly accessible. Debug endpoints expose runtime configuration, memory state, goroutine stacks, environment variables, and internal topology - all of which aid targeted attacks.

### Remediation

- Remove all debug endpoints from production deployments.
- If monitoring is required, bind to an internal interface and restrict by IP.
- Require authentication for all monitoring and metrics endpoints.

---

## endpoints-adfs-wstrust | ADFS WS-Trust Endpoint Exposed | CRITICAL

The ADFS WS-Trust `usernamemixed` endpoint accepts plaintext username/password credentials. This endpoint completely bypasses MFA and Conditional Access policies and is the primary target for password spray attacks against Microsoft environments.

### Remediation

- Block this endpoint at the perimeter if not required for legacy clients.
- Enable Entra ID Smart Lockout and sign-in risk policies.
- Migrate legacy clients to modern authentication protocols.

---

## endpoints-ews | Exchange Web Services (EWS) Exposed | CRITICAL

The Exchange Web Services endpoint supports Basic authentication and is a primary target for credential stuffing and password spray attacks. On most configurations it bypasses MFA, and it is responsible for a large share of Office 365 account compromises.

### Remediation

- Disable Basic authentication on EWS.
- Block legacy authentication in Entra ID Conditional Access.
- Migrate EWS clients to Microsoft Graph API.

---

## endpoints-k8s | Kubernetes API Accessible | CRITICAL

The Kubernetes API server is publicly accessible. An unauthenticated or weakly authenticated Kubernetes API provides access to secrets (including OAuth tokens and certificates), allows workload manipulation, and can enable full cluster takeover.

### Remediation

- Restrict Kubernetes API access to internal networks only.
- Disable anonymous authentication: `--anonymous-auth=false`
- Enable RBAC and audit logging.
- Use network policies to restrict API server access to authorized nodes only.

---

## endpoints-vault | HashiCorp Vault API Accessible | HIGH

The HashiCorp Vault API is publicly accessible. Vault stores the most sensitive credentials in the environment. Even if authentication is required, public exposure creates unnecessary attack surface against the secret management system.

### Remediation

- Restrict Vault API access to internal networks or VPN.
- Enable Vault audit logging.
- Use network-level access control as a defence-in-depth measure.

---

## endpoints-graphql-introspection | GraphQL Introspection Enabled | MEDIUM

GraphQL introspection is enabled in production. Introspection allows any client to enumerate the complete API schema including all types, queries, mutations, and arguments. On identity APIs, this reveals all administrative, user management, and auth routes.

### Remediation

- Disable introspection in production: most GraphQL libraries support an `introspection: false` option.
- If introspection is needed for development, restrict it to authenticated admin users.
