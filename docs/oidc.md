## oidc-overview | OIDC / OAuth2 | 

The OIDC / OAuth2 module analyzes OpenID Connect and OAuth 2.0 identity provider configurations. It fetches the `/.well-known/openid-configuration` discovery document and inspects supported flows, signing algorithms, redirect URI registrations, and advanced security features - all without credentials.

### Checks performed

- Discovery document accessibility and content
- Supported grant types: implicit flow, hybrid flow, ROPC, device authorization
- PKCE support and S256 method enforcement
- Token signing algorithm security (alg=none, symmetric HS256)
- Issuer validation: HTTPS enforcement, host matching, internal hostname leakage
- Endpoint HTTPS enforcement across all advertised URLs
- Redirect URI safety: wildcards, HTTP URIs, localhost, IP addresses
- Advanced features: PAR, JAR, token revocation endpoint presence
- Token endpoint client authentication requirements

---

## oidc-discovery | OIDC Discovery Endpoint Exposed | INFO

The OpenID Connect discovery document at `/.well-known/openid-configuration` is publicly accessible. This is expected per the OIDC specification but exposes the complete IdP configuration including endpoint URLs, supported algorithms, and grant types.

### What to check

- Ensure no internal hostnames, private IPs, or staging domain names appear in any endpoint URL.
- Verify the issuer matches the public-facing hostname exactly.
- Confirm no weak algorithms or insecure flows are advertised.

---

## oidc-implicit | Implicit Flow Enabled | MEDIUM

The implicit OAuth2 flow (`response_type=token` or `response_type=id_token`) returns tokens directly in the URL fragment after authorization. These tokens are visible in browser history, server access logs, and HTTP Referer headers. The flow is deprecated in OAuth 2.1.

### Remediation

- Disable `response_type=token` and `response_type=id_token` in your IdP.
- Migrate all clients to Authorization Code flow with PKCE (RFC 7636).
- Keycloak: Realm → Clients → client → uncheck "Implicit Flow Enabled".

---

## oidc-hybrid | Hybrid Flow Enabled | MEDIUM

The hybrid flow (`code token` or `code id_token`) mixes authorization code and token responses. Tokens returned in the front channel via URL fragment bypass PKCE protections, creating token leakage risk even when code flow is also active.

### Remediation

- Disable hybrid flows and use pure Authorization Code + PKCE.
- Ensure no `response_type` combinations include `token` or `id_token` alongside `code`.

---

## oidc-multi-insecure | Multiple Insecure Flows Enabled | HIGH

Two or more insecure response types (implicit, hybrid) are simultaneously active. Each adds attack surface; together they significantly increase the likelihood that tokens can be obtained through front-channel leakage.

### Remediation

- Disable all flows except `code`.
- Enable PKCE requirement for all code flows.
- Audit all registered clients and remove unused response_type grants.

---

## oidc-ropc | ROPC Grant Enabled | HIGH

The Resource Owner Password Credentials grant (`password`) allows clients to collect user credentials directly and exchange them for tokens. This completely bypasses MFA, browser-based authentication, and Conditional Access policies. Deprecated in OAuth 2.1.

### Remediation

- Disable the `password` grant type in your IdP.
- Migrate any ROPC clients to Authorization Code + PKCE.
- Keycloak: Clients → client → uncheck "Direct Access Grants".

---

## oidc-device-flow | Device Authorization Grant Enabled | MEDIUM

The device authorization grant (device flow) is designed for input-constrained devices. On public-facing IAM systems it is abused in device code phishing attacks where attackers trick users into authorizing attacker-controlled device sessions.

### Remediation

- Disable device flow if not required for legitimate device clients.
- If required: limit to specific, registered client IDs. Do not advertise publicly.
- Implement short expiry on device codes (max 5 minutes).

---

## oidc-fragment-mode | Fragment response_mode Supported | LOW

The fragment response mode delivers tokens and codes in the URL hash fragment. Hash fragments are accessible to JavaScript, logged in browser history, and can leak via the Referer header to external resources loaded on the redirect page.

### Remediation

- Prefer `form_post` response mode for all authorization responses.
- If fragment mode is required, ensure redirect pages load no external resources that could read the fragment.

---

## oidc-pkce | PKCE Not Supported | MEDIUM

Proof Key for Code Exchange (RFC 7636) prevents authorization code interception attacks by binding the authorization code to a cryptographic verifier known only to the legitimate client. Without PKCE, intercepted codes can be exchanged for tokens by an attacker.

### Remediation

- Enable PKCE with the S256 method in your IdP.
- Require PKCE for all public clients (SPAs, mobile apps).
- Keycloak 21+: PKCE is enabled by default. For older versions, set "PKCE Code Challenge Method" per client.

---

## oidc-pkce-plain | PKCE S256 Not Supported (plain only) | LOW

Only the `plain` PKCE method is supported. The plain method transmits the code verifier in cleartext during the token exchange, providing weaker protection than S256 which hashes the verifier before transmission.

### Remediation

- Enable `S256` and disable or deprioritize `plain`.
- Require S256 for all new clients.

---

## oidc-alg-none | Algorithm alg=none Allowed | CRITICAL

`alg=none` disables JWT signature verification entirely. Any client can forge a token by setting the algorithm to `none` and removing the signature. This is a complete authentication bypass.

### Remediation

- Remove `none` from `id_token_signing_alg_values_supported` immediately.
- Verify your token validation library explicitly rejects `alg=none`.
- Rotate all existing tokens after the change.

---

## oidc-alg-symmetric | Symmetric Signing Algorithm (HS256) | MEDIUM

Symmetric algorithms (HS256, HS384, HS512) require sharing the signing secret with all token validators. This creates key management risk and enables algorithm confusion attacks where a public key is used as an HMAC secret.

### Remediation

- Use asymmetric algorithms: RS256 or ES256.
- Keycloak: Realm Settings → Tokens → Default Signature Algorithm → RS256.
- If HS256 is required for legacy clients, restrict it to specific clients only.

---

## oidc-issuer-https | OIDC Issuer Does Not Use HTTPS | HIGH

The issuer value in the discovery document does not use HTTPS. Per RFC 8414, the issuer must be an `https://` URI. Clients that validate the issuer will reject tokens, and clients that don't will accept tokens from unauthenticated sources.

### Remediation

- Set the IdP's public URL to an `https://` URI.
- Keycloak: set `KC_HOSTNAME` or `--hostname` to the public HTTPS hostname.

---

## oidc-issuer-mismatch | OIDC Issuer Host Mismatch | MEDIUM

The discovery document is served from a different host than the `issuer` value. This indicates a broken reverse proxy setup, split-DNS misconfiguration, or incomplete migration. Clients that validate issuer binding will fail.

### Remediation

- Ensure the IdP's configured public hostname matches the URL from which the discovery document is served.
- Fix reverse proxy X-Forwarded-Host header rewriting.
- Keycloak: `KC_HOSTNAME` must match the external load balancer hostname.

---

## oidc-internal-leak | Discovery Document Contains Internal Hostname | MEDIUM

The OIDC discovery document references internal hostnames (localhost, private IPs, .internal, .corp, Kubernetes service names, staging domains). These are permanently logged in Certificate Transparency logs and aid attacker reconnaissance.

### Remediation

- Configure the IdP's public-facing hostname explicitly.
- Ensure all endpoint URLs use the public hostname, not internal container or service names.
- Keycloak: set `KC_HOSTNAME` to the public external hostname.

---

## oidc-endpoint-https | OIDC Endpoint Does Not Use HTTPS | HIGH

One or more OIDC endpoints (authorization, token, JWKS, userinfo) are served over HTTP. Auth codes, tokens, and user data transmitted over HTTP are visible to network observers.

### Remediation

- All OIDC endpoints must be served exclusively over TLS.
- Configure the web server to redirect HTTP to HTTPS with a 301 permanent redirect.
- Enable HSTS to prevent future HTTP access.

---

## oidc-wildcard-redirect | Wildcard redirect_uri Registered | HIGH

A wildcard pattern in a registered redirect_uri allows authorization codes to be delivered to any URL matching the pattern. An attacker with a subdomain on the same domain can receive authorization codes.

### Remediation

- Register only exact, fully qualified redirect URIs.
- Never use wildcard patterns (`*`) in redirect URIs.
- Audit all registered clients for wildcard redirects.

---

## oidc-http-redirect | HTTP redirect_uri Registered | HIGH

A non-localhost redirect URI uses HTTP instead of HTTPS. Authorization codes delivered to HTTP endpoints are visible to network observers and proxy logs.

### Remediation

- All redirect URIs must use HTTPS, except for localhost development URIs.
- Update all client registrations to use HTTPS redirect URIs.

---

## oidc-localhost-redirect | Localhost redirect_uri in Production | LOW

A localhost redirect URI is registered on a production IdP. While valid for native desktop applications, localhost URIs in production configurations are often forgotten development artifacts from testing.

### Remediation

- Remove localhost redirect URIs from production client registrations.
- Use separate development client registrations with localhost URIs.

---

## oidc-ip-redirect | IP Address redirect_uri Registered | MEDIUM

A redirect URI uses a raw IP address instead of a hostname. IP-based redirect URIs bypass hostname-based security controls, are harder to audit, and may indicate a misconfigured or development-era registration in production.

### Remediation

- Use hostname-based redirect URIs.
- Replace IP addresses with DNS names in all client registrations.

---

## oidc-par | Pushed Authorization Requests (PAR) Not Supported | INFO

PAR (RFC 9126) moves authorization parameters from the front channel (URL) to a back-channel server-to-server request before redirecting the user. This prevents parameter tampering and reduces token exposure in browser URLs.

### Remediation

- Consider enabling PAR for high-security authorization flows.
- Require PAR for confidential clients handling sensitive data.

---

## oidc-token-endpoint-auth-none | Token Endpoint Allows Unauthenticated Clients | MEDIUM

The token endpoint advertises `none` as a supported client authentication method. This allows public clients to exchange authorization codes without any client authentication, enabling authorization code interception attacks if PKCE is not enforced.

### Remediation

- Require PKCE for all public clients using `none` authentication.
- For confidential clients, require `client_secret_basic` or `private_key_jwt`.
- Never allow `none` auth for clients handling sensitive scopes.

---

## oidc-jar | JWT Secured Authorization Requests (JAR) Not Supported | INFO

JAR (RFC 9101) allows authorization request parameters to be transmitted as a signed JWT, preventing front-channel parameter tampering. Its absence means authorization parameters can be modified in transit by a network attacker.

### Remediation

- Enable JAR support and require signed request objects for high-security clients.
- Combine with PAR for maximum front-channel protection.

---

## oidc-revocation | Token Revocation Endpoint Missing | LOW

No token revocation endpoint (RFC 7009) is advertised. Without revocation support, compromised tokens remain valid until expiry. Logout flows that rely on revocation will fail silently.

### Remediation

- Implement and advertise a token revocation endpoint.
- Ensure logout flows call the revocation endpoint for all active tokens.
- Use short token lifetimes as a compensating control.

---

## oidc-request-uri-ssrf | request_uri Parameter Supported Without Allowlisting | MEDIUM

When `request_uri_parameter_supported: true` is set without a strict allowlist of permitted URIs, the IdP will fetch authorization request objects from arbitrary URLs supplied by the client. This creates a Server-Side Request Forgery (SSRF) vector through the authorization endpoint.

### Remediation

- Implement a strict allowlist of permitted request_uri values per client registration.
- Block requests to internal IP ranges and metadata endpoints.
- Disable request_uri support if JAR via direct request object is sufficient.

---

## oidc-multi-domain | OIDC Endpoints Span Multiple Domains | LOW

The OIDC endpoints (issuer, authorization, token, JWKS, userinfo) reference more than two distinct hostnames. This indicates a complex or fragmented deployment where trust boundaries are unclear and federation partners may have difficulty validating endpoints.

### Remediation

- Consolidate OIDC endpoints under a single domain where possible.
- Document and justify any legitimate cross-domain endpoint distribution.
