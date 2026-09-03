## redirects-overview | Redirects | 

The Redirects module probes login, logout, and OAuth callback endpoints for open redirect vulnerabilities and debug information leakage. Open redirects on authentication surfaces can be chained with phishing attacks or used to steal OAuth authorization codes.

### Checks performed

- Redirect parameter presence on login pages (`next`, `return_to`, `redirect_uri`, etc.)
- Open redirect on logout endpoint: off-domain redirect accepted without allowlisting
- Debug or error information leaked in OAuth callback or redirect endpoint responses

---

## redirects-param | Redirect Parameter on Login Page | MEDIUM

The login page references a redirect parameter (redirect=, returnUrl=, next=, etc.). If this parameter is not validated against an allowlist, it enables open redirect attacks. Combined with OIDC flows, open redirects become authorization code theft vectors.

### Remediation

- Validate all redirect parameters against a strict allowlist of registered URLs.
- Reject or sanitize any value not on the allowlist.
- Never redirect to arbitrary external URLs based on user-supplied input.

---

## redirects-open | Open Redirect on Logout Endpoint | HIGH

The logout endpoint redirected to an attacker-controlled URL injected via `post_logout_redirect_uri`. After legitimate logout, users are sent to a convincing fake login page, enabling credential phishing.

### Remediation

- Validate `post_logout_redirect_uri` against a registered allowlist.
- Reject any URI not pre-registered for the client.
- For OIDC: use the `post_logout_redirect_uris` client metadata field.

---

## redirects-debug-leak | Debug Information Leaked on Callback Endpoint | MEDIUM

A callback or redirect endpoint returned what appears to be a stack trace or debug output when accessed without a valid authorization context. This reveals implementation details, framework versions, and internal file paths useful for targeted attacks.

### Remediation

- Disable debug output in production. Return generic error pages for all error conditions.
- Ensure framework debug mode is disabled in production deployments.
