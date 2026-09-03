## cookies-overview | Cookies | 

The Cookies module inspects session and authentication cookies returned from auth endpoints. It validates security attributes that prevent session hijacking, cross-site request forgery, and token theft via JavaScript or network interception.

### Checks performed

- `Secure` flag: cookie transmission restricted to HTTPS
- `HttpOnly` flag: JavaScript access prevention
- `SameSite` attribute: CSRF cross-origin submission control
- `SameSite=None` without `Secure`: credential exposure over HTTP
- Persistent cookie expiry: excessively long session lifetime
- Overly broad `Domain` scope spanning subdomains
- Multiple session cookie indicators suggesting misconfiguration

---

## cookies-secure | Session Cookie Missing Secure Flag | HIGH

A session or authentication cookie is set without the `Secure` flag. It will be transmitted over HTTP connections, exposing the session token to interception on any network path where HTTP is reachable.

### Remediation

- Set the `Secure` attribute on all authentication and session cookies.
- Combine with HSTS to ensure HTTP connections are never made.

---

## cookies-httponly | Session Cookie Missing HttpOnly Flag | MEDIUM

A session cookie is accessible via JavaScript (`document.cookie`). Any XSS vulnerability on the domain allows direct theft of the session token without further exploitation.

### Remediation

- Set `HttpOnly` on all session and authentication cookies.
- Note: HttpOnly does not prevent XSS but limits its impact.

---

## cookies-samesite | Cookie Missing SameSite Attribute | LOW

Without `SameSite`, cookies are included in cross-site requests, enabling CSRF attacks. An attacker can trigger authenticated state-changing actions by embedding requests in a malicious page.

### Remediation

- Set `SameSite=Strict` for session cookies where no cross-site navigation is needed.
- Use `SameSite=Lax` if top-level GET navigation from external sites must include the cookie.
- Never use `SameSite=None` without the `Secure` flag.

---

## cookies-samesite-none | SameSite=None Without Secure Flag | HIGH

`SameSite=None` requires the `Secure` flag. Without it, the cookie is either rejected by modern browsers (creating a functionality issue) or transmitted insecurely over HTTP (creating a security issue).

### Remediation

- Add the `Secure` flag alongside `SameSite=None`.
- Review whether `SameSite=None` is actually required for cross-site usage.

---

## cookies-persistent | Session Cookie Has Long Persistent Expiry | LOW

A session cookie has an explicit expiry of more than 24 hours. Persistent session cookies survive browser restarts and extend the window for session hijacking after device theft or sharing.

### Remediation

- Use session-scoped cookies (no Expires/Max-Age) for authentication sessions.
- If persistence is required for UX, limit to 8-24 hours and implement idle timeout.

---

## cookies-broad-domain | Cookie Scoped to Overly Broad Domain | MEDIUM

A session cookie has a wildcard domain scope covering all subdomains. A subdomain takeover or XSS vulnerability on any subdomain allows theft of the authentication cookie across the entire domain.

### Remediation

- Scope authentication cookies to the specific hostname, not a wildcard domain.
- Do not set the `Domain` attribute unless cross-subdomain access is specifically required.

---

## cookies-multiple | Multiple Session Cookies Detected | LOW

More than two distinct session or authentication cookie names are set. This indicates a fragmented session architecture where ensuring all cookies have correct security flags and are all invalidated on logout is more difficult.

### Remediation

- Consolidate to a single session cookie per application context.
- Audit logout flows to ensure all session cookies are cleared server-side.
