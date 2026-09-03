## cors-overview | CORS | 

The CORS module tests Cross-Origin Resource Sharing policies on authentication, token, and API endpoints. It probes using crafted `Origin` headers and inspects `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` response headers for dangerous configurations.

### Checks performed

- Wildcard `Access-Control-Allow-Origin: *` on endpoints that handle credentials
- Origin reflection: server mirrors the request `Origin` while also allowing credentials
- Null origin acceptance combined with `Allow-Credentials: true`
- Preflight cache duration: aggressive `Access-Control-Max-Age` values

---

## cors-wildcard | Wildcard CORS on Auth Endpoint | HIGH

`Access-Control-Allow-Origin: *` on token, user, or session endpoints allows any website to make cross-origin requests and read the response. This enables cross-origin credential and token theft from any malicious website.

### Remediation

- Never use wildcard CORS on authenticated endpoints.
- Maintain an explicit allowlist of trusted origins validated server-side.

---

## cors-reflected | Reflected CORS Origin with Credentials | CRITICAL

The server reflects the request Origin header back in `Access-Control-Allow-Origin` combined with `Access-Control-Allow-Credentials: true`. Any website can make credentialed cross-origin requests to this endpoint and read the response, enabling account takeover.

### Remediation

- Validate Origin against a strict allowlist before reflecting it.
- Never combine a dynamic/reflected ACAO with `ACAC: true`.

---

## cors-null-origin | Null Origin Accepted with Credentials | HIGH

The null origin is accepted with credentials. The null origin can be triggered from sandboxed iframes, file:// pages, and redirected cross-origin requests, enabling credential theft from local HTML files or sandboxed contexts.

### Remediation

- Never allow the null origin in CORS policy.
- Explicitly reject null origin requests in server-side CORS validation.

---

## cors-max-age | CORS Preflight Caching Too Aggressive | LOW

`Access-Control-Max-Age` is set to more than 86400 seconds (24 hours). Extended preflight caching means CORS policy changes take longer than a day to take effect, delaying incident response when a misconfiguration is discovered.

### Remediation

- Set `Access-Control-Max-Age` to a maximum of 86400 (24 hours).
- For security-sensitive endpoints, use shorter cache durations (e.g. 600 seconds).
