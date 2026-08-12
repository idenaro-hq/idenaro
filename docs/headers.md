## headers-overview | Security Headers | 

The Security Headers module fetches HTTP responses from authentication endpoints and validates the presence and configuration of browser security headers. These headers form a critical defense-in-depth layer around the authentication surface.

### Checks performed

- HTTP Strict Transport Security (HSTS): presence and max-age value
- Content-Security-Policy: presence (detailed analysis handled by the CSP module)
- X-Frame-Options: clickjacking protection
- X-Content-Type-Options: MIME sniffing prevention
- Referrer-Policy: referrer leakage control
- Permissions-Policy: browser feature access restrictions
- Subresource Integrity (SRI) on externally loaded scripts
- Cross-Origin-Opener-Policy (COOP): cross-origin isolation
- Server and technology version disclosure in response headers

---

## headers-hsts | Missing HSTS | HIGH

Without HTTP Strict Transport Security, browsers will follow HTTP redirects and users are vulnerable to SSL stripping attacks that downgrade HTTPS connections to HTTP, allowing traffic interception.

### Remediation

- Add: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- Start with a short max-age (300s) and increase after confirming HTTPS works correctly.
- Submit to the HSTS preload list at hstspreload.org for browser-level enforcement.

---

## headers-csp | Missing or Weak Content Security Policy | MEDIUM

Without CSP, injected JavaScript runs with full page privileges. On login portals, injected scripts can harvest credentials and steal session tokens. `unsafe-inline` in script-src negates virtually all XSS protection.

### Remediation

- Start with: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`
- Use nonces or hashes instead of `unsafe-inline`.
- Deploy in report-only mode first to identify violations before enforcing.

---

## headers-xframe | Missing X-Frame-Options | MEDIUM

Without frame protection, login pages can be embedded in iframes on attacker-controlled sites. Clickjacking attacks overlay transparent iframes to capture credentials or trigger authenticated actions without the user's awareness.

### Remediation

- Add: `X-Frame-Options: DENY`
- Or use CSP: `frame-ancestors 'none'` which takes precedence in modern browsers.

---

## headers-xcto | Missing X-Content-Type-Options | LOW

Without `nosniff`, browsers may MIME-sniff responses away from the declared content type. An attacker who can upload files to the server can cause them to execute as scripts by exploiting MIME sniffing.

### Remediation

- Add: `X-Content-Type-Options: nosniff`

---

## headers-referrer | Missing Referrer-Policy | LOW

Without a referrer policy, authentication tokens or session IDs in URLs may be leaked via the Referer header to third-party resources loaded on auth pages (analytics, fonts, CDNs).

### Remediation

- Add: `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`

---

## headers-permissions | Missing Permissions-Policy | INFO

Permissions-Policy restricts browser feature access (camera, microphone, geolocation). On identity portals it reduces the attack surface available to any injected script or malicious iframe.

### Remediation

- Add: `Permissions-Policy: geolocation=(), camera=(), microphone=()`

---

## headers-sri | Subresource Integrity (SRI) Absent on CDN Scripts | MEDIUM

External scripts loaded from CDNs without SRI hashes will execute even if the CDN is compromised and serves malicious content. On login pages, this creates a supply chain attack vector for credential theft.

### Remediation

- Add `integrity` and `crossorigin` attributes to all external script and link tags.
- Generate hashes using: `openssl dgst -sha384 -binary script.js | openssl base64 -A`
- Consider self-hosting critical scripts to eliminate CDN dependency.

---

## headers-coop | Cross-Origin-Opener-Policy Missing | LOW

Without COOP, pages opened from your site retain a browsing context group with the opener. This allows cross-origin pages to access the `window` object of your login page and execute timing attacks or XS-Leaks.

### Remediation

- Add: `Cross-Origin-Opener-Policy: same-origin`

---

## headers-info-disclosure | Server/Technology Version Disclosure | LOW

Response headers (Server, X-Powered-By, X-AspNet-Version, X-Generator) reveal the web server software and version. This aids targeted exploitation by allowing attackers to look up known CVEs for the specific version in use.

### Remediation

- Suppress the Server header: Nginx: `server_tokens off;`, Apache: `ServerTokens Prod`
- Remove X-Powered-By in application configuration.
- In ASP.NET: `<httpRuntime enableVersionHeader="false"/>`
