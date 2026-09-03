## tokens-overview | Token Leakage | 

The Token Leakage module fetches and analyzes JavaScript files loaded by authentication pages, searching for hardcoded credentials and insecure client-side token storage patterns. Tokens exposed in JavaScript are readable by any script on the page and by anyone with access to the source.

### Checks performed

- Hardcoded access tokens in JavaScript source
- OAuth client secrets embedded in JavaScript
- Authentication tokens stored in `localStorage`
- Authentication tokens stored in `sessionStorage`
- Authentication tokens on the global `window` object
- OAuth `client_id` values in JavaScript (informational)
- API keys embedded in JavaScript source

---

## tokens-access-token | Access Token Hardcoded in JavaScript | CRITICAL

An access token value is hardcoded in JavaScript source code. Access tokens grant API access on behalf of a user or service. Any visitor can extract this token and use it to make authenticated API calls until the token expires or is revoked.

### Remediation

- Remove the token from source code immediately.
- Rotate the token to invalidate any copies.
- Use a Backend-for-Frontend (BFF) pattern where tokens are held server-side.

---

## tokens-client-secret | OAuth Client Secret Exposed in JavaScript | CRITICAL

An OAuth client secret is present in JavaScript source code. Client secrets are credentials that authenticate the OAuth client to the authorization server. Any visitor can use this secret to impersonate the application, obtain tokens, and make authenticated API calls.

### Remediation

- Revoke the exposed client secret and generate a new one immediately.
- Client secrets must never appear in frontend code - use the BFF pattern.
- For SPAs that genuinely cannot keep a secret, use public clients with PKCE only (no client secret).

---

## tokens-localstorage | Auth Token Stored in localStorage | HIGH

Authentication tokens are stored in `localStorage`, which is accessible to any JavaScript on the page. Any XSS vulnerability allows full token theft. Unlike HttpOnly cookies, localStorage provides no XSS protection.

### Remediation

- Store tokens in HttpOnly cookies for server-rendered apps.
- For SPAs: use in-memory storage with silent refresh via a BFF.
- If localStorage must be used, ensure strict CSP prevents XSS.

---

## tokens-sessionstorage | Auth Token Stored in sessionStorage | MEDIUM

Authentication tokens are stored in `sessionStorage`. While sessionStorage is cleared when the tab closes, it is still accessible to JavaScript and vulnerable to XSS-based theft.

### Remediation

- Prefer HttpOnly cookies over sessionStorage for token storage.
- If sessionStorage is used, implement strict CSP to mitigate XSS risk.

---

## tokens-window-global | Auth Token on Global window Object | HIGH

An authentication token is assigned to the global `window` object (e.g. `window.access_token`). Global variables are accessible to any script running on the page, including third-party scripts, browser extensions, and injected code.

### Remediation

- Use closures or module scope to restrict token visibility.
- Never assign tokens to global variables.

---

## tokens-client-id | OAuth client_id in JavaScript | INFO

An OAuth `client_id` is present in JavaScript. For public clients (SPAs, mobile apps) this is expected and not a vulnerability - `client_id` is not a secret. However, verify that the client is registered as a public client without a client secret, and that PKCE is enforced.

### What to verify

- Confirm the client is configured as a public client (no client secret).
- Verify PKCE is required for this client.
- Ensure the client has minimal scopes.

---

## tokens-api-key | API Key Exposed in JavaScript | MEDIUM

An API key is present in JavaScript source code. API keys in frontend JS are visible to all users of the application. Depending on the API, this can enable quota abuse, unauthorized data access, or be used for further reconnaissance.

### Remediation

- Proxy API calls through a backend server that holds the API key server-side.
- Rotate the exposed API key.
- If the API supports it, restrict the key by domain or IP.
