## csp-overview | CSP | 

The CSP module parses and analyzes `Content-Security-Policy` and `Content-Security-Policy-Report-Only` headers returned from authentication endpoints. A weak or missing CSP on auth pages enables cross-site scripting attacks that can steal session tokens or credentials.

### Checks performed

- Report-only mode: CSP present but not enforced
- `unsafe-inline` in `script-src`: allows inline script injection
- `unsafe-eval` in `script-src`: allows dynamic code execution
- Wildcard sources (`*`) in any directive
- Missing `frame-ancestors`: clickjacking protection gap
- Missing `form-action`: uncontrolled form submission targets
- Missing `base-uri`: base tag injection risk
- Missing `default-src` fallback directive

---

## csp-report-only | CSP in Report-Only Mode | MEDIUM

`Content-Security-Policy-Report-Only` is present but enforcement mode is absent. Report-only mode collects violations but does not block anything. This provides no actual XSS protection.

### Remediation

- Promote CSP from report-only to enforcement mode.
- Use report-only only during initial rollout. Transition to enforcement within a defined timeframe.

---

## csp-unsafe-inline | CSP Allows unsafe-inline Scripts | HIGH

`unsafe-inline` in script-src allows inline JavaScript execution, completely negating XSS protection on this page. Login pages with this setting are fully vulnerable to injected scripts that steal credentials.

### Remediation

- Remove `unsafe-inline` from script-src.
- Replace inline event handlers and script blocks with external scripts.
- Use nonces or hashes for any remaining legitimate inline scripts.

---

## csp-unsafe-eval | CSP Allows unsafe-eval | MEDIUM

`unsafe-eval` permits dynamic JavaScript execution via `eval()`, `Function()`, `setTimeout(string)`, and similar constructs. Attackers who can inject data into these call sites achieve XSS despite CSP being present.

### Remediation

- Remove `unsafe-eval` from script-src.
- Refactor code that uses `eval()` or `new Function()`.

---

## csp-wildcard-src | CSP Uses Wildcard Source | MEDIUM

A wildcard (`*`) in script-src, style-src, frame-src, or connect-src allows resources from any origin, defeating the purpose of CSP for that resource type.

### Remediation

- Replace wildcards with explicit trusted origins.
- Use `default-src 'self'` as a safe baseline and explicitly allow only necessary external sources.

---

## csp-frame-ancestors | CSP Missing frame-ancestors | MEDIUM

The `frame-ancestors` directive is absent. This is the modern replacement for X-Frame-Options and prevents login page embedding in iframes for clickjacking attacks. In modern browsers, CSP `frame-ancestors` takes precedence over X-Frame-Options.

### Remediation

- Add: `frame-ancestors 'none'` to prevent all framing.
- Use `frame-ancestors 'self'` only if the application legitimately embeds itself.

---

## csp-form-action | CSP Missing form-action | LOW

Without `form-action`, any form on the page can POST to any URL. If an attacker can inject a form or modify form targets via XSS, credentials are sent to attacker infrastructure.

### Remediation

- Add: `form-action 'self'` to restrict where forms can submit data.

---

## csp-base-uri | CSP Missing base-uri | LOW

Without `base-uri`, an attacker who can inject a `<base>` tag can redirect all relative URLs (script sources, form actions, links) to an attacker-controlled origin.

### Remediation

- Add: `base-uri 'self'` or `base-uri 'none'` to prevent base tag injection.

---

## csp-no-default | CSP Has No default-src Fallback | MEDIUM

The CSP policy has no `default-src` directive. Resource types not explicitly listed in other directives fall back to allowing all sources. This creates silent coverage gaps for resource types the developer did not consider.

### Remediation

- Add `default-src 'none'` or `default-src 'self'` as a safe baseline.
- Explicitly allow only the specific resource types your application needs.
