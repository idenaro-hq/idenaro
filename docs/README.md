# Module Documentation

English documentation for every finding produced by idenaro's free-tier
modules. Each file lists what the module checks and, for non-`INFO`
findings, a remediation.

These are the same descriptions the CLI embeds and prints in reports
(`internal/i18n/docs/modules/*.md` - the German translations live there
too, keyed by the `-de.md` suffix and applied via `--lang de`). This is
just the subset of that content most useful as standalone reading.

| Doc | Module | Findings covered |
|-----|--------|-------------------|
| [oidc.md](oidc.md) | `oidc` | Flow security (implicit/hybrid/ROPC/device), PKCE, token signing algorithm, issuer/endpoint HTTPS, redirect URI safety, PAR/JAR, token revocation |
| [saml.md](saml.md) | `saml` | Metadata exposure, signed AuthnRequest/assertion requirements, binding types (Redirect/SOAP/Artifact), certificate validity, Single Logout |
| [headers.md](headers.md) | `headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, SRI, COOP, server/technology disclosure |
| [endpoints.md](endpoints.md) | `endpoints` | Exposed admin panels, Spring Boot actuator env, `.env` files, debug endpoints, ADFS WS-Trust, EWS, Kubernetes API, HashiCorp Vault, GraphQL introspection |

> **Note:** the `client` module has no English doc source yet - only a
> German version (`client-de.md`) exists upstream, so `--lang de` gets
> localized client-module text but the default English output falls back
> to whatever's hardcoded in the module itself. Not covered here until
> that's written.

## Severity scale

| Severity | Meaning |
|----------|---------|
| `CRITICAL` | Direct path to full compromise; fix immediately |
| `HIGH` | Significant weakness with a realistic exploit path |
| `MEDIUM` | Weakens defenses; should be scheduled |
| `LOW` | Best-practice gap, limited exploitability alone |
| `INFO` | Observational - not a weakness by itself |

## See also

- [../README.md](../README.md) - CLI usage, build instructions, flags
