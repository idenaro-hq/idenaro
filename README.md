# Idenaro

Active CLI scanner for identity and access management (IAM) misconfigurations.
Targets web-facing IdP infrastructure - OIDC, SAML, security headers, exposed
endpoints - by sending unauthenticated probe requests, without credentials,
payload injection, or port scanning.

This is the **free, open-source tier**. It ships the core scanner and its
free modules. A [pro tier](#pro-tier) adds more modules, NIS2 Art. 21
compliance mapping/reporting, and a desktop UI.

## Modules

| Module      | What it checks                                                        |
|-------------|-----------------------------------------------------------------------|
| `oidc`      | OIDC discovery, implicit flow, PKCE, wildcard redirect URIs, HTTPS    |
| `saml`      | Metadata exposure, HTTP-Redirect binding, unsigned assertions, certs  |
| `headers`   | HSTS, CSP, X-Frame-Options, info leakage (Server/X-Powered-By, etc.)  |
| `endpoints` | Exposed admin panels, actuator, debug, .env, metrics, GraphQL         |
| `client`    | Relying-party checks against a client application URL (`--client`)   |

Run `idenaro modules` to list them from the binary itself.

---

## Build

```bash
# Prerequisites: Go 1.25+
make deps
make build
# Binary: bin/idenaro
```

### Cross-platform release builds
```bash
make release
# dist/idenaro-linux-amd64
# dist/idenaro-darwin-amd64
# dist/idenaro-darwin-arm64
# dist/idenaro-windows.exe
```

---

## Usage

```bash
# Basic scan (text output)
idenaro scan --target auth.example.com

# Multiple targets
idenaro scan --target auth.example.com --target sso.example.com

# From file (one host per line, # comments supported)
idenaro scan --targets targets.txt

# HTML report for a client
idenaro scan --target auth.example.com --format html --output report.html

# JSON for CI/CD pipelines
idenaro scan --target auth.example.com --format json \
  | jq '.results[].findings[] | select(.severity=="HIGH" or .severity=="CRITICAL")'

# Specific modules only
idenaro scan --target auth.example.com --modules oidc,headers

# Keycloak realm other than "master"
idenaro scan --target auth.example.com --realm myrealm

# Check a relying-party client application (client module)
idenaro scan --target auth.example.com --client https://app.example.com

# Self-signed cert / internal targets
idenaro scan --target internal.corp.local --skip-tls-verify

# German report output
idenaro scan --target auth.example.com --lang de

# Verbose progress, or plain output for CI (no colors/progress bar)
idenaro scan --target auth.example.com -v
idenaro scan --target auth.example.com --plain

# List available modules
idenaro modules
```

Run `idenaro scan --help` for the full flag reference.

---

## Architecture

```
idenaro/
├── cmd/scanner/                   # CLI entrypoint (cobra)
├── internal/
│   ├── config/                     # Flags, target parsing, FreeModules list
│   ├── engine/                    # Concurrent per-target module orchestration
│   ├── modules/
│   │   ├── module.go              # Module interface + Target struct
│   │   └── free/
│   │       ├── oidc/
│   │       ├── saml/
│   │       ├── headers/
│   │       ├── endpoints/
│   │       └── client/
│   ├── finding/                    # Finding struct + severity
│   ├── scoring/                   # Risk score calculation
│   ├── i18n/                      # en/de report strings + module docs
│   └── report/                    # JSON, HTML, and text output
└── pkg/httpclient/                # Shared HTTP client
```

---

## Legal

This tool performs **active, unauthenticated reconnaissance** - it sends probe
requests to the target's exposed endpoints, but makes no authentication
attempts, no payload injection, and no port scanning.

**Always obtain written permission before scanning systems you do not own.**

---

## Pro tier

The free CLI covers the core IdP-facing checks. The pro tier (closed-source,
[idenaro.com](https://idenaro.com)) adds:

- Additional modules: cookies, CORS, CSP, enumeration, lifecycle, MFA,
  redirects, SCIM, TLS, tokens, and a pro `client` variant
- NIS2 Art. 21 compliance mapping and PDF compliance reports
- A free-to-use desktop UI (Wails-based), with pro modules unlocked by license
