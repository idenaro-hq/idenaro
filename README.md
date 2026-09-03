# Idenaro

**Version 1.1.0**

Active CLI scanner (and desktop UI) for identity and access management (IAM)
misconfigurations. Targets web-facing IdP infrastructure - OIDC, SAML,
security headers, exposed endpoints, TLS, cookies, CORS, CSP, redirects,
tokens, MFA, lifecycle, SCIM, product/vendor fingerprinting, and endpoint
enumeration - by sending unauthenticated probe requests, without credentials,
payload injection, or port scanning.

This is a **single, fully open-source build**: the former free and pro tiers
have been merged into one product. Every module, NIS2 Art. 21 compliance
mapping/reporting, PDF compliance reports, and the desktop UI are included
unconditionally - there is no license, no activation, and no locked feature.

## Modules

| Module        | What it checks                                                        |
|---------------|-----------------------------------------------------------------------|
| `oidc`        | OIDC discovery, implicit flow, PKCE, wildcard redirect URIs, HTTPS    |
| `saml`        | Metadata exposure, HTTP-Redirect binding, unsigned assertions, certs  |
| `headers`     | HSTS, CSP, X-Frame-Options, info leakage (Server/X-Powered-By, etc.)  |
| `endpoints`   | Exposed admin panels, actuator, debug, .env, metrics, GraphQL         |
| `client`      | Relying-party checks against a client application URL (`--client`)   |
| `oidc-pro`    | Deeper OIDC checks (token endpoint auth, JARM, DPoP, PAR, etc.)       |
| `saml-pro`    | Deeper SAML checks (signature wrapping, replay, encryption)          |
| `tls`         | TLS/cert configuration, protocol/cipher weaknesses                   |
| `cookies`     | Session cookie flags (Secure, HttpOnly, SameSite)                    |
| `cors`        | CORS policy misconfiguration                                         |
| `csp`         | Content-Security-Policy quality analysis                             |
| `redirects`   | Open-redirect and redirect-URI validation issues                     |
| `tokens`      | Access/refresh token handling and exposure                           |
| `mfa`         | Multi-factor authentication enforcement gaps                         |
| `lifecycle`   | Session/account lifecycle handling                                   |
| `scim`        | SCIM provisioning endpoint exposure                                  |
| `products`    | IdP product/vendor fingerprinting                                    |
| `enumeration` | Username/realm enumeration                                           |
| `client-pro`  | Deeper relying-party checks (clickjacking, CSP quality, silent auth) |

Run `idenaro modules` to list them from the binary itself, or `idenaro --version`
to check the installed version against `VERSION` in the repo root.

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

### Desktop UI (Wails)

A cross-platform desktop application lives under `cmd/wails` (Go backend +
React/TypeScript frontend). See `cmd/wails/README` / `wails.json` for the
Wails-specific build steps (`wails build`). It exposes the same modules, NIS2
mapping, and PDF export as the CLI, with no license or activation step.

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
idenaro scan --target auth.example.com --modules oidc,headers,tls,cookies

# Keycloak realm other than "master"
idenaro scan --target auth.example.com --realm myrealm

# Check a relying-party client application (client + client-pro modules)
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
├── cmd/
│   ├── scanner/                   # CLI entrypoint (cobra)
│   └── wails/                     # Desktop UI (Go backend + React frontend)
├── internal/
│   ├── config/                    # Flags, target parsing, module lists
│   ├── engine/                    # Concurrent per-target module orchestration
│   ├── modules/
│   │   ├── module.go              # Module interface + Target struct
│   │   ├── free/                  # oidc, saml, headers, endpoints, client
│   │   └── pro/                   # oidc, saml, tls, cookies, cors, csp,
│   │                               # redirects, tokens, mfa, lifecycle, scim,
│   │                               # products, enumeration, client
│   ├── finding/                   # Finding struct + severity
│   ├── scoring/                   # Risk score calculation + finding chaining
│   ├── nis2/                      # NIS2 Art. 21 article mapping
│   ├── i18n/                      # en/de report strings + module docs
│   └── report/                    # JSON, HTML, text, and PDF output
└── pkg/httpclient/                # Shared HTTP client
```

---

## Legal

This tool performs **active, unauthenticated reconnaissance** - it sends probe
requests to the target's exposed endpoints, but makes no authentication
attempts, no payload injection, and no port scanning.

**Always obtain written permission before scanning systems you do not own.**
