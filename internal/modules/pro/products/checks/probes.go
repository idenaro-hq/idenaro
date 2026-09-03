package checks

import (
	"strings"

	"idenaro/internal/finding"
)

// Probe defines a vendor-specific endpoint to check.
type Probe struct {
	Path        string
	Vendor      string
	Title       string
	Description string
	Severity    finding.Severity
	Recommend   string
	Tags        []string
	DocID       string
	// DetectFn optionally validates response content for higher-confidence detection.
	DetectFn func(statusCode int, body, contentType string) bool
}

// Probes is the ordered list of vendor-specific endpoints to probe.
var Probes = []Probe{
	// ── Keycloak ──────────────────────────────────────────────────────────────
	{
		Path:   "/auth/admin/master/console/",
		Vendor: "Keycloak",
		Title:  "Keycloak admin console accessible (legacy path)",
		DocID:  "vendor-keycloak-admin",
		Description: "The Keycloak admin console is accessible at the legacy /auth/admin path. " +
			"This interface controls all realms, clients, users, and identity providers.",
		Severity:  finding.High,
		Recommend: "Restrict admin console to internal networks. Use --hostname-admin to separate admin from public traffic.",
		Tags:      []string{"admin-exposure", "iam", "endpoints"},
		DetectFn:  func(s int, b, ct string) bool { return s == 200 },
	},
	{
		Path:   "/realms/master/protocol/openid-connect/token",
		Vendor: "Keycloak",
		Title:  "Keycloak master realm token endpoint exposed",
		Description: "The Keycloak master realm token endpoint is publicly reachable. " +
			"The master realm is the super-admin realm that controls all other realms. " +
			"Brute-force against this endpoint grants full Keycloak administration access.",
		Severity:  finding.High,
		Recommend: "The master realm should only be used for Keycloak admin operations. Block public access.",
		Tags:      []string{"oidc", "iam", "endpoints"},
		DetectFn:  func(s int, b, ct string) bool { return s != 404 },
	},
	{
		Path:   "/realms/master/clients-registrations/openid-connect",
		Vendor: "Keycloak",
		Title:  "Keycloak dynamic client registration endpoint exposed",
		DocID:  "vendor-keycloak-client-reg",
		Description: "The dynamic client registration endpoint is publicly accessible. " +
			"If not protected by an initial access token, anyone can register OAuth clients in this realm, " +
			"potentially obtaining redirect URIs for token theft.",
		Severity:  finding.High,
		Recommend: "Require an initial access token for client registration. Disable open registration.",
		Tags:      []string{"oidc", "iam", "endpoints"},
		DetectFn:  func(s int, b, ct string) bool { return s == 200 || s == 201 },
	},
	{
		Path:   "/realms/master",
		Vendor: "Keycloak",
		Title:  "Keycloak realm info endpoint exposed",
		DocID:  "vendor-keycloak-realm-list",
		Description: "The Keycloak realm information endpoint exposes realm configuration including " +
			"password policy, supported identity providers, and enabled features.",
		Severity:  finding.Info,
		Recommend: "Expected for Keycloak. Verify the disclosed password policy is sufficiently strict.",
		Tags:      []string{"iam", "endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && strings.Contains(b, `"realm"`)
		},
	},
	{
		Path:   "/auth",
		Vendor: "Keycloak",
		Title:  "Keycloak legacy /auth prefix accessible",
		Description: "The legacy /auth prefix is accessible. Keycloak 17+ removed this prefix by default. " +
			"Old deployment still using it may be running an outdated version.",
		Severity:  finding.Low,
		Recommend: "Migrate to Keycloak 17+ without the /auth prefix. Update all client configurations.",
		Tags:      []string{"iam", "endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && (strings.Contains(b, "Keycloak") || strings.Contains(b, "keycloak"))
		},
	},

	// ── Authentik ─────────────────────────────────────────────────────────────
	{
		Path:   "/api/v3/core/users/",
		Vendor: "Authentik",
		Title:  "Authentik users API accessible",
		DocID:  "vendor-authentik-user-api",
		Description: "The Authentik users API endpoint is accessible. If unauthenticated access is permitted, " +
			"this enables full user enumeration and potentially account manipulation.",
		Severity:  finding.High,
		Recommend: "Authentik API requires a valid session or API token. Verify no anonymous access is permitted.",
		Tags:      []string{"admin-exposure", "iam", "endpoints"},
		DetectFn:  func(s int, b, ct string) bool { return s == 200 },
	},
	{
		Path:   "/api/v3/",
		Vendor: "Authentik",
		Title:  "Authentik API root accessible",
		Description: "The Authentik API root is accessible, confirming Authentik is deployed here. " +
			"Verify API authentication is enforced on all endpoints.",
		Severity:  finding.Info,
		Recommend: "Expected for Authentik. Ensure API tokens are rotated and access is logged.",
		Tags:      []string{"iam", "endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && strings.Contains(b, "authentik")
		},
	},
	{
		Path:        "/-/health/live/",
		Vendor:      "Authentik",
		Title:       "Authentik liveness probe exposed",
		Description: "Authentik's liveness health endpoint is publicly accessible. While not a direct security issue, it confirms the product in use.",
		Severity:    finding.Info,
		Recommend:   "Restrict health endpoints to internal networks or monitoring systems.",
		Tags:        []string{"endpoints"},
		DetectFn:    func(s int, b, ct string) bool { return s == 204 || s == 200 },
	},

	// ── ADFS ──────────────────────────────────────────────────────────────────
	{
		Path:   "/adfs/ls/idpinitiatedsignon.aspx",
		Vendor: "ADFS",
		Title:  "ADFS IdP-initiated sign-on page exposed",
		DocID:  "vendor-adfs-idp-initiated",
		Description: "The ADFS IdP-initiated sign-on page is publicly accessible. " +
			"This endpoint is commonly abused in phishing campaigns and bypasses " +
			"SP-initiated flow controls and Conditional Access policies.",
		Severity:  finding.High,
		Recommend: "Disable IdP-initiated SSO: Set-AdfsProperties -EnableIdPInitiatedSignonPage $false",
		Tags:      []string{"admin-exposure", "iam", "endpoints"},
		DetectFn:  func(s int, b, ct string) bool { return s == 200 },
	},
	{
		Path:   "/adfs/portal/updatepassword/",
		Vendor: "ADFS",
		Title:  "ADFS password update portal exposed",
		Description: "The ADFS password update portal is publicly accessible. " +
			"This endpoint allows users to change their AD password via the web.",
		Severity:  finding.Medium,
		Recommend: "Restrict the ADFS password change portal to internal networks only.",
		Tags:      []string{"iam", "endpoints"},
		DetectFn:  func(s int, b, ct string) bool { return s == 200 },
	},
	{
		Path:   "/adfs/services/trust/13/usernamemixed",
		Vendor: "ADFS",
		Title:  "ADFS WS-Trust username/password endpoint exposed",
		DocID:  "endpoints-adfs-wstrust",
		Description: "The ADFS WS-Trust usernamemixed endpoint is publicly accessible. " +
			"This endpoint accepts plaintext username/password credentials and is the " +
			"primary target for password spray attacks against Microsoft environments. " +
			"It completely bypasses MFA and Conditional Access.",
		Severity: finding.Critical,
		Recommend: "Block this endpoint at the perimeter immediately if not needed for legacy clients. " +
			"Enable Entra ID Smart Lockout and sign-in risk policies.",
		Tags:     []string{"admin-exposure", "iam", "endpoints"},
		DetectFn: func(s int, b, ct string) bool { return s != 404 },
	},
	{
		Path:      "/adfs/services/trust/2005/usernamemixed",
		Vendor:    "ADFS",
		Title:     "ADFS WS-Trust 2005 legacy endpoint exposed",
		DocID:     "endpoints-adfs-wstrust",
		Description: "The older WS-Trust 2005 usernamemixed endpoint is publicly accessible. " +
			"Functionally identical risk to the 2013 variant - often missed during hardening.",
		Severity:  finding.Critical,
		Recommend: "Disable alongside the 2013 variant. Both must be blocked.",
		Tags:      []string{"admin-exposure", "iam", "endpoints"},
		DetectFn:  func(s int, b, ct string) bool { return s != 404 },
	},

	// ── Zitadel ───────────────────────────────────────────────────────────────
	{
		Path:   "/management/v1/orgs",
		Vendor: "Zitadel",
		Title:  "Zitadel organization management API exposed",
		Description: "The Zitadel organization management API is accessible. " +
			"Verify authentication is enforced - this API controls organization-level identity settings.",
		Severity:  finding.High,
		Recommend: "Zitadel APIs require service account tokens. Verify no unauthenticated access is permitted.",
		Tags:      []string{"admin-exposure", "iam", "endpoints"},
		DetectFn:  func(s int, b, ct string) bool { return s == 200 },
	},
	{
		Path:        "/debug",
		Vendor:      "Zitadel",
		Title:       "Zitadel debug endpoint exposed",
		Description: "Zitadel's debug endpoint is publicly accessible, exposing internal diagnostics.",
		Severity:    finding.Medium,
		Recommend:   "Disable the Zitadel debug endpoint in production: ExtraOrigins or reverse proxy restriction.",
		Tags:        []string{"admin-exposure", "endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && strings.Contains(b, "zitadel")
		},
	},

	// ── PingFederate ──────────────────────────────────────────────────────────
	{
		Path:   "/pingfederate/app",
		Vendor: "PingFederate",
		Title:  "PingFederate admin console accessible",
		DocID:  "vendor-pingfederate-admin",
		Description: "The PingFederate administrative console is publicly accessible. " +
			"This interface controls all federation configurations, partner connections, and OAuth clients.",
		Severity:  finding.Critical,
		Recommend: "PingFederate admin console must be restricted to internal management networks only.",
		Tags:      []string{"admin-exposure", "iam", "endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && (strings.Contains(b, "PingFederate") || strings.Contains(b, "pingfederate"))
		},
	},
	{
		Path:        "/pf/heartbeat.ping",
		Vendor:      "PingFederate",
		Title:       "PingFederate heartbeat endpoint exposed",
		Description: "PingFederate's heartbeat monitoring endpoint is publicly accessible, confirming PingFederate is deployed.",
		Severity:    finding.Info,
		Recommend:   "Restrict monitoring endpoints to internal networks.",
		Tags:        []string{"endpoints"},
		DetectFn:    func(s int, b, ct string) bool { return s == 200 },
	},

	// ── ForgeRock / OpenAM ────────────────────────────────────────────────────
	{
		Path:   "/openam/json/serverinfo/*",
		Vendor: "ForgeRock",
		Title:  "ForgeRock/OpenAM server info exposed",
		Description: "The ForgeRock/OpenAM server information endpoint is accessible, " +
			"exposing deployment configuration and version information.",
		Severity:  finding.Medium,
		Recommend: "Restrict the serverinfo endpoint or disable version disclosure.",
		Tags:      []string{"iam", "endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && strings.Contains(b, "openam")
		},
	},
	{
		Path:        "/openam/console",
		Vendor:      "ForgeRock",
		Title:       "ForgeRock/OpenAM admin console exposed",
		Description: "The ForgeRock/OpenAM administrative console is publicly accessible.",
		Severity:    finding.Critical,
		Recommend:   "Restrict the OpenAM console to internal administration networks.",
		Tags:        []string{"admin-exposure", "iam", "endpoints"},
		DetectFn:    func(s int, b, ct string) bool { return s == 200 },
	},

	// ── Okta custom-hosted artifacts ──────────────────────────────────────────
	{
		Path:   "/.well-known/okta-organization",
		Vendor: "Okta",
		Title:  "Okta organization metadata exposed",
		Description: "Okta organization metadata is exposed, revealing the Okta tenant ID, " +
			"organization name, and other configuration details.",
		Severity:  finding.Info,
		Recommend: "Expected for Okta-hosted portals. Verify no sensitive tenant data is disclosed.",
		Tags:      []string{"iam", "endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && strings.Contains(b, "okta")
		},
	},

	// ── Dex ───────────────────────────────────────────────────────────────────
	{
		Path:   "/dex/.well-known/openid-configuration",
		Vendor: "Dex",
		Title:  "Dex OIDC discovery endpoint exposed",
		Description: "A Dex identity provider OIDC discovery endpoint is accessible at /dex/. " +
			"Dex is commonly deployed as an internal OIDC provider for Kubernetes environments.",
		Severity:  finding.Info,
		Recommend: "Verify Dex is not publicly accessible if deployed for internal Kubernetes auth.",
		Tags:      []string{"oidc", "iam", "endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && strings.Contains(b, "dex")
		},
	},

	// ── Authelia ──────────────────────────────────────────────────────────────
	{
		Path:        "/api/health",
		Vendor:      "Authelia",
		Title:       "Authelia health endpoint accessible",
		Description: "Authelia's health endpoint is publicly accessible, confirming Authelia is deployed as the auth proxy.",
		Severity:    finding.Info,
		Recommend:   "Restrict health endpoints to internal monitoring systems.",
		Tags:        []string{"endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && strings.Contains(b, "authelia")
		},
	},

	// ── Generic API docs (cross-vendor) ───────────────────────────────────────
	{
		Path:   "/swagger-ui.html",
		Vendor: "Generic",
		Title:  "Swagger UI exposed on identity endpoint",
		Description: "A Swagger UI is accessible, exposing the full API specification. " +
			"On identity systems, this reveals all admin, user management, and auth API routes.",
		Severity:  finding.Medium,
		Recommend: "Disable Swagger UI in production or restrict to internal networks.",
		Tags:      []string{"admin-exposure", "endpoints"},
		DetectFn:  func(s int, b, ct string) bool { return s == 200 },
	},
	{
		Path:        "/swagger-ui/index.html",
		Vendor:      "Generic",
		Title:       "Swagger UI exposed on identity endpoint",
		Description: "Swagger UI is accessible, exposing the full API specification including auth and admin routes.",
		Severity:    finding.Medium,
		Recommend:   "Disable Swagger UI in production or restrict to internal networks.",
		Tags:        []string{"admin-exposure", "endpoints"},
		DetectFn:    func(s int, b, ct string) bool { return s == 200 },
	},
	{
		Path:   "/v3/api-docs",
		Vendor: "Generic",
		Title:  "OpenAPI spec (v3) exposed",
		Description: "The OpenAPI v3 specification is publicly accessible. " +
			"On identity systems, this exposes all available API routes, request formats, and auth schemes.",
		Severity:  finding.Medium,
		Recommend: "Restrict API documentation to authenticated users or internal networks.",
		Tags:      []string{"admin-exposure", "endpoints"},
		DetectFn: func(s int, b, ct string) bool {
			return s == 200 && strings.Contains(b, "openapi")
		},
	},
}
