package endpoints

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/pkg/httpclient"
)

const moduleName = "endpoints"

// endpointProbe defines an endpoint to check and its risk profile
type endpointProbe struct {
	Path        string
	Title       string
	Description string
	Severity    finding.Severity
	Tags        []string
	Recommend   string
}

// probes defines all admin/sensitive endpoints to check
var probes = []endpointProbe{
	// Admin panels
	{"/admin", "Admin panel exposed", "An admin panel is accessible without authentication.", finding.High, []string{"admin-exposure", "endpoints"}, "Restrict admin endpoints to internal networks or VPN only."},
	{"/admin/", "Admin panel exposed", "An admin panel is accessible without authentication.", finding.High, []string{"admin-exposure", "endpoints"}, "Restrict admin endpoints to internal networks or VPN only."},
	{"/administrator", "Administrator panel exposed", "Administrator interface accessible without authentication.", finding.High, []string{"admin-exposure", "endpoints"}, "Restrict to internal network or VPN."},

	// Identity & Auth admin
	{"/auth/admin", "Auth admin panel exposed", "Authentication admin interface is publicly accessible.", finding.Critical, []string{"admin-exposure", "iam", "endpoints"}, "Immediately restrict this endpoint to trusted IPs only."},
	{"/realms/master/protocol/openid-connect/token", "Keycloak master realm token endpoint exposed", "Keycloak master realm is publicly accessible. This realm controls all other realms.", finding.High, []string{"oidc", "iam", "endpoints"}, "The master realm should only be used for Keycloak administration. Disable public access."},
	{"/.well-known/jwks.json", "JWKS (JSON Web Key Set) exposed", "Public keys for JWT verification are exposed. This is expected but confirms JWT is in use.", finding.Info, []string{"oidc", "iam"}, "Expected behavior. Ensure the key rotation process is documented and tested."},

	// Monitoring & metrics (often left open)
	{"/metrics", "Prometheus metrics endpoint exposed", "Application metrics are publicly accessible. May leak infrastructure details.", finding.Medium, []string{"admin-exposure", "endpoints"}, "Restrict /metrics to monitoring systems only. Use authentication or IP allowlisting."},
	{"/actuator", "Spring Boot Actuator exposed", "Spring Boot actuator endpoints are publicly accessible. May expose env vars, heap dumps, and config.", finding.High, []string{"admin-exposure", "endpoints"}, "Disable or authenticate all actuator endpoints. Never expose /actuator/env or /actuator/heapdump publicly."},
	{"/actuator/health", "Spring Boot health endpoint exposed", "Spring Actuator health check is publicly accessible.", finding.Low, []string{"admin-exposure", "endpoints"}, "Limit health endpoint detail to authenticated users."},
	{"/actuator/env", "Spring Boot environment variables exposed", "Spring Actuator env endpoint exposes environment variables including secrets.", finding.Critical, []string{"admin-exposure", "endpoints"}, "Immediately restrict or disable /actuator/env."},
	{"/_health", "Health endpoint exposed", "Application health endpoint is publicly accessible.", finding.Info, []string{"endpoints"}, "Verify no sensitive information is disclosed in the health response."},
	{"/health", "Health endpoint exposed", "Application health endpoint is publicly accessible.", finding.Info, []string{"endpoints"}, "Verify no sensitive information is disclosed in the health response."},

	// Debug / development leftovers
	{"/debug", "Debug endpoint exposed", "A debug endpoint is publicly accessible.", finding.High, []string{"admin-exposure", "endpoints"}, "Remove all debug endpoints from production deployments."},
	{"/debug/vars", "Go expvar debug endpoint exposed", "Go expvar debug endpoint exposes runtime variables and statistics.", finding.Medium, []string{"admin-exposure", "endpoints"}, "Disable or restrict expvar in production."},
	{"/api/debug", "API debug endpoint exposed", "An API debug endpoint is publicly accessible.", finding.High, []string{"admin-exposure", "endpoints"}, "Remove debug endpoints from production."},

	// GraphQL introspection
	{"/graphql", "GraphQL endpoint accessible", "A GraphQL endpoint is publicly accessible. Check if introspection is enabled.", finding.Info, []string{"endpoints", "iam"}, "Disable GraphQL introspection in production to prevent schema enumeration."},

	// Config / secrets
	{"/.env", ".env File Exposed", ".env file is publicly accessible. May contain secrets, API keys, and database credentials.", finding.Critical, []string{"admin-exposure", "endpoints"}, "Immediately remove .env files from web root and rotate any exposed secrets."},
	{"/config.json", "Config file exposed", "Application configuration file is publicly accessible.", finding.High, []string{"admin-exposure", "endpoints"}, "Remove configuration files from web root."},
	{"/api/v1/users", "User list API endpoint exposed", "User enumeration may be possible via public API.", finding.Medium, []string{"iam", "endpoints"}, "Require authentication for all user management endpoints."},
}

// endpointDocIDs maps probe titles to their stable documentation IDs.
var endpointDocIDs = map[string]string{
	"Admin panel exposed":                       "endpoints-admin",
	"Administrator panel exposed":               "endpoints-admin",
	"Auth admin panel exposed":                  "endpoints-admin",
	"Spring Boot environment variables exposed": "endpoints-actuator-env",
	".env File Exposed":                         "endpoints-dotenv",
	"Debug endpoint exposed":                    "endpoints-debug",
	"API debug endpoint exposed":                "endpoints-debug",
	"GraphQL endpoint accessible":               "endpoints-graphql-introspection",
}

// Scanner implements the exposed endpoints detection module
type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding

	realm := target.RealmOrDefault()
	for _, probe := range probes {
		endpointURL := target.BaseURL() + strings.ReplaceAll(probe.Path, "/realms/master/", "/realms/"+realm+"/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		finalURL := httpclient.EffectiveFinalURL(resp, responseBody)
		ct := resp.Header.Get("Content-Type")

		// Ignore redirects that land on a clearly safe login/auth page.
		if httpclient.RedirectLooksSafe(req.URL, finalURL, ct, responseBody) {
			continue
		}

		redirected := httpclient.Redirected(req.URL, finalURL)

		sev := probe.Severity
		confidence := "HIGH"
		evidence := []string{fmt.Sprintf("HTTP %d at %s", resp.StatusCode, endpointURL)}

		if redirected {
			evidence = append(evidence, fmt.Sprintf("redirected to %s", finalURL.String()))
			if sev != finding.Critical {
				sev = finding.Info
				confidence = "LOW"
			}
		}

		f := finding.NewFinding(moduleName, target.Host,
			probe.Title,
			probe.Description,
			sev,
		)
		if docID, ok := endpointDocIDs[probe.Title]; ok {
			f.ID = docID
		}
		f.Evidence = evidence
		f.Confidence = confidence
		f.Recommendation = probe.Recommend
		f.Tags = probe.Tags
		findings = append(findings, f)
	}

	return findings, nil
}
