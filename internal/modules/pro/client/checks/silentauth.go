package checks

import (
	"fmt"
	"net/http"
	"strings"

	"idenaro/internal/finding"
)

// SilentAuth builds findings from a prompt=none probe against an OIDC authorization endpoint.
// statusCode is the HTTP status returned; location is the redirect Location header (if any).
func SilentAuth(host, probeURL string, statusCode int, location string) []finding.Finding {
	lowerLoc := strings.ToLower(location)

	// A proper IdP must redirect back with error=login_required or interaction_required.
	if strings.Contains(lowerLoc, "error=login_required") ||
		strings.Contains(lowerLoc, "error=interaction_required") {
		f := finding.NewFinding(moduleName, host,
			"Silent authentication correctly rejected (prompt=none)",
			fmt.Sprintf("The authorization endpoint at %s returned error=login_required or "+
				"interaction_required for a prompt=none request without an active session, "+
				"indicating correct enforcement of user interaction requirements.", probeURL),
			finding.Info,
		)
		f.Evidence = []string{
			fmt.Sprintf("Probe: GET %s", probeURL),
			fmt.Sprintf("Response: HTTP %d → Location: %s", statusCode, location),
		}
		f.Confidence = "HIGH"
		f.NIS2Articles = []string{NIS2SilentAuth}
		f.Tags = []string{moduleName, "client-silent-auth"}
		return []finding.Finding{f}
	}

	// A redirect that contains code= or token suggests a token was issued without interaction.
	if statusCode >= 300 && statusCode < 400 &&
		(strings.Contains(lowerLoc, "code=") || strings.Contains(lowerLoc, "access_token=")) {
		f := finding.NewFinding(moduleName, host,
			"Silent authentication issued token without active session (prompt=none)",
			fmt.Sprintf("The authorization endpoint at %s issued an authorization code or token "+
				"in response to a prompt=none request without a verifiable active user session. "+
				"This may allow silent token issuance to any client, bypassing user consent.", probeURL),
			finding.High,
		)
		f.Evidence = []string{
			fmt.Sprintf("Probe: GET %s", probeURL),
			fmt.Sprintf("Response: HTTP %d → Location: %s", statusCode, location),
		}
		f.Confidence = "MEDIUM"
		f.Recommendation = "Require an active, verified session before honouring prompt=none. " +
			"Return error=login_required if no session is present."
		f.NIS2Articles = []string{NIS2SilentAuth}
		f.Tags = []string{moduleName, "client-silent-auth"}
		return []finding.Finding{f}
	}

	// Endpoint not reachable, returned error, or no redirect - inconclusive.
	f := finding.NewFinding(moduleName, host,
		"Silent authentication probe inconclusive (prompt=none)",
		fmt.Sprintf("The prompt=none probe to %s returned HTTP %d. No OIDC authorization "+
			"endpoint could be confirmed or the response does not indicate token issuance.", probeURL, statusCode),
		finding.Info,
	)
	f.Evidence = []string{
		fmt.Sprintf("Probe: GET %s", probeURL),
		fmt.Sprintf("Response: HTTP %d", statusCode),
	}
	if location != "" {
		f.Evidence = append(f.Evidence, fmt.Sprintf("Location: %s", location))
	}
	f.Confidence = "LOW"
	f.NIS2Articles = []string{NIS2SilentAuth}
	f.Tags = []string{moduleName, "client-silent-auth"}
	return []finding.Finding{f}
}

// SilentAuthNoEndpoint returns an info finding when no OIDC endpoint could be
// discovered to probe for silent authentication.
func SilentAuthNoEndpoint(host string) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		"Silent authentication probe skipped - no OIDC authorization endpoint found",
		"No /.well-known/openid-configuration or /authorize endpoint was discoverable "+
			"on the relying party. Silent authentication (prompt=none) could not be probed.",
		finding.Info,
	)
	f.Confidence = "LOW"
	f.NIS2Articles = []string{NIS2SilentAuth}
	f.Tags = []string{moduleName, "client-silent-auth"}
	return f
}

// parseLocation extracts the Location header from an HTTP response safely.
func ParseLocation(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	return resp.Header.Get("Location")
}
