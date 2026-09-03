package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// LogoutOpenRedirect returns a finding when a logout endpoint follows the
// attacker-controlled redirect URI injected in the probe.
func LogoutOpenRedirect(host, endpointURL, logoutName, testURL string, statusCode int, location string) []finding.Finding {
	if statusCode < 300 || statusCode >= 400 {
		return nil
	}
	if location == "" {
		return nil
	}
	if !strings.Contains(location, "evil.com") && !strings.Contains(strings.ToLower(location), "evil") {
		return nil
	}
	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("Open redirect on %s endpoint", logoutName),
		fmt.Sprintf("The %s endpoint at %s redirected to the attacker-controlled URL injected in "+
			"post_logout_redirect_uri. This enables phishing: after legitimate logout, users are "+
			"redirected to a convincing fake login page.", logoutName, endpointURL),
		finding.High,
	)
	f.ID = "redirects-open"
	f.Evidence = []string{
		fmt.Sprintf("HTTP %d redirect to: %s", statusCode, location),
		fmt.Sprintf("Triggered by: %s", testURL),
	}
	f.Confidence = "HIGH"
	f.Recommendation = "Validate post_logout_redirect_uri against a registered allowlist. " +
		"Reject any URI not pre-registered for the client."
	f.Tags = []string{"redirects", "iam"}
	return []finding.Finding{f}
}

// LogoutAccessible returns an informational finding when a logout endpoint responds
// (i.e. is not 404).
func LogoutAccessible(host, endpointURL, logoutName string, statusCode int) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("Logout endpoint accessible: %s", logoutName),
		fmt.Sprintf("A logout endpoint is accessible at %s. Verify it properly invalidates "+
			"server-side sessions and restricts post-logout redirect destinations.", endpointURL),
		finding.Info,
	)
	f.Evidence = []string{fmt.Sprintf("HTTP %d at %s", statusCode, endpointURL)}
	f.Confidence = "HIGH"
	f.Recommendation = "Ensure logout invalidates all session state server-side. " +
		"Restrict post_logout_redirect_uri to pre-registered URIs only."
	f.Tags = []string{"redirects", "iam"}
	return f
}
