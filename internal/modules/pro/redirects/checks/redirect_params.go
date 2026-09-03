package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// RedirectParamDetected returns a finding when a redirect parameter is found in
// a login page's body source. Returns nil if nothing is detected.
func RedirectParamDetected(host, endpointURL, param string) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("Redirect parameter %q detected on login page", param),
		fmt.Sprintf("The login page at %s references the redirect parameter %q. "+
			"If this parameter is not validated against an allowlist, it enables open redirect attacks. "+
			"Combined with OIDC flows, open redirects become token theft vectors.", endpointURL, param),
		finding.Medium,
	)
	f.ID = "redirects-param"
	f.Evidence = []string{
		fmt.Sprintf("Parameter %q found in page source: %s", param, endpointURL),
	}
	f.Confidence = "MEDIUM"
	f.Recommendation = "Validate all redirect parameters against a strict allowlist of trusted URLs. " +
		"Reject or sanitize any value not on the allowlist. Never redirect to arbitrary external URLs."
	f.Tags = []string{"redirects", "iam"}
	return f
}

// ScanRedirectParams checks the body of a login page for known redirect parameters.
// Returns at most one finding per page (first match wins).
func ScanRedirectParams(host, endpointURL, bodyStr string) []finding.Finding {
	lower := strings.ToLower(bodyStr)
	for _, param := range RedirectParams {
		if strings.Contains(lower, param+"=") ||
			strings.Contains(lower, `name="`+param+`"`) ||
			strings.Contains(lower, `name='`+param+`'`) {
			return []finding.Finding{RedirectParamDetected(host, endpointURL, param)}
		}
	}
	return nil
}
