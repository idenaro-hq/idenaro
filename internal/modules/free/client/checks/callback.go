package checks

import (
	"fmt"

	"idenaro/internal/finding"
)

// StateParamMissing builds a finding when an OAuth callback accepts a request without a state parameter.
func StateParamMissing(host, path, endpointURL string, statusCode int) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("OAuth callback %s accepts request without state parameter", path),
		fmt.Sprintf("The callback endpoint at %s returned HTTP %d when called without a state "+
			"parameter. A correct OAuth implementation must validate a cryptographically random "+
			"state value to prevent CSRF-based authorization code injection.", endpointURL, statusCode),
		finding.Medium,
	)
	f.ID = "client-state-missing"
	f.Evidence = []string{
		fmt.Sprintf("Sent: GET %s (no state, no code)", endpointURL),
		fmt.Sprintf("Received: HTTP %d - expected 400 Bad Request", statusCode),
	}
	f.Confidence = "MEDIUM"
	f.Recommendation = "Require and validate a cryptographically random state parameter on every " +
		"OAuth callback request. Return HTTP 400 for any request missing or mismatching the state value."
	f.NIS2Articles = []string{NIS2CSRFVal}
	f.Tags = []string{moduleName, "client-csrf"}
	return f
}

// StateEnforced builds an informational finding confirming state parameter validation is active.
func StateEnforced(host string, enforced []string) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		"OAuth state parameter enforced on callback endpoints",
		"All reachable OAuth callback endpoints rejected requests without a state parameter "+
			"with HTTP 400, confirming CSRF protection is active.",
		finding.Info,
	)
	f.ID = "client-state-enforced"
	f.Evidence = enforced
	f.Confidence = "HIGH"
	f.NIS2Articles = []string{NIS2CSRFVal}
	f.Tags = []string{moduleName, "client-csrf"}
	return f
}

// OpenRedirect builds a finding when a callback endpoint follows a redirect_uri injection.
func OpenRedirect(host, path, probeURL, location string, statusCode int) finding.Finding {
	callbackURL := probeURL // the full probe URL including redirect_uri param
	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("Open redirect on OAuth callback %s", path),
		fmt.Sprintf("The callback endpoint at %s redirected to the attacker-controlled URL "+
			"injected via redirect_uri. An attacker can use this to capture OAuth authorization "+
			"codes or tokens by directing victims through a crafted callback URL.", callbackURL),
		finding.High,
	)
	f.ID = "redirects-open"
	f.Evidence = []string{
		fmt.Sprintf("Sent: GET %s", probeURL),
		fmt.Sprintf("Received: HTTP %d → Location: %s", statusCode, location),
	}
	f.Confidence = "HIGH"
	f.Recommendation = "Validate redirect_uri against the pre-registered URI allowlist for the OAuth client. " +
		"Reject any redirect_uri not explicitly registered; never redirect to arbitrary external URLs."
	f.NIS2Articles = []string{NIS2CSRFVal}
	f.Tags = []string{moduleName, "client-csrf"}
	return f
}
