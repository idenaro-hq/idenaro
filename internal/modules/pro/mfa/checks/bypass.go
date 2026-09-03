package checks

import (
	"fmt"

	"idenaro/internal/finding"
)

// MFABypassPaths are the paths probed for MFA bypass endpoints.
var MFABypassPaths = []string{
	"/api/auth/mfa/bypass", "/auth/skip-mfa", "/auth/mfa/disable",
	"/login?skip_mfa=true", "/login?mfa=false",
}

// BypassFound returns a finding for a potential MFA bypass endpoint that
// responded with HTTP 200.
func BypassFound(host, pageURL string) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		"Potential MFA bypass endpoint accessible",
		fmt.Sprintf("A potential MFA bypass endpoint returned HTTP 200 at %s. "+
			"Manual investigation is required.", pageURL),
		finding.High,
	)
	f.ID = "mfa-bypass-endpoint"
	f.Evidence = []string{fmt.Sprintf("HTTP 200 at: %s", pageURL)}
	f.Confidence = "LOW"
	f.Recommendation = "Investigate this endpoint immediately. MFA must not be bypassable via URL parameters."
	f.Tags = []string{"mfa", "iam"}
	return f
}
