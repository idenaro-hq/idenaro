package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// ResponseModes checks response_modes_supported for the insecure fragment mode.
func ResponseModes(host string, supported []string) []finding.Finding {
	var findings []finding.Finding
	fragmentFound := false
	for _, rm := range supported {
		if rm == "fragment" {
			fragmentFound = true
			f := finding.NewFinding(moduleName, host,
				"Fragment response_mode supported",
				"The fragment response mode delivers tokens/codes in URL hash fragments. "+
					"These are accessible to JavaScript and logged in browser history, "+
					"making them vulnerable to exfiltration via XSS or referrer leakage.",
				finding.Low,
			)
			f.ID = "oidc-fragment-mode"
			f.Evidence = []string{`response_modes_supported includes: "fragment"`}
			f.Confidence = "HIGH"
			f.Recommendation = "Prefer form_post response mode for all authorization responses."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}
	}

	if len(supported) > 0 && !fragmentFound {
		f := finding.NewFinding(moduleName, host,
			"Fragment response mode not advertised",
			"The fragment response mode is not listed in response_modes_supported. "+
				"Tokens and codes will not be delivered via URL hash fragments, eliminating browser history and referrer leakage risk from this vector.",
			finding.Info,
		)
		f.ID = "oidc-fragment-mode-ok"
		f.Evidence = []string{fmt.Sprintf("response_modes_supported: %s", strings.Join(supported, ", "))}
		f.Confidence = "HIGH"
		f.Recommendation = "No action required."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	return findings
}
