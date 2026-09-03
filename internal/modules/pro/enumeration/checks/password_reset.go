package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// PasswordResetAccessible returns an informational finding for a reachable
// password reset page.
func PasswordResetAccessible(host, endpointURL, resetName string, statusCode int) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("Password reset page accessible: %s", resetName),
		fmt.Sprintf("A password reset page is accessible at %s. "+
			"Verify that the reset flow does not disclose whether an email or username exists.", endpointURL),
		finding.Info,
	)
	f.Evidence = []string{fmt.Sprintf("HTTP %d at %s", statusCode, endpointURL)}
	f.Confidence = "HIGH"
	f.Recommendation = "Password reset responses should be identical whether the account exists or not. " +
		"Use a message like 'If an account exists, you will receive an email'."
	f.Tags = []string{"enumeration", "iam"}
	return f
}

// PasswordResetEnum checks the password reset page body for phrases that reveal
// whether an account exists.
func PasswordResetEnum(host, endpointURL, bodyStr string) []finding.Finding {
	var findings []finding.Finding
	lower := strings.ToLower(bodyStr)
	for _, ind := range enumIndicators {
		if strings.Contains(lower, ind.phrase) {
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("User enumeration possible via password reset - %s", ind.meaning),
				fmt.Sprintf("The password reset page at %s contains the phrase %q which %s. "+
					"Attackers can use this to build a list of valid accounts for targeted credential attacks.",
					endpointURL, ind.phrase, ind.meaning),
				ind.severity,
			)
			f.ID = "enum-reset-wording"
			f.Evidence = []string{
				fmt.Sprintf("Page contains: %q", ind.phrase),
				fmt.Sprintf("URL: %s", endpointURL),
			}
			f.Confidence = "MEDIUM"
			f.Recommendation = "Return identical responses for existing and non-existing accounts during password reset. " +
				"Implement rate limiting on the reset endpoint."
			f.Tags = []string{"enumeration", "iam"}
			findings = append(findings, f)
		}
	}
	return findings
}
