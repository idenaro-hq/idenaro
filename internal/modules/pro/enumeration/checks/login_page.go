package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// LoginPageEnum checks the login page body for phrases that distinguish between
// wrong passwords and non-existent accounts.
func LoginPageEnum(host, loginURL, bodyStr string) []finding.Finding {
	var findings []finding.Finding
	lower := strings.ToLower(bodyStr)
	for _, ind := range enumIndicators {
		if strings.Contains(lower, ind.phrase) {
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("User enumeration indicator on login page: %q", ind.phrase),
				fmt.Sprintf("The login page contains %q which %s. "+
					"This allows attackers to distinguish between invalid usernames and wrong passwords.",
					ind.phrase, ind.meaning),
				ind.severity,
			)
			f.ID = "enum-login-wording"
			f.Evidence = []string{
				fmt.Sprintf("Page contains: %q", ind.phrase),
				fmt.Sprintf("URL: %s", loginURL),
			}
			f.Confidence = "LOW"
			f.Recommendation = "Return generic authentication failure messages. " +
				"Never distinguish between 'user not found' and 'wrong password'."
			f.Tags = []string{"enumeration", "iam"}
			findings = append(findings, f)
		}
	}
	return findings
}
