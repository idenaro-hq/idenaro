package checks

import "idenaro/internal/finding"

const moduleName = "enumeration"

type enumIndicator struct {
	phrase   string
	severity finding.Severity
	meaning  string
}

var enumIndicators = []enumIndicator{
	{"user not found", finding.Medium, "reveals non-existent usernames"},
	{"no account found", finding.Medium, "reveals non-existent usernames"},
	{"email not found", finding.Medium, "reveals non-existent email addresses"},
	{"account not found", finding.Medium, "reveals non-existent accounts"},
	{"unknown email", finding.Medium, "reveals non-existent email addresses"},
	{"that email doesn't exist", finding.Medium, "reveals non-existent email addresses"},
	{"we don't recognize that email", finding.Medium, "reveals non-existent email addresses"},
	{"no user with that", finding.Medium, "reveals non-existent usernames"},
	{"invalid username", finding.Low, "may reveal non-existent usernames"},
	{"account is locked", finding.Medium, "confirms account existence and locked state"},
	{"account has been disabled", finding.Medium, "confirms account existence and disabled state"},
	{"account is suspended", finding.Medium, "confirms account existence and suspended state"},
	{"too many attempts", finding.Low, "confirms account existence via lockout messaging"},
	{"mfa required", finding.Low, "confirms account existence and MFA configuration"},
	{"verify your identity", finding.Info, "confirms account existence"},
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
