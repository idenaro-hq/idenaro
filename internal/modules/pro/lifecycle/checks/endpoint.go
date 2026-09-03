package checks

import (
	"fmt"
	"net/url"
	"strings"

	"idenaro/internal/finding"
)

var lifecycleDocIDs = map[string]string{
	"self-service registration":       "lifecycle-register-open",
	"self-service signup":             "lifecycle-register-open",
	"auth register endpoint":          "lifecycle-register-open",
	"API registration endpoint":       "lifecycle-register-open",
	"invitation endpoint":             "lifecycle-invite",
	"invitations API":                 "lifecycle-invite",
	"admin invitation endpoint":       "lifecycle-invite",
	"account unlock endpoint":         "lifecycle-unlock",
	"account unblock endpoint":        "lifecycle-unlock",
	"admin impersonation endpoint":    "lifecycle-impersonate",
	"API impersonation endpoint":      "lifecycle-impersonate",
	"auth impersonation endpoint":     "lifecycle-impersonate",
	"Keycloak user management (master realm)": "lifecycle-impersonate",
	"password change endpoint":        "lifecycle-password-change",
	"API password change endpoint":    "lifecycle-password-change",
}

func EndpointFound(host string, p Probe, statusCode int, redirected bool, finalURL *url.URL, ct, bodyStr string) finding.Finding {
	sev := p.Severity
	confidence := "HIGH"
	extraDesc := ""

	if redirected && sev != finding.Critical {
		sev = finding.Info
		confidence = "LOW"
		extraDesc = fmt.Sprintf(" Request was redirected to %s.", finalURL.String())
	} else if statusCode == 200 {
		bodyLower := strings.ToLower(bodyStr)
		isRealContent := strings.Contains(ct, "html") || strings.Contains(ct, "json")
		hasForm := strings.Contains(bodyLower, "<form") || strings.Contains(bodyLower, "form")
		if isRealContent && (hasForm || strings.Contains(ct, "json")) {
			extraDesc = fmt.Sprintf(" The endpoint returned HTTP 200 with %s content.", ct)
		}
	} else {
		sev = finding.Info
		confidence = "LOW"
		extraDesc = fmt.Sprintf(" The endpoint responded with HTTP %d (access is restricted).", statusCode)
	}

	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("Account lifecycle endpoint accessible: %s", p.Name),
		p.Description+extraDesc,
		sev,
	)
	if docID, ok := lifecycleDocIDs[p.Name]; ok {
		f.ID = docID
	}
	f.Confidence = confidence
	f.Recommendation = p.Recommend
	f.Tags = p.Tags
	return f
}
