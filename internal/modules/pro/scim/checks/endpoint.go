package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// Unauthenticated builds findings when a SCIM endpoint responds with HTTP 200.
func Unauthenticated(host, endpointURL, description, bodyStr, ct string, statusCode int, redirected bool) []finding.Finding {
	isScimResponse := strings.Contains(ct, "scim") ||
		strings.Contains(bodyStr, `"schemas"`) ||
		strings.Contains(bodyStr, "urn:ietf:params:scim")

	hasUserData := strings.Contains(bodyStr, `"userName"`) ||
		strings.Contains(bodyStr, `"emails"`) ||
		strings.Contains(bodyStr, `"displayName"`) ||
		strings.Contains(bodyStr, `"totalResults"`)

	sev := finding.High
	detail := ""
	confidence := "HIGH"

	switch {
	case hasUserData:
		sev = finding.Critical
		detail = " The response contains user identity records (userName, email, displayName) without authentication."
	case isScimResponse:
		sev = finding.Critical
		detail = " The response contains SCIM-formatted data, confirming unauthenticated access to identity data."
	case redirected:
		sev = finding.Info
		confidence = "LOW"
		detail = fmt.Sprintf(" Request was redirected to %s - endpoint may not be directly accessible.", endpointURL)
	}

	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("%s accessible without authentication", description),
		fmt.Sprintf("The %s at %s is accessible without authentication (HTTP %d).%s "+
			"SCIM endpoints provide full CRUD access to user and group identities. "+
			"Unauthenticated access enables mass user enumeration, account manipulation, "+
			"and privilege escalation.", description, endpointURL, statusCode, detail),
		sev,
	)
	f.ID = "scim-exposed"
	f.Evidence = []string{
		fmt.Sprintf("HTTP %d at %s", statusCode, endpointURL),
		fmt.Sprintf("Content-Type: %s", ct),
	}
	if hasUserData {
		f.Evidence = append(f.Evidence, fmt.Sprintf("Response preview: %s", truncate(bodyStr, 300)))
	}
	f.Confidence = confidence
	f.Recommendation = "SCIM endpoints must require authentication (Bearer token or mutual TLS). " +
		"Restrict SCIM access to provisioning systems only. " +
		"Never expose SCIM endpoints publicly without authentication. " +
		"NIS2 Art. 21 (2)(i) requires access control for identity management systems."
	f.Tags = []string{"scim", "iam", "admin-exposure"}
	return []finding.Finding{f}
}

// RequiresAuth builds an informational finding when a SCIM endpoint exists but correctly requires auth.
func RequiresAuth(host, endpointURL, description string, statusCode int) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("%s exists (requires authentication)", description),
		fmt.Sprintf("A SCIM endpoint is present at %s and correctly requires authentication (HTTP %d). "+
			"SCIM is in use for identity provisioning. Ensure only authorized provisioning systems have access.", endpointURL, statusCode),
		finding.Info,
	)
	f.Evidence = []string{fmt.Sprintf("HTTP %d at %s", statusCode, endpointURL)}
	f.Confidence = "HIGH"
	f.Recommendation = "Verify SCIM access is restricted to your provisioning systems (e.g., Azure AD, Okta, Workday). " +
		"Rotate SCIM bearer tokens regularly. Monitor SCIM activity logs."
	f.Tags = []string{"scim", "iam"}
	return f
}
