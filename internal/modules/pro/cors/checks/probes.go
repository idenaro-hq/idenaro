package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// Wildcard returns a finding for an Access-Control-Allow-Origin: * response.
func Wildcard(hostName, endpointURL, endpointDescription string) finding.Finding {
	f := finding.NewFinding(moduleName, hostName,
		fmt.Sprintf("Wildcard CORS on %s", endpointDescription),
		fmt.Sprintf("The %s at %s returns Access-Control-Allow-Origin: * allowing any origin to "+
			"make cross-site requests. On auth endpoints this enables token and credential theft "+
			"from any malicious website.", endpointDescription, endpointURL),
		finding.High,
	)
	f.ID = "cors-wildcard"
	f.Evidence = []string{
		"Access-Control-Allow-Origin: *",
		fmt.Sprintf("Endpoint: %s", endpointURL),
	}
	f.Confidence = "HIGH"
	f.Recommendation = "Never use wildcard CORS on auth endpoints. Maintain an explicit allowlist of trusted origins."
	f.Tags = []string{"cors", "iam"}
	return f
}

// ReflectedOrigin returns a finding for an origin reflection, escalating to
// Critical when Access-Control-Allow-Credentials is also true.
func ReflectedOrigin(
	hostName, endpointURL, endpointDescription,
	injectedOrigin, reflectedOrigin, allowCredentials string,
) finding.Finding {
	severity := finding.High
	description := fmt.Sprintf("The %s at %s reflects the request Origin header back in "+
		"Access-Control-Allow-Origin, allowing any origin to make cross-site requests.", endpointDescription, endpointURL)

	if strings.EqualFold(allowCredentials, "true") {
		severity = finding.Critical
		description += " Access-Control-Allow-Credentials: true is also set, meaning cookies and " +
			"Authorization headers are included - this is directly exploitable for account takeover " +
			"from any malicious website."
	}

	f := finding.NewFinding(moduleName, hostName,
		fmt.Sprintf("Reflected CORS origin on %s", endpointDescription),
		description,
		severity,
	)
	f.ID = "cors-reflected"
	f.Evidence = []string{
		fmt.Sprintf("Request Origin: %s", injectedOrigin),
		fmt.Sprintf("Access-Control-Allow-Origin: %s", reflectedOrigin),
		fmt.Sprintf("Access-Control-Allow-Credentials: %s", allowCredentials),
		fmt.Sprintf("Endpoint: %s", endpointURL),
	}
	f.Confidence = "HIGH"
	f.Recommendation = "Validate Origin against a strict allowlist. Never reflect arbitrary origins. " +
		"Never combine a dynamic ACAO value with ACAC: true."
	f.Tags = []string{"cors", "iam"}
	return f
}

// NullOrigin returns a finding for null-origin + credentials acceptance.
func NullOrigin(hostName, endpointURL, endpointDescription string) finding.Finding {
	f := finding.NewFinding(moduleName, hostName,
		fmt.Sprintf("Null origin accepted with credentials on %s", endpointDescription),
		fmt.Sprintf("The %s accepts the null origin with Access-Control-Allow-Credentials: true. "+
			"The null origin is triggered from sandboxed iframes, file:// pages, and redirected "+
			"cross-origin requests - enabling credential theft from attacker-crafted local HTML files.", endpointDescription),
		finding.High,
	)
	f.ID = "cors-null-origin"
	f.Evidence = []string{
		"Access-Control-Allow-Origin: null",
		"Access-Control-Allow-Credentials: true",
		fmt.Sprintf("Endpoint: %s", endpointURL),
	}
	f.Confidence = "HIGH"
	f.Recommendation = "Never allow the null origin. Reject it explicitly in your CORS policy."
	f.Tags = []string{"cors", "iam"}
	return f
}
