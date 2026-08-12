package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// ResponseTypes checks response_types_supported for implicit and hybrid flows.
// An extra finding is emitted when two or more insecure types are active simultaneously.
func ResponseTypes(host string, supported []string) []finding.Finding {
	var findings []finding.Finding
	insecureCount := 0
	var insecureNames []string

	for _, rt := range supported {
		parts := strings.Fields(rt)
		hasToken := containsStr(parts, "token")
		hasCode := containsStr(parts, "code")
		hasIDToken := containsStr(parts, "id_token")

		if (hasToken || hasIDToken) && !hasCode {
			insecureCount++
			insecureNames = append(insecureNames, "implicit (response_type="+rt+")")
			f := finding.NewFinding(moduleName, host,
				"Implicit Flow enabled (response_type="+rt+")",
				"The implicit OAuth2 flow transmits tokens in URL fragments, exposing them to "+
					"browser history, referrer headers, and server logs. Deprecated in OAuth 2.1.",
				finding.Medium,
			)
			f.ID = "oidc-implicit"
			f.Evidence = []string{fmt.Sprintf("response_types_supported includes: %q", rt)}
			f.Confidence = "HIGH"
			f.Recommendation = "Disable implicit flow. Use authorization_code with PKCE instead."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}

		if hasCode && (hasToken || hasIDToken) {
			insecureCount++
			insecureNames = append(insecureNames, "hybrid (response_type="+rt+")")
			f := finding.NewFinding(moduleName, host,
				"Hybrid Flow enabled (response_type="+rt+")",
				"The hybrid flow mixes code and token responses. Tokens returned in the front channel "+
					"(URL fragment) before the code exchange bypass PKCE protections.",
				finding.Medium,
			)
			f.ID = "oidc-hybrid"
			f.Evidence = []string{fmt.Sprintf("response_types_supported includes: %q", rt)}
			f.Confidence = "HIGH"
			f.Recommendation = "Prefer pure authorization_code flow with PKCE. Avoid hybrid flows."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}
	}

	if insecureCount >= 2 {
		f := finding.NewFinding(moduleName, host,
			"Multiple insecure OAuth2 flows enabled simultaneously",
			fmt.Sprintf("%d insecure response types are simultaneously active: %s. "+
				"Each adds attack surface; together they significantly weaken the token security posture.",
				insecureCount, strings.Join(insecureNames, "; ")),
			finding.High,
		)
		f.ID = "oidc-multi-insecure"
		f.Evidence = []string{
			fmt.Sprintf("Active insecure flows (%d): %s", insecureCount, strings.Join(insecureNames, ", ")),
		}
		f.Confidence = "HIGH"
		f.Recommendation = "Disable all flows except authorization_code. Enable PKCE requirement."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	if insecureCount == 0 && len(supported) > 0 {
		f := finding.NewFinding(moduleName, host,
			"Implicit and hybrid flows not advertised",
			"No implicit or hybrid OAuth2 response types were found in response_types_supported. "+
				"Only authorization_code-based flows are available, which is the secure default.",
			finding.Info,
		)
		f.ID = "oidc-response-types-ok"
		f.Evidence = []string{fmt.Sprintf("response_types_supported: %s", strings.Join(supported, ", "))}
		f.Confidence = "HIGH"
		f.Recommendation = "No action required."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	return findings
}
