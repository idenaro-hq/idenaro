package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// PKCE checks code_challenge_methods_supported for PKCE support.
// Emits an INFO finding when S256 is supported, a LOW finding when only plain is supported.
// When the field is absent from discovery, no finding is emitted as the provider may still
// support PKCE without advertising it.
func PKCE(host string, methods []string) []finding.Finding {
	if len(methods) == 0 {
		return nil
	}

	var findings []finding.Finding
	hasS256 := containsStr(methods, "S256")
	hasPlain := containsStr(methods, "plain")
	methodsStr := strings.Join(methods, ", ")

	if hasS256 {
		f := finding.NewFinding(moduleName, host,
			"PKCE with S256 code challenge method supported",
			"The server advertises S256 as a supported PKCE code challenge method. "+
				"S256 binds the authorization code to a cryptographic hash of the code verifier, "+
				"protecting against authorization code interception attacks.",
			finding.Info,
		)
		f.ID = "oidc-pkce-s256"
		f.Evidence = []string{fmt.Sprintf("code_challenge_methods_supported: %s", methodsStr)}
		f.Confidence = "HIGH"
		f.Recommendation = "No action required. Ensure clients are configured to enforce PKCE usage."
		f.Tags = []string{"oidc", "iam", "pkce"}
		findings = append(findings, f)
	}

	if hasPlain && !hasS256 {
		f := finding.NewFinding(moduleName, host,
			"PKCE only supports plain code challenge method",
			"The server advertises only the plain PKCE method. "+
				"plain does not protect against code interception because the challenge equals the verifier. "+
				"S256 should be used instead.",
			finding.Low,
		)
		f.ID = "oidc-pkce-plain"
		f.Evidence = []string{fmt.Sprintf("code_challenge_methods_supported: %s", methodsStr)}
		f.Confidence = "HIGH"
		f.Recommendation = "Enable S256 code challenge method and deprecate plain."
		f.Tags = []string{"oidc", "iam", "pkce"}
		findings = append(findings, f)
	}

	return findings
}
