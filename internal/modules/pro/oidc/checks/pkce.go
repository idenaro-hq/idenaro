package checks

import (
	"fmt"

	"idenaro/internal/finding"
)

// PKCE checks code_challenge_methods_supported and returns findings if PKCE is
// absent or only the weak plain method is supported.
func PKCE(host string, methodsSupported []string) []finding.Finding {
	var findings []finding.Finding

	if len(methodsSupported) == 0 {
		f := finding.NewFinding(moduleName, host,
			"PKCE not advertised in OIDC discovery",
			"code_challenge_methods_supported is absent. PKCE prevents authorization code "+
				"interception attacks, especially for public clients (SPAs, mobile apps). "+
				"Its absence means the IdP cannot enforce PKCE, leaving public clients unprotected.",
			finding.Medium,
		)
		f.ID = "oidc-pkce"
		f.Evidence = []string{"code_challenge_methods_supported: absent or empty"}
		f.Confidence = "MEDIUM"
		f.Recommendation = "Enable PKCE support (S256 method). Require PKCE for all public clients."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
		return findings
	}

	hasS256 := false
	for _, m := range methodsSupported {
		if m == "S256" {
			hasS256 = true
			break
		}
	}
	if !hasS256 {
		f := finding.NewFinding(moduleName, host,
			"PKCE S256 method not supported",
			"Only the plain PKCE method is supported. The plain method provides weaker protection "+
				"than S256 since the code_verifier is transmitted without hashing, allowing it to "+
				"be intercepted before the token exchange completes.",
			finding.Low,
		)
		f.ID = "oidc-pkce-plain"
		f.Evidence = []string{fmt.Sprintf("code_challenge_methods_supported: %v", methodsSupported)}
		f.Confidence = "HIGH"
		f.Recommendation = "Enable S256 PKCE method and disable or deprioritize plain."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	} else {
		f := finding.NewFinding(moduleName, host,
			"PKCE S256 supported",
			"The IdP advertises S256 as a supported PKCE code challenge method. S256 uses a "+
				"SHA-256 hash of the code_verifier, ensuring it cannot be replayed even if "+
				"intercepted in transit.",
			finding.Info,
		)
		f.ID = "oidc-pro-pkce-s256-ok"
		f.Evidence = []string{fmt.Sprintf("code_challenge_methods_supported: %v", methodsSupported)}
		f.Confidence = "HIGH"
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	return findings
}
