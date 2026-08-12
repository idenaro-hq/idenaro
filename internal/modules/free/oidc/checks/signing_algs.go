package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

var weakAlgorithms = map[string]string{
	"none":  "No signing - token forgery is trivially possible if clients accept unsigned tokens",
	"HS256": "Symmetric HMAC - requires sharing the secret with all validators, symmetric confusion attacks",
	"HS384": "Symmetric HMAC - same risks as HS256",
	"HS512": "Symmetric HMAC - same risks as HS256",
	"RS1":   "RSA with SHA-1 - deprecated, collision-prone",
}

// SigningAlgorithms checks id_token_signing_alg_values_supported for weak or deprecated algorithms.
func SigningAlgorithms(host string, supported []string) []finding.Finding {
	var findings []finding.Finding
	for _, alg := range supported {
		if reason, weak := weakAlgorithms[alg]; weak {
			sev := finding.Medium
			if alg == "none" {
				sev = finding.Critical
			}
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("Weak/insecure signing algorithm advertised: %s", alg),
				fmt.Sprintf("The algorithm %q is listed in id_token_signing_alg_values_supported. %s", alg, reason),
				sev,
			)
			if alg == "none" {
				f.ID = "oidc-alg-none"
			} else {
				f.ID = "oidc-alg-symmetric"
			}
			f.Evidence = []string{fmt.Sprintf("id_token_signing_alg_values_supported includes: %q", alg)}
			f.Confidence = "HIGH"
			f.Recommendation = "Use RS256 or ES256. Remove symmetric and deprecated algorithms from the supported list."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}
	}

	if len(supported) > 0 && len(findings) == 0 {
		f := finding.NewFinding(moduleName, host,
			"No weak signing algorithms advertised",
			"All algorithms in id_token_signing_alg_values_supported are considered secure. "+
				"No deprecated or symmetric algorithms (alg:none, HS256/384/512, RS1) were found.",
			finding.Info,
		)
		f.ID = "oidc-alg-ok"
		f.Evidence = []string{fmt.Sprintf("id_token_signing_alg_values_supported: %s", strings.Join(supported, ", "))}
		f.Confidence = "HIGH"
		f.Recommendation = "No action required."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	return findings
}
