package checks

import (
	"strings"

	"idenaro/internal/finding"
)

// TokenAuth inspects token_endpoint_auth_methods_supported and reports weak or
// dangerous authentication methods.
func TokenAuth(host string, methods []string) []finding.Finding {
	var findings []finding.Finding

	hasNone := false
	hasSecure := false
	for _, method := range methods {
		if strings.EqualFold(method, "none") {
			hasNone = true
			f := finding.NewFinding(moduleName, host,
				"Token endpoint accepts unauthenticated client requests (auth method: none)",
				"token_endpoint_auth_methods_supported includes \"none\", meaning the token endpoint "+
					"will accept requests from clients that provide no client credential. "+
					"This allows any actor to obtain tokens on behalf of unprotected clients "+
					"without proving client identity.",
				finding.High,
			)
			f.ID = "oidc-token-endpoint-auth-none"
			f.Evidence = []string{`token_endpoint_auth_methods_supported includes: "none"`}
			f.Confidence = "HIGH"
			f.Recommendation = "Remove \"none\" from supported auth methods. " +
				"Require client_secret_post, client_secret_basic, or private_key_jwt for all non-public clients."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}

		if strings.EqualFold(method, "client_secret_post") {
			f := finding.NewFinding(moduleName, host,
				"Client secret transmitted in POST body (client_secret_post)",
				"The token endpoint supports client_secret_post, which places the client secret "+
					"in the HTTP body. This exposes the secret in access logs, proxy logs, and "+
					"request traces unless explicit log redaction is in place.",
				finding.Low,
			)
			f.Evidence = []string{`token_endpoint_auth_methods_supported includes: "client_secret_post"`}
			f.Confidence = "MEDIUM"
			f.Recommendation = "Prefer client_secret_basic (Authorization header) or private_key_jwt " +
				"to keep secrets out of the request body and logs."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}

		switch strings.ToLower(method) {
		case "client_secret_basic", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth":
			hasSecure = true
		}
	}

	if !hasNone && hasSecure && len(methods) > 0 {
		f := finding.NewFinding(moduleName, host,
			"Token endpoint requires client authentication",
			"The token endpoint only advertises strong client authentication methods "+
				"(client_secret_basic, private_key_jwt, or mTLS). The \"none\" method is absent, "+
				"meaning all clients must authenticate before obtaining tokens.",
			finding.Info,
		)
		f.ID = "oidc-token-auth-ok"
		f.Evidence = []string{strings.Join(methods, ", ")}
		f.Confidence = "HIGH"
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	return findings
}
