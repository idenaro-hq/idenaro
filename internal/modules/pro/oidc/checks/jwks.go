package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// JWKSKey is a minimal view of a JWK entry.
type JWKSKey struct {
	Kid string
	Kty string
	N   string // RSA modulus (base64url), used to estimate key size
}

// JWKS checks the parsed JWKS key set for empty sets, single-key (no rotation
// readiness), and undersized RSA keys.
func JWKS(host, jwksURL string, keys []JWKSKey) []finding.Finding {
	var findings []finding.Finding

	if len(keys) == 0 {
		f := finding.NewFinding(moduleName, host,
			"JWKS endpoint returned no signing keys",
			"The JWKS endpoint at "+jwksURL+" returned an empty key set. "+
				"Clients cannot validate token signatures, which may cause authentication failures "+
				"or - if clients skip validation - accept unsigned tokens.",
			finding.High,
		)
		f.Evidence = []string{jwksURL, "keys: []"}
		f.Confidence = "HIGH"
		f.Recommendation = "Ensure at least one active signing key is published in the JWKS."
		f.Tags = []string{"oidc", "iam", "tls"}
		findings = append(findings, f)
		return findings
	}

	if len(keys) == 1 {
		f := finding.NewFinding(moduleName, host,
			"JWKS contains only one signing key - no rotation readiness",
			"Only a single key is published in the JWKS. Rotating keys (publishing a new key before "+
				"retiring the old one) requires at least two keys to be present simultaneously. "+
				"With a single key, any emergency rotation causes immediate token validation failures.",
			finding.Low,
		)
		f.Evidence = []string{
			jwksURL,
			fmt.Sprintf("key count: 1 (kid=%s)", keys[0].Kid),
		}
		f.Confidence = "HIGH"
		f.Recommendation = "Publish at least two keys during rotation windows. " +
			"Keep the retiring key active until all issued tokens have expired."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	undersized := false
	for _, key := range keys {
		if strings.EqualFold(key.Kty, "RSA") && key.N != "" {
			nBytes := base64URLLen(key.N)
			if nBytes > 0 && nBytes < 256 { // < 2048 bits
				undersized = true
				f := finding.NewFinding(moduleName, host,
					fmt.Sprintf("RSA signing key may be undersized (kid=%s)", key.Kid),
					fmt.Sprintf("The RSA key with kid=%q has a modulus of approximately %d bits. "+
						"Keys below 2048 bits are considered insecure and are no longer recommended "+
						"by NIST SP 800-131A.", key.Kid, nBytes*8),
					finding.Medium,
				)
				f.Evidence = []string{
					fmt.Sprintf("kid: %s, kty: RSA, estimated bits: %d", key.Kid, nBytes*8),
				}
				f.Confidence = "MEDIUM"
				f.Recommendation = "Use RSA keys of at least 2048 bits. Prefer RS256 with 4096-bit keys or ES256."
				f.Tags = []string{"oidc", "iam", "tls"}
				findings = append(findings, f)
			}
		}
	}

	if len(keys) >= 2 && !undersized {
		kids := make([]string, 0, len(keys))
		for _, k := range keys {
			kids = append(kids, k.Kid)
		}
		f := finding.NewFinding(moduleName, host,
			"JWKS contains multiple adequately-sized signing keys",
			fmt.Sprintf("The JWKS endpoint publishes %d signing keys. Multiple keys enable graceful "+
				"key rotation (new key published before the old one is retired) without causing "+
				"token validation failures for already-issued tokens.", len(keys)),
			finding.Info,
		)
		f.ID = "oidc-jwks-ok"
		f.Evidence = []string{
			jwksURL,
			fmt.Sprintf("key count: %d, kids: %s", len(keys), strings.Join(kids, ", ")),
		}
		f.Confidence = "HIGH"
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	return findings
}

// base64URLLen returns the decoded byte length from a base64url string without
// decoding it - used as a proxy for RSA key size.
func base64URLLen(s string) int {
	s = strings.TrimRight(s, "=")
	return len(s) * 6 / 8
}
