package checks

import (
	"crypto/tls"
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// weakCipherKeywords are substrings that, if found in a negotiated cipher suite
// name, indicate use of a deprecated or broken algorithm. Go's TLS stack does
// not negotiate RC4/NULL/EXPORT suites, but 3DES (TLS_RSA_WITH_3DES_EDE_CBC_SHA)
// can still appear in TLS 1.2 handshakes with legacy servers.
var weakCipherKeywords = []string{"RC4", "DES", "3DES", "EXPORT", "NULL", "ANON"}

// WeakCipher returns a HIGH finding if the negotiated cipher suite name
// contains a known-weak algorithm keyword.
func WeakCipher(host string, suite uint16) []finding.Finding {
	name := tls.CipherSuiteName(suite)
	nameUpper := strings.ToUpper(name)
	for _, kw := range weakCipherKeywords {
		if strings.Contains(nameUpper, kw) {
			f := finding.NewFinding(moduleName, host,
				"Weak cipher suite negotiated",
				fmt.Sprintf("The TLS handshake negotiated cipher suite %q which contains the deprecated "+
					"algorithm %q. Weak ciphers can be exploited to decrypt or tamper with encrypted traffic.",
					name, kw),
				finding.High,
			)
			f.ID = "tls-weak-cipher"
			f.Evidence = []string{
				fmt.Sprintf("Negotiated cipher suite: %s (0x%04x)", name, suite),
				fmt.Sprintf("Weak algorithm matched: %s", kw),
			}
			f.Confidence = "HIGH"
			f.Recommendation = "Restrict the server cipher suite list to AEAD ciphers " +
				"(AES-128/256-GCM, ChaCha20-Poly1305). Remove all 3DES, RC4, DES, EXPORT, NULL, and anonymous suites."
			f.Tags = []string{"tls", "iam"}
			return []finding.Finding{f}
		}
	}
	return nil
}
