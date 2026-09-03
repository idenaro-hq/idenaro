package checks

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"idenaro/internal/finding"
)

// KeyDescriptor is a minimal view of a SAML KeyDescriptor used to avoid
// importing the parent saml package (circular dependency).
type KeyDescriptor struct {
	Use    string
	CertB64 string // raw base64 from X509Certificate element (whitespace stripped)
}

// KeyDescriptors analyses signing and encryption key descriptors for a given
// role ("IdP" or "SP") and returns all certificate-related findings.
func KeyDescriptors(host, role string, keyDescs []KeyDescriptor) []finding.Finding {
	var findings []finding.Finding

	signingCerts := 0
	encryptionCerts := 0
	var signingCertPEM string

	for _, kd := range keyDescs {
		certB64 := strings.TrimSpace(kd.CertB64)
		certB64 = strings.ReplaceAll(certB64, "\n", "")
		certB64 = strings.ReplaceAll(certB64, " ", "")
		if certB64 == "" {
			continue
		}

		certDER, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			continue
		}

		use := strings.ToLower(kd.Use)
		if use == "signing" || use == "" {
			signingCerts++
			signingCertPEM = certB64
		}
		if use == "encryption" {
			encryptionCerts++
		}

		if time.Now().After(cert.NotAfter) {
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("SAML %s signing certificate expired", role),
				fmt.Sprintf("The %s signing certificate expired on %s. "+
					"Authentication failures or lenient signature validation may follow.", role, cert.NotAfter.Format("2006-01-02")),
				finding.High,
			)
			f.ID = "saml-cert-expired"
			f.Evidence = []string{
				fmt.Sprintf("Subject: %s", cert.Subject.CommonName),
				fmt.Sprintf("Expired: %s", cert.NotAfter.Format(time.RFC3339)),
			}
			f.Confidence = "HIGH"
			f.Recommendation = "Rotate the certificate immediately and update federation partner metadata."
			f.Tags = []string{"saml", "iam", "tls"}
			findings = append(findings, f)
		} else if time.Until(cert.NotAfter) < 30*24*time.Hour {
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("SAML %s signing certificate expiring within 30 days", role),
				fmt.Sprintf("Certificate expires on %s.", cert.NotAfter.Format("2006-01-02")),
				finding.Medium,
			)
			f.ID = "saml-cert-expiring"
			f.Evidence = []string{fmt.Sprintf("Expires: %s", cert.NotAfter.Format(time.RFC3339))}
			f.Confidence = "HIGH"
			f.Recommendation = "Plan certificate rotation before expiry. Update all SP metadata after rotation."
			f.Tags = []string{"saml", "iam", "tls"}
			findings = append(findings, f)
		} else if time.Until(cert.NotAfter) > 3*365*24*time.Hour {
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("SAML %s certificate has very long validity period", role),
				fmt.Sprintf("The certificate is valid until %s (%d years). "+
					"Long-lived certificates increase the blast radius of key compromise.",
					cert.NotAfter.Format("2006-01-02"),
					int(time.Until(cert.NotAfter).Hours()/8760)),
				finding.Low,
			)
			f.ID = "saml-cert-long-lived"
			f.Evidence = []string{fmt.Sprintf("Valid until: %s", cert.NotAfter.Format(time.RFC3339))}
			f.Confidence = "HIGH"
			f.Recommendation = "Use certificates with a maximum 2-year validity. Implement automated rotation."
			f.Tags = []string{"saml", "iam"}
			findings = append(findings, f)
		}
	}

	if signingCerts > 0 && encryptionCerts > 0 && signingCertPEM != "" {
		for _, kd := range keyDescs {
			if strings.EqualFold(kd.Use, "encryption") {
				enc := strings.ReplaceAll(strings.TrimSpace(kd.CertB64), "\n", "")
				enc = strings.ReplaceAll(enc, " ", "")
				if enc == signingCertPEM {
					f := finding.NewFinding(moduleName, host,
						fmt.Sprintf("SAML %s uses same certificate for signing and encryption", role),
						"The signing and encryption key descriptors reference the same certificate. "+
							"Best practice requires separate keys: compromise of the signing key then "+
							"also compromises assertion confidentiality.",
						finding.Low,
					)
					f.ID = "saml-same-cert"
					f.Evidence = []string{"Signing and encryption KeyDescriptors contain identical certificate"}
					f.Confidence = "HIGH"
					f.Recommendation = "Use separate key pairs for signing and encryption."
					f.Tags = []string{"saml", "iam"}
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}
