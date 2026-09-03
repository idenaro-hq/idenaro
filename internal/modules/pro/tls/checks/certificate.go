package checks

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"idenaro/internal/finding"
)

// Certificate analyses the leaf TLS certificate and the full chain for expiry,
// self-signing, hostname mismatch, internal SANs, and incomplete chains.
func Certificate(host string, leaf *x509.Certificate, peerCerts []*x509.Certificate) []finding.Finding {
	var findings []finding.Finding

	if time.Now().After(leaf.NotAfter) {
		daysAgo := int(time.Since(leaf.NotAfter).Hours() / 24)
		f := finding.NewFinding(moduleName, host,
			"TLS certificate expired",
			fmt.Sprintf("The TLS certificate expired on %s (%d days ago). Browsers will show security "+
				"warnings and many clients will refuse to connect. Users may be trained to click through "+
				"warnings, weakening security culture.", leaf.NotAfter.Format("2006-01-02"), daysAgo),
			finding.Critical,
		)
		f.ID = "tls-expired"
		f.Evidence = []string{
			fmt.Sprintf("Subject CN: %s", leaf.Subject.CommonName),
			fmt.Sprintf("SANs: %s", strings.Join(leaf.DNSNames, ", ")),
			fmt.Sprintf("Expired: %s", leaf.NotAfter.Format(time.RFC3339)),
			fmt.Sprintf("Days since expiry: %d", daysAgo),
		}
		f.Confidence = "HIGH"
		f.Recommendation = "Renew the certificate immediately. Consider using Let's Encrypt with auto-renewal."
		f.Tags = []string{"tls", "iam"}
		findings = append(findings, f)
	} else {
		daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
		switch {
		case daysLeft <= 14:
			f := finding.NewFinding(moduleName, host,
				"TLS certificate expiring within 14 days",
				fmt.Sprintf("The certificate expires in %d days (%s). Imminent expiry will cause "+
					"service outages and security warnings for users.", daysLeft, leaf.NotAfter.Format("2006-01-02")),
				finding.High,
			)
			f.ID = "tls-expiring-14d"
			f.Evidence = []string{
				fmt.Sprintf("Subject CN: %s", leaf.Subject.CommonName),
				fmt.Sprintf("Expires: %s", leaf.NotAfter.Format(time.RFC3339)),
				fmt.Sprintf("Days remaining: %d", daysLeft),
			}
			f.Confidence = "HIGH"
			f.Recommendation = "Renew the certificate immediately. Implement automated renewal to prevent future incidents."
			f.Tags = []string{"tls", "iam"}
			findings = append(findings, f)
		case daysLeft <= 30:
			f := finding.NewFinding(moduleName, host,
				"TLS certificate expiring within 30 days",
				fmt.Sprintf("The certificate expires in %d days (%s). Begin renewal now to avoid service disruption.",
					daysLeft, leaf.NotAfter.Format("2006-01-02")),
				finding.Medium,
			)
			f.ID = "tls-expiring-30d"
			f.Evidence = []string{
				fmt.Sprintf("Subject CN: %s", leaf.Subject.CommonName),
				fmt.Sprintf("Expires: %s", leaf.NotAfter.Format(time.RFC3339)),
				fmt.Sprintf("Days remaining: %d", daysLeft),
			}
			f.Confidence = "HIGH"
			f.Recommendation = "Renew the certificate before expiry. Set up automated renewal (e.g. Let's Encrypt ACME)."
			f.Tags = []string{"tls", "iam"}
			findings = append(findings, f)
		case daysLeft <= 60:
			f := finding.NewFinding(moduleName, host,
				"TLS certificate expiring within 60 days",
				fmt.Sprintf("The certificate expires in %d days (%s). Schedule renewal soon.",
					daysLeft, leaf.NotAfter.Format("2006-01-02")),
				finding.Low,
			)
			f.ID = "tls-expiring-60d"
			f.Evidence = []string{
				fmt.Sprintf("Subject CN: %s", leaf.Subject.CommonName),
				fmt.Sprintf("Expires: %s", leaf.NotAfter.Format(time.RFC3339)),
				fmt.Sprintf("Days remaining: %d", daysLeft),
			}
			f.Confidence = "HIGH"
			f.Recommendation = "Plan certificate renewal. Consider automated renewal to prevent future alerts."
			f.Tags = []string{"tls", "iam"}
			findings = append(findings, f)
		}
	}

	isSelfSigned := leaf.Issuer.String() == leaf.Subject.String()
	if isSelfSigned {
		f := finding.NewFinding(moduleName, host,
			"Self-signed TLS certificate in use",
			"The certificate is self-signed. Users will receive browser security warnings, "+
				"and automated clients may refuse to connect or require insecure TLS verification bypass. "+
				"Self-signed certs on production auth portals erode user trust and often indicate "+
				"that certificate management processes are absent.",
			finding.High,
		)
		f.ID = "tls-self-signed"
		f.Evidence = []string{
			fmt.Sprintf("Subject: %s", leaf.Subject.CommonName),
			fmt.Sprintf("Issuer: %s", leaf.Issuer.CommonName),
		}
		f.Confidence = "HIGH"
		f.Recommendation = "Use a certificate from a trusted CA. Let's Encrypt provides free trusted certificates."
		f.Tags = []string{"tls", "iam"}
		findings = append(findings, f)
	}

	// hostname is the bare host without port
	bareHost := host
	if h, _, err := splitHostPort(host); err == nil {
		bareHost = h
	}

	if err := leaf.VerifyHostname(bareHost); err != nil {
		sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
		sans = append(sans, leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			sans = append(sans, ip.String())
		}
		f := finding.NewFinding(moduleName, host,
			"TLS certificate hostname mismatch",
			fmt.Sprintf("The certificate is not valid for hostname %q: %v. "+
				"This often indicates a misconfigured reverse proxy or a certificate issued for "+
				"an internal hostname being used on a public endpoint.", bareHost, err),
			finding.High,
		)
		f.ID = "tls-hostname-mismatch"
		f.Evidence = []string{
			fmt.Sprintf("Expected hostname: %s", bareHost),
			fmt.Sprintf("Certificate CN: %s", leaf.Subject.CommonName),
			fmt.Sprintf("SANs: %s", strings.Join(sans, ", ")),
		}
		f.Confidence = "HIGH"
		f.Recommendation = "Issue a certificate that includes the correct hostname in the Subject Alternative Names."
		f.Tags = []string{"tls", "iam"}
		findings = append(findings, f)
	}

	for _, san := range leaf.DNSNames {
		for _, pat := range internalSANPatterns {
			if strings.HasSuffix(strings.ToLower(san), pat) {
				f := finding.NewFinding(moduleName, host,
					"Internal hostname in TLS certificate SAN",
					fmt.Sprintf("The certificate Subject Alternative Names include the internal hostname %q. "+
						"Internal names in public certificates disclose internal network topology "+
						"and are logged in Certificate Transparency logs permanently.", san),
					finding.Medium,
				)
				f.ID = "tls-internal-san"
			f.Evidence = []string{fmt.Sprintf("SAN contains internal name: %s", san)}
				f.Confidence = "HIGH"
				f.Recommendation = "Issue separate certificates for internal and external hostnames. " +
					"Do not include internal DNS names in certificates used on public endpoints."
				f.Tags = []string{"tls", "iam"}
				findings = append(findings, f)
				break
			}
		}
	}

	if len(peerCerts) == 1 && !isSelfSigned {
		roots, err := x509.SystemCertPool()
		if err == nil {
			opts := x509.VerifyOptions{DNSName: bareHost, Roots: roots}
			if _, err := leaf.Verify(opts); err != nil && strings.Contains(err.Error(), "signed by unknown authority") {
				f := finding.NewFinding(moduleName, host,
					"Incomplete TLS certificate chain",
					"The server did not send intermediate certificates. Clients that don't have "+
						"the intermediate CA cached will see validation errors. This is a common "+
						"misconfiguration after certificate renewal.",
					finding.Medium,
				)
				f.Evidence = []string{
					fmt.Sprintf("Certificates in chain: %d (leaf only)", len(peerCerts)),
					fmt.Sprintf("Subject: %s", leaf.Subject.CommonName),
				}
				f.Confidence = "MEDIUM"
				f.Recommendation = "Configure the web server to send the full certificate chain including intermediate CAs."
				f.Tags = []string{"tls", "iam"}
				findings = append(findings, f)
			}
		}
	}

	if len(findings) == 0 {
		daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
		f := finding.NewFinding(moduleName, host,
			"TLS certificate is valid and trusted",
			fmt.Sprintf("The TLS certificate is issued by a trusted CA, matches the hostname, "+
				"and expires in %d days. No expiry warnings, self-signing, hostname mismatch, "+
				"or incomplete chain issues were detected.", daysLeft),
			finding.Info,
		)
		f.ID = "tls-cert-ok"
		f.Evidence = []string{
			fmt.Sprintf("Subject: %s", leaf.Subject.CommonName),
			fmt.Sprintf("Issuer: %s", leaf.Issuer.CommonName),
			fmt.Sprintf("Expires: %s (%d days)", leaf.NotAfter.Format("2006-01-02"), daysLeft),
		}
		f.Confidence = "HIGH"
		f.Tags = []string{"tls", "iam"}
		findings = append(findings, f)
	}

	return findings
}

// splitHostPort wraps net.SplitHostPort but is inlined to avoid importing net
// in this package when the caller already has it.
func splitHostPort(hostport string) (host, port string, err error) {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i], hostport[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("no port in %q", hostport)
}
