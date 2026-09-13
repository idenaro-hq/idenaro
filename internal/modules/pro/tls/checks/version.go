package checks

import (
	"context"
	"crypto/tls"
	"fmt"

	"idenaro/internal/finding"
)

var tlsVersionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// Version returns a finding if the negotiated TLS version is below 1.2,
// or an INFO finding confirming the negotiated version when it meets requirements.
func Version(host string, version uint16) []finding.Finding {
	if version >= tls.VersionTLS12 {
		name, ok := tlsVersionNames[version]
		if !ok {
			name = fmt.Sprintf("unknown (0x%x)", version)
		}
		f := finding.NewFinding(moduleName, host,
			fmt.Sprintf("Secure TLS version negotiated: %s", name),
			fmt.Sprintf("The server negotiated %s, which meets or exceeds the minimum required "+
				"version (TLS 1.2). Deprecated protocol versions (TLS 1.0, TLS 1.1) are not "+
				"accepted.", name),
			finding.Info,
		)
		f.ID = "tls-version-ok"
		f.Evidence = []string{fmt.Sprintf("Negotiated TLS version: %s", name)}
		f.Confidence = "HIGH"
		f.Tags = []string{"tls", "iam"}
		return []finding.Finding{f}
	}
	name, ok := tlsVersionNames[version]
	if !ok {
		name = fmt.Sprintf("unknown (0x%x)", version)
	}
	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("Deprecated TLS version negotiated: %s", name),
		fmt.Sprintf("The server negotiated %s which is deprecated and vulnerable to POODLE, BEAST, "+
			"and other downgrade attacks. Auth portals must use TLS 1.2 at minimum.", name),
		finding.High,
	)
	f.ID = "tls-deprecated-version"
	f.Evidence = []string{fmt.Sprintf("Negotiated TLS version: %s", name)}
	f.Confidence = "HIGH"
	f.Recommendation = "Disable TLS 1.0 and 1.1. Require TLS 1.2 minimum, prefer TLS 1.3."
	f.Tags = []string{"tls", "iam"}
	return []finding.Finding{f}
}

// LegacyVersionAccepted actively probes whether the server accepts TLS 1.0 or
// TLS 1.1 by attempting a handshake with the version range pinned. This is more
// rigorous than Version() which only inspects the negotiated version from the
// default handshake - a server may default to TLS 1.3 while still accepting 1.0.
func LegacyVersionAccepted(ctx context.Context, host, tlsAddr, serverName string) []finding.Finding {
	probes := []struct {
		ver  uint16
		name string
		sev  finding.Severity
	}{
		{tls.VersionTLS10, "TLS 1.0", finding.High},
		{tls.VersionTLS11, "TLS 1.1", finding.Medium},
	}

	var findings []finding.Finding
	for _, p := range probes {
		cfg := &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional for audit
			ServerName:         serverName,
			MinVersion:         p.ver,
			MaxVersion:         p.ver,
		}
		d := tls.Dialer{Config: cfg}
		conn, err := d.DialContext(ctx, "tcp", tlsAddr)
		if err != nil {
			continue // server rejected this version - good
		}
		_ = conn.Close()

		f := finding.NewFinding(moduleName, host,
			fmt.Sprintf("Deprecated TLS version accepted by server: %s", p.name),
			fmt.Sprintf("The server accepted a TLS handshake at %s even though its default negotiation "+
				"may use a higher version. A downgrade attack can force clients to use this deprecated "+
				"protocol (POODLE, BEAST). Servers must refuse connections at deprecated versions entirely.", p.name),
			p.sev,
		)
		f.ID = fmt.Sprintf("tls-accepts-%s", p.name[4:]) // e.g. "tls-accepts-1.0"
		f.Evidence = []string{
			fmt.Sprintf("Successful handshake pinned to: %s", p.name),
			fmt.Sprintf("Target: %s", tlsAddr),
		}
		f.Confidence = "HIGH"
		f.Recommendation = fmt.Sprintf(
			"Configure the server to reject %s connections. Set the minimum TLS version to 1.2.", p.name)
		f.Tags = []string{"tls", "iam"}
		findings = append(findings, f)
	}
	return findings
}
