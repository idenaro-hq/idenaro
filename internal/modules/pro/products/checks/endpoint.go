package checks

import (
	"fmt"
	"net/url"

	"idenaro/internal/finding"
)

func EndpointFound(host string, p Probe, statusCode int, redirected bool, finalURL *url.URL) finding.Finding {
	sev := p.Severity
	confidence := "HIGH"
	if redirected && sev != finding.Critical {
		sev = finding.Info
		confidence = "LOW"
	}

	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("[%s] %s", p.Vendor, p.Title),
		p.Description,
		sev,
	)
	if p.DocID != "" {
		f.ID = p.DocID
	}
	f.Evidence = []string{
		fmt.Sprintf("HTTP %d at %s", statusCode, p.Path),
		fmt.Sprintf("Vendor: %s", p.Vendor),
	}
	if redirected {
		f.Evidence = append(f.Evidence, fmt.Sprintf("redirected to %s", finalURL.String()))
	}
	f.Confidence = confidence
	f.Recommendation = p.Recommend
	f.Tags = p.Tags
	return f
}
