package csp

import (
	"context"
	"fmt"
	"net/http"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/csp/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "csp"

type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding

	paths := []string{"/", "/login", "/signin", "/auth"}
	checked := map[string]bool{}

	for _, path := range paths {
		endpointURL := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		cspHeader := resp.Header.Get("Content-Security-Policy")
		cspro := resp.Header.Get("Content-Security-Policy-Report-Only")

		if cspHeader == "" && cspro != "" {
			if !checked["report-only"] {
				checked["report-only"] = true
				f := finding.NewFinding(moduleName, target.Host,
					"CSP in report-only mode - not enforced",
					"Content-Security-Policy-Report-Only is present but CSP enforcement is absent. "+
						"Report-only mode collects violations but does not block anything. "+
						"This provides no actual XSS protection.",
					finding.Medium,
				)
				f.ID = "csp-report-only"
				f.Evidence = []string{
					fmt.Sprintf("Content-Security-Policy-Report-Only: %s", truncate(cspro, 120)),
					"Content-Security-Policy: (absent)",
					"URL: " + endpointURL,
				}
				f.Confidence = "HIGH"
				f.Recommendation = "Promote CSP from report-only to enforcement mode. " +
					"Use report-only only during initial rollout with a short transition window."
				f.Tags = []string{"csp", "headers", "iam"}
				findings = append(findings, f)
			}
			continue
		}

		if cspHeader == "" {
			continue
		}

		if checked[cspHeader] {
			continue
		}
		checked[cspHeader] = true

		findings = append(findings, checks.Policy(target.Host, cspHeader, endpointURL)...)
	}

	return findings, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
