package products

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/products/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "products"

type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding

	realm := target.RealmOrDefault()
	for _, probe := range checks.Probes {
		endpointURL := target.BaseURL() + strings.ReplaceAll(probe.Path, "/realms/master/", "/realms/"+realm+"/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		req.Header.Set("Accept", "text/html,application/json,*/*")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}

		contentType := resp.Header.Get("Content-Type")
		bodyStr := string(responseBody)

		finalURL := httpclient.EffectiveFinalURL(resp, responseBody)
		if httpclient.RedirectLooksSafe(req.URL, finalURL, contentType, responseBody) {
			continue
		}

		redirected := httpclient.Redirected(req.URL, finalURL)

		if probe.DetectFn != nil && !probe.DetectFn(resp.StatusCode, bodyStr, contentType) {
			continue
		}
		if probe.DetectFn == nil && resp.StatusCode != http.StatusOK {
			continue
		}

		f := checks.EndpointFound(target.Host, probe, resp.StatusCode, redirected, finalURL)
		// Overwrite the path-based evidence with the resolved URL.
		f.Evidence = []string{
			fmt.Sprintf("HTTP %d at %s", resp.StatusCode, endpointURL),
			fmt.Sprintf("Vendor: %s", probe.Vendor),
		}
		if redirected {
			f.Evidence = append(f.Evidence, fmt.Sprintf("redirected to %s", finalURL.String()))
		}
		findings = append(findings, f)
	}

	return findings, nil
}
