package lifecycle

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/lifecycle/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "lifecycle"

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
		pageURL := target.BaseURL() + strings.ReplaceAll(probe.Path, "/realms/master/", "/realms/"+realm+"/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		req.Header.Set("Accept", "text/html,application/json,*/*")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		ct := resp.Header.Get("Content-Type")
		finalURL := httpclient.EffectiveFinalURL(resp, responseBody)
		if httpclient.RedirectLooksSafe(req.URL, finalURL, ct, responseBody) {
			continue
		}
		redirected := httpclient.Redirected(req.URL, finalURL)

		f := checks.EndpointFound(target.Host, probe, resp.StatusCode, redirected, finalURL, ct, string(responseBody))
		f.Evidence = []string{fmt.Sprintf("HTTP %d at %s", resp.StatusCode, pageURL)}
		findings = append(findings, f)
	}

	return findings, nil
}
