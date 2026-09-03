package scim

import (
	"context"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/scim/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "scim"

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
	for _, sp := range checks.SCIMPaths {
		endpointURL := target.BaseURL() + strings.ReplaceAll(sp.Path, "/realms/master/", "/realms/"+realm+"/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		req.Header.Set("Accept", "application/scim+json, application/json, */*")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		ct := resp.Header.Get("Content-Type")

		finalURL := httpclient.EffectiveFinalURL(resp, responseBody)
		if httpclient.RedirectLooksSafe(req.URL, finalURL, ct, responseBody) {
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		redirected := httpclient.Redirected(req.URL, finalURL)
		bodyStr := string(responseBody)

		if resp.StatusCode == http.StatusOK {
			findings = append(findings, checks.Unauthenticated(target.Host, endpointURL, sp.Description, bodyStr, ct, resp.StatusCode, redirected)...)
		} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			findings = append(findings, checks.RequiresAuth(target.Host, endpointURL, sp.Description, resp.StatusCode))
			break // Found a SCIM endpoint; no need to enumerate further.
		}
	}

	return findings, nil
}
