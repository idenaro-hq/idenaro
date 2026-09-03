package cookies

import (
	"context"
	"net/http"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/cookies/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "cookies"

var loginPaths = []string{"/", "/login", "/signin", "/auth", "/auth/login", "/account/login"}

type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding

	seenCookieKeys := make(map[string]bool)
	authCookieNamesFound := make(map[string]bool)

	for _, path := range loginPaths {
		pageURL := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		for _, cookie := range resp.Cookies() {
			deduplicationKey := cookie.Name + "@" + path
			if seenCookieKeys[deduplicationKey] {
				continue
			}
			seenCookieKeys[deduplicationKey] = true

			if checks.IsAuthCookieName(cookie.Name) {
				authCookieNamesFound[cookie.Name] = true
			}
			findings = append(findings, checks.Flags(cookie, target.Host, pageURL)...)
		}
	}

	if len(authCookieNamesFound) > 2 {
		findings = append(findings, checks.MultipleCookies(target.Host, authCookieNamesFound))
	}

	return findings, nil
}
