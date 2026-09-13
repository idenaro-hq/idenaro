package redirects

import (
	"context"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/redirects/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "redirects"

var callbackPaths = []struct {
	path string
	name string
}{
	{"/callback", "OAuth callback"},
	{"/oauth/callback", "OAuth callback"},
	{"/oidc/callback", "OIDC callback"},
	{"/auth/callback", "auth callback"},
	{"/signin-oidc", "OIDC signin callback"},
	{"/signin-google", "Google signin callback"},
	{"/signin-microsoft", "Microsoft signin callback"},
	{"/saml/callback", "SAML callback"},
	{"/saml/acs", "SAML ACS"},
	{"/auth/saml/callback", "SAML callback"},
	{"/login/callback", "login callback"},
}

var logoutPaths = []struct {
	path string
	name string
}{
	{"/logout", "logout"},
	{"/signout", "signout"},
	{"/auth/logout", "auth logout"},
	{"/realms/master/protocol/openid-connect/logout", "OIDC logout"},
	{"/connect/endsession", "OIDC end session"},
	{"/adfs/ls/?wa=wsignout1.0", "ADFS logout"},
}

type Scanner struct {
	noFollowRedirectClient *http.Client
	httpClient             *http.Client
}

func New(opts httpclient.Options) modules.Module {
	noFollow := opts
	noFollow.FollowRedirects = false
	return &Scanner{
		noFollowRedirectClient: httpclient.New(noFollow),
		httpClient:             httpclient.New(opts),
	}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding

	// 1. Probe login/auth pages for redirect parameter patterns
	authPages := []string{"/login", "/signin", "/auth", "/"}
	for _, page := range authPages {
		endpointURL := target.BaseURL() + page
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}

		findings = append(findings, checks.ScanRedirectParams(target.Host, endpointURL, string(responseBody))...)
	}

	// 2. Test logout endpoints for uncontrolled post-logout redirect
	realm := target.RealmOrDefault()
	for _, lo := range logoutPaths {
		testURL := target.BaseURL() + strings.ReplaceAll(lo.path, "/realms/master/", "/realms/"+realm+"/")
		if !strings.Contains(lo.path, "?") {
			testURL += "?post_logout_redirect_uri=https://evil.com&redirect_uri=https://evil.com"
		}
		endpointURL := target.BaseURL() + strings.ReplaceAll(lo.path, "/realms/master/", "/realms/"+realm+"/")

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.noFollowRedirectClient.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		location := resp.Header.Get("Location")
		findings = append(findings, checks.LogoutOpenRedirect(
			target.Host, endpointURL, lo.name, testURL,
			resp.StatusCode, location,
		)...)

		if resp.StatusCode != http.StatusNotFound {
			findings = append(findings, checks.LogoutAccessible(target.Host, endpointURL, lo.name, resp.StatusCode))
			break
		}
	}

	// 3. Probe callback endpoints for information leakage
	for _, cb := range callbackPaths {
		endpointURL := target.BaseURL() + cb.path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode == http.StatusNotFound {
			continue
		}

		findings = append(findings, checks.CallbackDebug(target.Host, endpointURL, cb.name, string(responseBody))...)
	}

	return findings, nil
}
