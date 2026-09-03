package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	freeclient "idenaro/internal/modules/free/client"
	"idenaro/internal/modules/free/oidc"
	"idenaro/internal/modules/pro/client/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "client-pro"

// authPagePaths are pages probed for clickjacking and CSP checks.
var authPagePaths = []string{"/login", "/auth", "/signin", "/api/auth"}

// silentAuthClientID is the dummy client_id sent with prompt=none probes.
const silentAuthClientID = "probe-scanner"

// silentAuthRedirectURI is the dummy redirect sent with prompt=none probes.
const silentAuthRedirectURI = "https://probe.invalid/callback"

type Scanner struct {
	freeModule       modules.Module
	httpClient       *http.Client
	noRedirectClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	noRedirectOpts := opts
	noRedirectOpts.FollowRedirects = false
	return &Scanner{
		freeModule:       freeclient.New(opts),
		httpClient:       httpclient.New(opts),
		noRedirectClient: httpclient.New(noRedirectOpts),
	}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	// All free checks run first.
	findings, err := s.freeModule.Run(ctx, target)
	if err != nil {
		return findings, err
	}

	// Pro-only checks.
	findings = append(findings, safeRun(func() []finding.Finding {
		return s.checkLoginPageHeaders(ctx, target)
	})...)

	findings = append(findings, safeRun(func() []finding.Finding {
		return s.checkSilentAuth(ctx, target)
	})...)

	return findings, nil
}

// safeRun wraps fn so that a panic in one check cannot abort the rest.
func safeRun(fn func() []finding.Finding) (out []finding.Finding) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
		}
	}()
	return fn()
}

// checkLoginPageHeaders fetches the first reachable auth page and runs the
// clickjacking and CSP checks against the response headers.
func (s *Scanner) checkLoginPageHeaders(ctx context.Context, target modules.Target) []finding.Finding {
	for _, path := range authPagePaths {
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
		csp := resp.Header.Get("Content-Security-Policy")
		cjFindings := checks.Clickjacking(target.Host, pageURL, resp)
		cspFindings := checks.AuthPageCSP(target.Host, pageURL, csp)
		resp.Body.Close()
		return append(cjFindings, cspFindings...)
	}
	return nil
}

// checkSilentAuth discovers the OIDC authorization endpoint and sends a
// prompt=none probe to test whether the server correctly refuses token issuance
// without an active session.
func (s *Scanner) checkSilentAuth(ctx context.Context, target modules.Target) []finding.Finding {
	authzEndpoint := s.discoverAuthzEndpoint(ctx, target)
	if authzEndpoint == "" {
		return []finding.Finding{checks.SilentAuthNoEndpoint(target.Host)}
	}

	probeURL := buildSilentAuthProbe(authzEndpoint)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return []finding.Finding{checks.SilentAuthNoEndpoint(target.Host)}
	}
	req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

	resp, err := s.noRedirectClient.Do(req)
	if err != nil {
		return checks.SilentAuth(target.Host, probeURL, 0, "")
	}
	resp.Body.Close()

	location := checks.ParseLocation(resp)
	return checks.SilentAuth(target.Host, probeURL, resp.StatusCode, location)
}

// discoverAuthzEndpoint fetches OIDC discovery and returns the authorization_endpoint.
func (s *Scanner) discoverAuthzEndpoint(ctx context.Context, target modules.Target) string {
	body, _ := oidc.FetchDiscovery(ctx, s.httpClient, target)
	if body == nil {
		// Fall back to /authorize as a common non-discovery endpoint.
		u := target.BaseURL() + "/authorize"
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return ""
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return u
		}
		return ""
	}

	var disc struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
	}
	if err := json.Unmarshal(body, &disc); err != nil || disc.AuthorizationEndpoint == "" {
		return ""
	}
	return disc.AuthorizationEndpoint
}

// buildSilentAuthProbe constructs a prompt=none authorization request URL.
func buildSilentAuthProbe(authzEndpoint string) string {
	return fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&prompt=none&scope=openid",
		authzEndpoint,
		url.QueryEscape(silentAuthClientID),
		url.QueryEscape(silentAuthRedirectURI),
	)
}
