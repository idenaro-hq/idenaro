package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/free/client/checks"
	"idenaro/pkg/httpclient"
	"idenaro/pkg/jwtforge"
)

const moduleName = "client"

// protectedCandidates are probed in order to find a 401/403-gated endpoint for token checks.
// /oauth2/auth is the oauth2-proxy auth-subrequest endpoint used by nginx auth_request setups -
// it returns 401 for unauthenticated requests, making it a reliable discovery target.
var protectedCandidates = []string{
	"/api/me", "/api/user", "/api/v1/me", "/api/v1/user", "/graphql",
	"/oauth2/auth",
}

// corsFallbackPaths are probed for CORS checks when no protected endpoint is found.
var corsFallbackPaths = []string{"/api/auth", "/api/user", "/api/me"}

// callbackPaths are the OAuth/OIDC callback endpoints to probe for state-param and redirect checks.
var callbackPaths = []string{"/callback", "/oauth/callback", "/oauth2/callback"}

// authPagePaths are pages most likely to issue session cookies on a GET response.
var authPagePaths = []string{"/login", "/auth", "/signin", "/api/auth", "/api/login"}

const (
	attackerOrigin   = "https://evil-corp.com"
	attackerRedirect = "https://evil-corp.com"
)

type Scanner struct {
	httpClient       *http.Client
	noRedirectClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	noRedirectOpts := opts
	noRedirectOpts.FollowRedirects = false
	return &Scanner{
		httpClient:       httpclient.New(opts),
		noRedirectClient: httpclient.New(noRedirectOpts),
	}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding

	protectedEndpoint, discoveryEvidence := s.findProtectedEndpoint(ctx, target)
	if protectedEndpoint == "" {
		f := finding.NewFinding(moduleName, target.Host,
			"No protected endpoint found for token probing",
			"None of the common protected paths returned 401 or 403. "+
				"Token validation checks were skipped. "+
				"Tip: append the protected path to the target URL, e.g. https://app.example.com/oauth2/auth",
			finding.Info,
		)
		f.ID = "client-no-endpoint"
		f.Evidence = discoveryEvidence
		f.Confidence = "LOW"
		f.NIS2Articles = []string{checks.NIS2TokenVal}
		f.Tags = []string{moduleName, "client-token-validation"}
		findings = append(findings, f)
	} else {
		disc := finding.NewFinding(moduleName, target.Host,
			"Protected endpoint identified - token probes active",
			fmt.Sprintf("A 401-gated endpoint was located at %s. "+
				"alg:none and expiry probes were sent to this endpoint.", protectedEndpoint),
			finding.Info,
		)
		disc.ID = "client-endpoint-found"
		disc.Evidence = discoveryEvidence
		disc.Confidence = "HIGH"
		disc.NIS2Articles = []string{checks.NIS2TokenVal}
		disc.Tags = []string{moduleName, "client-token-validation"}
		findings = append(findings, disc)

		findings = append(findings, safeRun(func() []finding.Finding {
			return s.checkAlgNone(ctx, target, protectedEndpoint)
		})...)
		findings = append(findings, safeRun(func() []finding.Finding {
			return s.checkExpiredToken(ctx, target, protectedEndpoint)
		})...)
	}

	corsEndpoint := protectedEndpoint
	if corsEndpoint == "" {
		corsEndpoint = target.BaseURL() + corsFallbackPaths[0]
	}
	findings = append(findings, safeRun(func() []finding.Finding {
		return s.checkCORS(ctx, target, corsEndpoint)
	})...)

	findings = append(findings, safeRun(func() []finding.Finding {
		return s.checkSessionCookies(ctx, target)
	})...)

	findings = append(findings, safeRun(func() []finding.Finding {
		return s.checkCallbackStateParam(ctx, target)
	})...)

	findings = append(findings, safeRun(func() []finding.Finding {
		return s.checkOpenRedirect(ctx, target)
	})...)

	return findings, nil
}

// safeRun executes fn and recovers from any panic so that a single failing check
// cannot abort the remaining checks in the module.
func safeRun(fn func() []finding.Finding) (out []finding.Finding) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
		}
	}()
	return fn()
}

// findProtectedEndpoint returns the full URL of a 401/403-gated endpoint and a
// list of evidence strings describing how it was found (or not found).
func (s *Scanner) findProtectedEndpoint(ctx context.Context, target modules.Target) (string, []string) {
	if target.ClientApp != "" {
		return target.ClientApp, []string{fmt.Sprintf("User-specified client app: %s (no probe performed)", target.ClientApp)}
	}
	if target.Path != "" {
		u := target.BaseURL() + target.Path
		return u, []string{fmt.Sprintf("User-specified path: %s (no probe performed)", u)}
	}

	var tried []string
	for _, path := range protectedCandidates {
		u := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		resp, err := s.httpClient.Do(req)
		if err != nil {
			tried = append(tried, fmt.Sprintf("GET %s → error (%s)", u, err))
			continue
		}
		resp.Body.Close()
		tried = append(tried, fmt.Sprintf("GET %s → HTTP %d", u, resp.StatusCode))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return u, tried
		}
	}
	return "", tried
}

// probeBaseline sends a GET with no Authorization header and returns the HTTP status code.
func (s *Scanner) probeBaseline(ctx context.Context, endpointURL string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (s *Scanner) checkAlgNone(ctx context.Context, target modules.Target, endpointURL string) []finding.Finding {
	baseline := s.probeBaseline(ctx, endpointURL)

	token := jwtforge.CraftUnsigned(map[string]any{
		"sub": "scanner-probe",
		"iss": "https://probe.invalid",
		"aud": "test",
		"iat": 9999999999,
		"exp": 9999999999,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	return checks.AlgNone(target.Host, endpointURL, baseline, resp.StatusCode)
}

func (s *Scanner) checkExpiredToken(ctx context.Context, target modules.Target, endpointURL string) []finding.Finding {
	baseline := s.probeBaseline(ctx, endpointURL)

	token := jwtforge.CraftExpired(map[string]any{
		"sub": "scanner-probe",
		"iss": "https://probe.invalid",
		"aud": "test",
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	return checks.ExpiredToken(target.Host, endpointURL, baseline, resp.StatusCode)
}

func (s *Scanner) checkCORS(ctx context.Context, target modules.Target, endpointURL string) []finding.Finding {
	acao, acac := s.probeCORSHeaders(ctx, endpointURL)
	return checks.CORSResult(target.Host, endpointURL, attackerOrigin, acao, acac)
}

// probeCORSHeaders sends an OPTIONS preflight with the attacker origin and returns
// the ACAO and ACAC header values. Falls back to GET if OPTIONS yields no ACAO.
func (s *Scanner) probeCORSHeaders(ctx context.Context, endpointURL string) (acao string, acac bool) {
	tryRequest := func(method string) (string, bool) {
		req, err := http.NewRequestWithContext(ctx, method, endpointURL, nil)
		if err != nil {
			return "", false
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		req.Header.Set("Origin", attackerOrigin)
		if method == http.MethodOptions {
			req.Header.Set("Access-Control-Request-Method", "GET")
			req.Header.Set("Access-Control-Request-Headers", "Authorization")
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return "", false
		}
		resp.Body.Close()
		a := resp.Header.Get("Access-Control-Allow-Origin")
		c := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
		return a, c
	}

	acao, acac = tryRequest(http.MethodOptions)
	if acao == "" {
		acao, acac = tryRequest(http.MethodGet)
	}
	return acao, acac
}

func (s *Scanner) checkSessionCookies(ctx context.Context, target modules.Target) []finding.Finding {
	var findings []finding.Finding
	seen := map[string]bool{}
	var probed []string

	for _, path := range authPagePaths {
		u := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		probed = append(probed, fmt.Sprintf("GET %s → HTTP %d (%d cookies)", u, resp.StatusCode, len(resp.Cookies())))
		resp.Body.Close()

		for _, cookie := range resp.Cookies() {
			key := cookie.Name + "@" + path
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, checks.SessionCookieFlags(target.Host, u, cookie)...)
		}
	}

	if len(findings) == 0 && len(probed) > 0 {
		findings = append(findings, checks.NoSessionCookies(target.Host, probed))
	}

	return findings
}

func (s *Scanner) checkCallbackStateParam(ctx context.Context, target modules.Target) []finding.Finding {
	var findings []finding.Finding
	var enforced []string

	for _, path := range callbackPaths {
		u := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if resp.StatusCode == http.StatusBadRequest {
			enforced = append(enforced, fmt.Sprintf("GET %s → HTTP 400 (state parameter required)", u))
			continue
		}

		findings = append(findings, checks.StateParamMissing(target.Host, path, u, resp.StatusCode))
	}

	if len(enforced) > 0 && len(findings) == 0 {
		findings = append(findings, checks.StateEnforced(target.Host, enforced))
	}

	return findings
}

func (s *Scanner) checkOpenRedirect(ctx context.Context, target modules.Target) []finding.Finding {
	var findings []finding.Finding

	for _, path := range callbackPaths {
		probeURL := fmt.Sprintf("%s%s?redirect_uri=%s",
			target.BaseURL(), path, url.QueryEscape(attackerRedirect))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.noRedirectClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			continue
		}

		location := resp.Header.Get("Location")
		if location == "" || !strings.Contains(location, "evil-corp.com") {
			continue
		}

		findings = append(findings, checks.OpenRedirect(target.Host, path, probeURL, location, resp.StatusCode))
	}

	return findings
}
