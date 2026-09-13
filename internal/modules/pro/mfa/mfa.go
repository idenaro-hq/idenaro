package mfa

import (
	"context"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/mfa/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "mfa"

var loginPaths = []string{
	"/login", "/signin", "/auth", "/auth/login",
	"/account/login", "/user/login", "/api/auth",
}

type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding
	var det checks.MFADetection
	var loginPageFound string

	// Phase 1: Login page analysis
	for _, path := range loginPaths {
		pageURL := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		req.Header.Set("Accept", "text/html,*/*")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}

		for _, headerName := range []string{"x-mfa-required", "x-2fa-required", "www-authenticate"} {
			if v := resp.Header.Get(headerName); v != "" && strings.Contains(strings.ToLower(v), "totp") {
				det.Found = true
			}
		}

		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode == http.StatusNotFound {
			continue
		}

		loginPageFound = pageURL
		weakFindings, pageDet := checks.LoginPage(target.Host, pageURL, string(responseBody))
		findings = append(findings, weakFindings...)
		if pageDet.Found {
			det.Found = true
		}
		if pageDet.StrengthLevel > det.StrengthLevel {
			det.StrengthLevel = pageDet.StrengthLevel
			det.StrengthLabel = pageDet.StrengthLabel
		}
		if pageDet.StepUpFound {
			det.StepUpFound = true
		}
		break
	}

	// Phase 2: MFA API endpoint presence
	for _, path := range checks.MFAEndpointPaths {
		pageURL := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if httpclient.RedirectLooksSafe(req.URL, httpclient.EffectiveFinalURL(resp, nil), resp.Header.Get("Content-Type"), nil) {
			continue
		}
		if resp.StatusCode == http.StatusOK ||
			resp.StatusCode == http.StatusMethodNotAllowed ||
			resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden {
			det.Found = true
			break
		}
	}

	// Phase 3: Synthesize
	if loginPageFound == "" {
		return findings, nil
	}
	findings = append(findings, checks.Synthesize(target.Host, loginPageFound, det)...)

	// Phase 4: Bypass endpoint probing
	for _, path := range checks.MFABypassPaths {
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
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		finalURL := httpclient.EffectiveFinalURL(resp, respBody)
		if httpclient.RedirectLooksSafe(req.URL, finalURL, resp.Header.Get("Content-Type"), respBody) {
			continue
		}
		if httpclient.Redirected(req.URL, finalURL) {
			continue
		}
		if resp.StatusCode == http.StatusOK {
			findings = append(findings, checks.BypassFound(target.Host, pageURL))
		}
	}

	return findings, nil
}
