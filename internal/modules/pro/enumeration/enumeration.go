package enumeration

import (
	"context"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/enumeration/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "enumeration"

var passwordResetPaths = []struct {
	path string
	name string
}{
	{"/forgot-password", "forgot password"},
	{"/forgot_password", "forgot password"},
	{"/reset-password", "password reset"},
	{"/reset_password", "password reset"},
	{"/password/reset", "password reset"},
	{"/auth/forgot-password", "auth forgot password"},
	{"/account/forgot-password", "account forgot password"},
	{"/users/password/new", "Rails password reset"},
	{"/realms/master/login-actions/reset-credentials", "Keycloak reset"},
}

var userSearchPaths = []struct {
	path string
	name string
}{
	{"/api/v1/users", "users API"},
	{"/api/users", "users API"},
	{"/users", "users endpoint"},
	{"/api/v1/user/search", "user search API"},
	{"/api/user/autocomplete", "user autocomplete"},
	{"/api/v1/people", "people API"},
	{"/scim/v2/Users", "SCIM users"},
	{"/admin/users", "admin users"},
	{"/realms/master/users", "Keycloak users"},
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

	realm := target.RealmOrDefault()

	// 1. Check password reset pages
	for _, pr := range passwordResetPaths {
		endpointURL := target.BaseURL() + strings.ReplaceAll(pr.path, "/realms/master/", "/realms/"+realm+"/")
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
		if err != nil || resp.StatusCode == http.StatusNotFound {
			continue
		}

		findings = append(findings, checks.PasswordResetAccessible(target.Host, endpointURL, pr.name, resp.StatusCode))
		findings = append(findings, checks.PasswordResetEnum(target.Host, endpointURL, string(responseBody))...)
	}

	// 2. Probe login page for enumeration indicators
	loginURL := target.BaseURL() + "/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		if resp, err := s.httpClient.Do(req); err == nil {
			responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			_ = resp.Body.Close()
			findings = append(findings, checks.LoginPageEnum(target.Host, loginURL, string(responseBody))...)
		}
	}

	// 3. Probe user-listing API endpoints
	for _, up := range userSearchPaths {
		endpointURL := target.BaseURL() + strings.ReplaceAll(up.path, "/realms/master/", "/realms/"+realm+"/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		req.Header.Set("Accept", "application/json")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode == http.StatusNotFound {
			continue
		}

		ct := resp.Header.Get("Content-Type")
		finalURL := httpclient.EffectiveFinalURL(resp, responseBody)
		if httpclient.RedirectLooksSafe(req.URL, finalURL, ct, responseBody) {
			continue
		}
		redirected := httpclient.Redirected(req.URL, finalURL)

		findings = append(findings, checks.UserSearch(
			target.Host, endpointURL, up.name,
			string(responseBody), ct,
			resp.StatusCode, redirected,
		)...)
	}

	return findings, nil
}
