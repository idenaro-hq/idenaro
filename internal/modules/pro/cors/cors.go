package cors

import (
	"context"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/cors/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "cors"

type authSensitiveEndpoint struct {
	path        string
	description string
}

var authEndpointsToProbe = []authSensitiveEndpoint{
	{"/api/auth", "auth API"},
	{"/api/login", "login API"},
	{"/api/user", "user API"},
	{"/api/me", "user profile API"},
	{"/api/token", "token API"},
	{"/oauth/token", "OAuth token endpoint"},
	{"/connect/token", "connect token endpoint"},
	{"/realms/master/protocol/openid-connect/token", "Keycloak token endpoint"},
	{"/userinfo", "OIDC userinfo endpoint"},
	{"/api/v1/users", "users API"},
	{"/api/admin", "admin API"},
	{"/api/session", "session API"},
}

var attackerControlledOrigins = []string{
	"https://evil.com",
	"https://attacker.example.com",
	"null",
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
	for _, endpoint := range authEndpointsToProbe {
		endpointURL := target.BaseURL() + strings.ReplaceAll(endpoint.path, "/realms/master/", "/realms/"+realm+"/")

		for _, injectedOrigin := range attackerControlledOrigins {
			corsFindings := s.probeEndpointCORS(ctx, target.Host, endpointURL, endpoint.description, injectedOrigin)
			if len(corsFindings) > 0 {
				findings = append(findings, corsFindings...)
				break
			}
		}
	}

	if len(findings) == 0 {
		probedPaths := make([]string, 0, len(authEndpointsToProbe))
		for _, ep := range authEndpointsToProbe {
			probedPaths = append(probedPaths, ep.path)
		}
		f := finding.NewFinding(moduleName, target.Host,
			"No permissive CORS policy detected on auth endpoints",
			"Preflight requests with attacker-controlled origins (evil.com, attacker.example.com, null) "+
				"were sent to common auth and API endpoints. None responded with a permissive "+
				"Access-Control-Allow-Origin header. Cross-origin token extraction is not possible "+
				"via these endpoints.",
			finding.Info,
		)
		f.ID = "cors-restricted-ok"
		f.Evidence = []string{"Probed: " + strings.Join(probedPaths, ", ")}
		f.Confidence = "MEDIUM"
		f.Tags = []string{"cors", "iam"}
		findings = append(findings, f)
	}

	return findings, nil
}

func (s *Scanner) probeEndpointCORS(
	ctx context.Context,
	hostName, endpointURL, endpointDescription, injectedOrigin string,
) []finding.Finding {
	resp, err := s.sendPreflightRequest(ctx, endpointURL, injectedOrigin)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	allowedOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")

	if allowedOrigin == "" {
		return nil
	}

	if allowedOrigin == "*" {
		return []finding.Finding{checks.Wildcard(hostName, endpointURL, endpointDescription)}
	}

	if allowedOrigin == injectedOrigin && injectedOrigin != "null" {
		return []finding.Finding{checks.ReflectedOrigin(hostName, endpointURL, endpointDescription, injectedOrigin, allowedOrigin, allowCredentials)}
	}

	if injectedOrigin == "null" && allowedOrigin == "null" && strings.EqualFold(allowCredentials, "true") {
		return []finding.Finding{checks.NullOrigin(hostName, endpointURL, endpointDescription)}
	}

	return nil
}

func (s *Scanner) sendPreflightRequest(ctx context.Context, endpointURL, origin string) (*http.Response, error) {
	preflightReq, err := http.NewRequestWithContext(ctx, http.MethodOptions, endpointURL, nil)
	if err != nil {
		return nil, err
	}
	preflightReq.Header.Set("User-Agent", httpclient.DefaultUserAgent)
	preflightReq.Header.Set("Origin", origin)
	preflightReq.Header.Set("Access-Control-Request-Method", "POST")
	preflightReq.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")

	resp, err := s.httpClient.Do(preflightReq)
	if err == nil {
		return resp, nil
	}

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return nil, err
	}
	getReq.Header.Set("User-Agent", httpclient.DefaultUserAgent)
	getReq.Header.Set("Origin", origin)
	return s.httpClient.Do(getReq)
}
