package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/free/oidc/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "oidc"

// OIDCDiscovery represents the /.well-known/openid-configuration response.
// Exported so pro/oidc can reuse the type without re-defining it.
type OIDCDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSUri                           string   `json:"jwks_uri"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
	RedirectURIs                      []string `json:"redirect_uris,omitempty"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	PAREndpoint                       string   `json:"pushed_authorization_request_endpoint"`
}

// DiscoveryPaths is the ordered list of well-known OIDC discovery paths probed
// during a scan. Exported so pro/oidc can reuse the same probe sequence.
var DiscoveryPaths = []string{
	"/.well-known/openid-configuration",
	"/realms/master/.well-known/openid-configuration",
	"/adfs/.well-known/openid-configuration",
	"/oauth2/default/.well-known/oauth-authorization-server",
	"/v2.0/.well-known/openid-configuration",
	"/dex/.well-known/openid-configuration",
	"/application/o/default/.well-known/openid-configuration",
}

type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	body, discoveryURL := FetchDiscovery(ctx, s.httpClient, target)
	if discoveryURL == "" {
		return nil, nil
	}

	findings := []finding.Finding{checks.DiscoveryExposed(target.Host, discoveryURL)}

	var disc OIDCDiscovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return findings, nil
	}

	findings = append(findings, checks.ResponseTypes(target.Host, disc.ResponseTypesSupported)...)
	findings = append(findings, checks.GrantTypes(target.Host, disc.GrantTypesSupported)...)
	findings = append(findings, checks.ResponseModes(target.Host, disc.ResponseModesSupported)...)
	findings = append(findings, checks.SigningAlgorithms(target.Host, disc.IDTokenSigningAlgValuesSupported)...)
	findings = append(findings, checks.PKCE(target.Host, disc.CodeChallengeMethodsSupported)...)
	findings = append(findings, checks.EndpointHTTPS(
		target.Host,
		disc.AuthorizationEndpoint, disc.TokenEndpoint,
		disc.JWKSUri, disc.UserinfoEndpoint,
		disc.Issuer,
	)...)

	return findings, nil
}

// ── Exported helpers (reused by pro/oidc) ─────────────────────────────────────

// FetchDiscovery probes all known discovery paths and returns the raw response
// body and the URL that succeeded, or (nil, "") if none responded.
func FetchDiscovery(ctx context.Context, client *http.Client, target modules.Target) ([]byte, string) {
	realm := target.RealmOrDefault()
	for _, path := range DiscoveryPaths {
		path = strings.ReplaceAll(path, "/realms/master/", "/realms/"+realm+"/")
		pageURL := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if err != nil || len(body) == 0 {
			continue
		}
		if httpclient.RedirectLooksSafe(req.URL, httpclient.EffectiveFinalURL(resp, body), resp.Header.Get("Content-Type"), body) {
			continue
		}
		return body, pageURL
	}
	return nil, ""
}

// ContainsStr reports whether slice contains target (case-insensitive).
// Exported so pro/oidc can reuse it.
func ContainsStr(slice []string, target string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}
