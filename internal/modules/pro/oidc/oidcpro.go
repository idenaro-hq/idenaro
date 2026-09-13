package oidcpro

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	freeoidc "idenaro/internal/modules/free/oidc"
	"idenaro/internal/modules/pro/oidc/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "oidc-pro"

type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	responseBody, discoveryURL := freeoidc.FetchDiscovery(ctx, s.httpClient, target)
	if discoveryURL == "" {
		return nil, nil
	}

	var disc freeoidc.OIDCDiscovery
	if err := json.Unmarshal(responseBody, &disc); err != nil {
		return nil, nil
	}

	var findings []finding.Finding

	findings = append(findings, checks.PKCE(target.Host, disc.CodeChallengeMethodsSupported)...)
	findings = append(findings, checks.TokenAuth(target.Host, disc.TokenEndpointAuthMethodsSupported)...)
	findings = append(findings, checks.RedirectURIs(target.Host, disc.RedirectURIs)...)
	findings = append(findings, checks.PAR(target.Host, disc.PAREndpoint)...)
	findings = append(findings, checks.Issuer(
		target.Host, target.Host,
		disc.Issuer, disc.AuthorizationEndpoint, disc.TokenEndpoint,
		disc.JWKSUri, disc.UserinfoEndpoint,
	)...)
	findings = append(findings, checks.DiscoveryLeakage(target.Host, discoveryURL, string(responseBody))...)

	if disc.JWKSUri != "" && strings.HasPrefix(disc.JWKSUri, "https://") {
		findings = append(findings, fetchAndCheckJWKS(ctx, s.httpClient, disc.JWKSUri, target.Host)...)
	}

	return findings, nil
}

func fetchAndCheckJWKS(ctx context.Context, client *http.Client, jwksURL, host string) []finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	var raw struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	keys := make([]checks.JWKSKey, len(raw.Keys))
	for i, k := range raw.Keys {
		keys[i] = checks.JWKSKey{Kid: k.Kid, Kty: k.Kty, N: k.N}
	}

	return checks.JWKS(host, jwksURL, keys)
}
