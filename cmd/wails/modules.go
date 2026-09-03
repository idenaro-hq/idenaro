package main

import (
	"sort"

	"idenaro/internal/config"
	"idenaro/internal/finding"
	"idenaro/internal/modules"
	freeclient "idenaro/internal/modules/free/client"
	"idenaro/internal/modules/free/endpoints"
	"idenaro/internal/modules/free/headers"
	"idenaro/internal/modules/free/oidc"
	"idenaro/internal/modules/free/saml"
	proclient "idenaro/internal/modules/pro/client"
	"idenaro/internal/modules/pro/cookies"
	"idenaro/internal/modules/pro/cors"
	"idenaro/internal/modules/pro/csp"
	"idenaro/internal/modules/pro/enumeration"
	"idenaro/internal/modules/pro/lifecycle"
	"idenaro/internal/modules/pro/mfa"
	oidcpro "idenaro/internal/modules/pro/oidc"
	"idenaro/internal/modules/pro/products"
	"idenaro/internal/modules/pro/redirects"
	samlpro "idenaro/internal/modules/pro/saml"
	"idenaro/internal/modules/pro/scim"
	"idenaro/internal/modules/pro/tls"
	"idenaro/internal/modules/pro/tokens"
	"idenaro/internal/nis2"
	"idenaro/internal/scoring"
	"idenaro/pkg/httpclient"
)

// idPModuleNames lists all IdP module names shown in the UI module grid.
// "client"/"client-pro" are excluded here because they have their own target
// field in the UI.
var idPModuleNames = []string{
	"oidc-pro", "saml-pro", "tls", "cookies", "cors", "csp",
	"redirects", "tokens", "mfa", "lifecycle", "scim", "products", "enumeration",
}

// allModules returns every module shipped in this open-source build.
func allModules(opts httpclient.Options) []modules.Module {
	return []modules.Module{
		oidc.New(opts),
		saml.New(opts),
		headers.New(opts),
		endpoints.New(opts),
		oidcpro.New(opts),
		samlpro.New(opts),
		tls.New(opts),
		cookies.New(opts),
		cors.New(opts),
		csp.New(opts),
		redirects.New(opts),
		tokens.New(opts),
		mfa.New(opts),
		lifecycle.New(opts),
		scim.New(opts),
		products.New(opts),
		enumeration.New(opts),
	}
}

// postProcess runs the full pipeline after all modules complete: score
// individual findings, apply chain-finding rules, map NIS2 articles, then
// sort by severity.
func postProcess(findings []finding.Finding) []finding.Finding {
	findings = scoring.ScoreAll(findings)
	findings = scoring.ApplyChaining(findings)
	for i := range findings {
		findings[i].NIS2Articles = nis2.Lookup(findings[i].Tags)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return finding.SeverityOrder[findings[i].Severity] > finding.SeverityOrder[findings[j].Severity]
	})
	return findings
}

// newFreeClient instantiates the free-tier client module.
func newFreeClient(opts httpclient.Options) modules.Module { return freeclient.New(opts) }

// newProClient instantiates the pro-tier client module (superset of free checks).
func newProClient(opts httpclient.Options) modules.Module { return proclient.New(opts) }

// GetModules returns the IdP module names for the module selector in the UI.
func (a *App) GetModules() []string {
	return append(append([]string{}, config.IdPModules...), idPModuleNames...)
}
