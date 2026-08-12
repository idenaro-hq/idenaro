package modules

import (
	"context"
	"fmt"

	"idenaro/internal/finding"
)

// Module is the interface every scanner module must implement.
// The engine calls Run for each target and aggregates the returned findings.
// A module must never return an error for network failures - unreachable
// targets should produce zero findings and a nil error.
type Module interface {
	// Name returns the short, lowercase identifier used in config and reports.
	Name() string

	// Run executes all checks for this module against the given target.
	// The context carries a per-module deadline; honour it on every request.
	Run(ctx context.Context, target Target) ([]finding.Finding, error)
}

// Target holds the parsed address of a single scan target.
type Target struct {
	Host      string // hostname or hostname:port, e.g. "auth.example.com"
	Port      int    // 0 means use the scheme default (443 for https, 80 for http)
	Scheme    string // "https" or "http"
	Realm     string // Keycloak realm; empty means use the default ("master")
	Path      string // deprecated path hint kept for internal parse use; prefer ClientApp
	ClientApp string // optional client application URL, e.g. "https://app.example.com";
	                 // only the client and client-pro modules read this - all other modules ignore it
}

// RealmOrDefault returns the configured Keycloak realm, falling back to "master".
func (t Target) RealmOrDefault() string {
	if t.Realm != "" {
		return t.Realm
	}
	return "master"
}

// BaseURL returns the full origin URL for the target.
// The port is omitted when it matches the scheme default.
func (t Target) BaseURL() string {
	if t.Port == 0 || t.Port == 443 {
		return t.Scheme + "://" + t.Host
	}
	return fmt.Sprintf("%s://%s:%d", t.Scheme, t.Host, t.Port)
}
