package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"idenaro/internal/modules"
	"idenaro/pkg/httpclient"
)

// Config holds every setting needed to run a scan. Build one via DefaultConfig
// and override individual fields before passing it to engine.New.
type Config struct {
	Targets       []modules.Target
	ActiveModules []string      // module names to run; empty slice means all
	Timeout       time.Duration // per-module deadline applied to every HTTP request
	HTTPOptions   httpclient.Options

	OutputFormat string // "json" | "html" | "text"
	OutputFile   string // path to write the report; empty means stdout

	Verbose bool // log per-module progress to stderr

	// OnModuleDone is called after each module completes on a host.
	// The Wails UI wires this to stream live progress events; leave nil for CLI.
	OnModuleDone func(hostName, moduleName string)
}

// FreeModules is the canonical list of modules shipped in the open-source
// free tier. Add free module names here when introducing a new free module.
var FreeModules = []string{
	"oidc", "saml", "headers", "endpoints", "client",
}

// AllModules is an alias for FreeModules kept for CLI compatibility.
// The pro binary extends this list by registering additional modules.
var AllModules = FreeModules

// IdPModules contains the free IdP modules (all free modules scan the IdP;
// the "client" module that scans the relying party is a pro-only feature).
var IdPModules = FreeModules

// DefaultConfig returns a Config with conservative, safe defaults:
// all modules active, 30-second timeout, TLS verification enabled.
func DefaultConfig() Config {
	return Config{
		ActiveModules: AllModules,
		Timeout:       30 * time.Second,
		HTTPOptions:   httpclient.DefaultOptions(),
		OutputFormat:  "text",
	}
}

// ParseTargets converts a slice of raw host strings into typed Target structs.
// Each string may be a bare hostname, hostname:port, or a full https:// URL.
func ParseTargets(rawHosts []string) ([]modules.Target, error) {
	parsedTargets := make([]modules.Target, 0, len(rawHosts))
	for _, rawHost := range rawHosts {
		target, err := parseSingleTarget(rawHost)
		if err != nil {
			return nil, err
		}
		parsedTargets = append(parsedTargets, target)
	}
	return parsedTargets, nil
}

// LoadTargetsFromFile reads one target per line from a file.
// Lines beginning with '#' and blank lines are ignored.
func LoadTargetsFromFile(filePath string) ([]modules.Target, error) {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("config: cannot read targets file %q: %w", filePath, err)
	}

	var rawHosts []string
	for _, line := range strings.Split(string(fileContent), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			rawHosts = append(rawHosts, trimmed)
		}
	}
	return ParseTargets(rawHosts)
}

// ValidateModules returns an error if any name in requestedNames is not
// present in AllModules. Call this before storing module names in Config.
func ValidateModules(requestedNames []string) error {
	knownModules := make(map[string]bool, len(AllModules))
	for _, name := range AllModules {
		knownModules[name] = true
	}
	for _, name := range requestedNames {
		if !knownModules[name] {
			return fmt.Errorf("unknown module %q - available: %s", name, strings.Join(AllModules, ", "))
		}
	}
	return nil
}

// parseSingleTarget parses a raw host string into a typed Target.
// The scheme defaults to "https". A /realms/<name> path segment is
// interpreted as a Keycloak realm. Any other non-root path (e.g.
// /oauth2/auth or /api/me) is preserved in Target.Path and used by
// the client module as the explicit protected endpoint to probe.
func parseSingleTarget(rawInput string) (modules.Target, error) {
	scheme := "https"
	hostPart := rawInput

	switch {
	case strings.HasPrefix(rawInput, "https://"):
		hostPart = strings.TrimPrefix(rawInput, "https://")
	case strings.HasPrefix(rawInput, "http://"):
		scheme = "http"
		hostPart = strings.TrimPrefix(rawInput, "http://")
	}

	realm := ""
	path := ""
	if slashIndex := strings.Index(hostPart, "/"); slashIndex != -1 {
		rawPath := hostPart[slashIndex:]
		if after, ok := strings.CutPrefix(rawPath, "/realms/"); ok {
			// e.g. "/realms/myrealm" or "/realms/myrealm/..."
			name, _, _ := strings.Cut(after, "/")
			if name != "" {
				realm = name
			}
		} else if rawPath != "/" {
			// Any non-root path is kept as a protected-endpoint hint.
			// This lets callers specify e.g. https://app.example.com/oauth2/auth
			// and have the client module use that path directly.
			path = rawPath
		}
		hostPart = hostPart[:slashIndex]
	}

	if hostPart == "" {
		return modules.Target{}, fmt.Errorf("config: empty host in target %q", rawInput)
	}

	return modules.Target{
		Host:   hostPart,
		Port:   0,
		Scheme: scheme,
		Realm:  realm,
		Path:   path,
	}, nil
}
