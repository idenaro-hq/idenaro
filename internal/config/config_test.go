package config_test

import (
	"os"
	"testing"

	"idenaro/internal/config"
)

func TestParseTargets_Basic(t *testing.T) {
	targets, err := config.ParseTargets([]string{"auth.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Host != "auth.example.com" {
		t.Errorf("expected host auth.example.com, got %s", targets[0].Host)
	}
	if targets[0].Scheme != "https" {
		t.Errorf("expected scheme https, got %s", targets[0].Scheme)
	}
}

func TestParseTargets_WithScheme(t *testing.T) {
	cases := []struct {
		input  string
		scheme string
		host   string
	}{
		{"https://auth.example.com", "https", "auth.example.com"},
		{"http://auth.example.com", "http", "auth.example.com"},
		{"https://auth.example.com/path/to/page", "https", "auth.example.com"},
	}
	for _, c := range cases {
		targets, err := config.ParseTargets([]string{c.input})
		if err != nil {
			t.Fatalf("input %q: unexpected error: %v", c.input, err)
		}
		if targets[0].Scheme != c.scheme {
			t.Errorf("input %q: expected scheme %s, got %s", c.input, c.scheme, targets[0].Scheme)
		}
		if targets[0].Host != c.host {
			t.Errorf("input %q: expected host %s, got %s", c.input, c.host, targets[0].Host)
		}
	}
}

func TestParseTargets_RealmFromURL(t *testing.T) {
	cases := []struct {
		input string
		host  string
		realm string
	}{
		{"https://auth.example.com/realms/myrealm", "auth.example.com", "myrealm"},
		{"https://auth.example.com/realms/master", "auth.example.com", "master"},
		{"https://auth.example.com/realms/corp/extra", "auth.example.com", "corp"},
		{"auth.example.com", "auth.example.com", ""},
		{"https://auth.example.com/other/path", "auth.example.com", ""},
	}
	for _, c := range cases {
		targets, err := config.ParseTargets([]string{c.input})
		if err != nil {
			t.Fatalf("input %q: unexpected error: %v", c.input, err)
		}
		if targets[0].Host != c.host {
			t.Errorf("input %q: expected host %s, got %s", c.input, c.host, targets[0].Host)
		}
		if targets[0].Realm != c.realm {
			t.Errorf("input %q: expected realm %q, got %q", c.input, c.realm, targets[0].Realm)
		}
	}
}

func TestParseTargets_Empty(t *testing.T) {
	_, err := config.ParseTargets([]string{""})
	if err == nil {
		t.Error("expected error for empty host")
	}
}

func TestValidateModules_Known(t *testing.T) {
	err := config.ValidateModules([]string{"oidc", "saml", "headers"})
	if err != nil {
		t.Errorf("unexpected error for known modules: %v", err)
	}
}

func TestValidateModules_Unknown(t *testing.T) {
	err := config.ValidateModules([]string{"oidc", "unknown-module"})
	if err == nil {
		t.Error("expected error for unknown module name")
	}
}

func TestLoadTargetsFromFile(t *testing.T) {
	f, err := os.CreateTemp("", "targets-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	_, err = f.WriteString("auth.example.com\n# comment\nsso.example.com\n\n")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	targets, err := config.LoadTargetsFromFile(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Errorf("expected 2 targets (skipping comment and blank line), got %d", len(targets))
	}
}
