package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"idenaro/internal/modules"
	"idenaro/internal/modules/free/oidc"
	"idenaro/pkg/httpclient"
)

func TestOIDC_NoDiscovery(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	opts := httpclient.DefaultOptions()
	opts.SkipTLSVerify = true
	scanner := oidc.New(opts)

	target := modules.Target{Host: srv.Listener.Addr().String(), Scheme: "https"}
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on 404, got %d", len(findings))
	}
}

func TestOIDC_RedirectToLoginIsIgnored(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.URL.Path == "/login" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>Login</h1><form><input name=\"username\"><input name=\"password\"></form></body></html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	opts := httpclient.DefaultOptions()
	opts.SkipTLSVerify = true
	scanner := oidc.New(opts)

	target := modules.Target{Host: srv.Listener.Addr().String(), Scheme: "https"}
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when discovery redirects to a safe login page, got %d", len(findings))
	}
}

func TestOIDC_ExposedDiscovery(t *testing.T) {
	discovery := map[string]interface{}{
		"issuer":                           "https://test.example.com",
		"authorization_endpoint":           "https://test.example.com/auth",
		"response_types_supported":         []string{"code", "token"},
		"code_challenge_methods_supported": []string{"S256"},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	opts := httpclient.DefaultOptions()
	opts.SkipTLSVerify = true
	scanner := oidc.New(opts)

	target := modules.Target{Host: srv.Listener.Addr().String(), Scheme: "https"}
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
	titles := map[string]bool{}
	for _, f := range findings {
		titles[f.Title] = true
	}
	if !titles["OIDC Discovery Endpoint publicly exposed"] {
		t.Error("expected 'OIDC Discovery Endpoint publicly exposed' finding")
	}
	if !titles["Implicit Flow enabled (response_type=token)"] {
		t.Error("expected 'Implicit Flow enabled (response_type=token)' finding")
	}
}

func TestOIDC_HTTPAuthEndpoint(t *testing.T) {
	discovery := map[string]interface{}{
		"issuer":                   "https://test.example.com",
		"authorization_endpoint":   "http://test.example.com/auth",
		"response_types_supported": []string{"code"},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	opts := httpclient.DefaultOptions()
	opts.SkipTLSVerify = true
	scanner := oidc.New(opts)

	target := modules.Target{Host: srv.Listener.Addr().String(), Scheme: "https"}
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "authorization_endpoint does not use HTTPS" {
			found = true
		}
	}
	if !found {
		t.Error("expected HTTPS finding for HTTP authorization_endpoint")
	}
}
