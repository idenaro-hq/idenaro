package endpoints_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"idenaro/internal/modules"
	"idenaro/internal/modules/free/endpoints"
	"idenaro/pkg/httpclient"
)

func newEndpointsScanner() modules.Module {
	opts := httpclient.DefaultOptions()
	opts.SkipTLSVerify = true
	return endpoints.New(opts)
}

func TestEndpoints_NoExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	target := modules.Target{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http"}
	scanner := newEndpointsScanner()
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when all endpoints return 404, got %d", len(findings))
	}
}

func TestEndpoints_AdminExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	target := modules.Target{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http"}
	scanner := newEndpointsScanner()
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Admin") {
			found = true
			if f.Severity != "HIGH" {
				t.Errorf("admin exposure should be HIGH, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected admin panel finding")
	}
}

func TestEndpoints_AdminRedirectsToLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	target := modules.Target{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http"}
	scanner := newEndpointsScanner()
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, "Admin") {
			t.Fatalf("expected no admin finding for safe redirect, got severity %s", f.Severity)
		}
	}
}

func TestEndpoints_AdminRedirectsToOtherHostSamePath(t *testing.T) {
	loginSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer loginSrv.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			http.Redirect(w, r, loginSrv.URL+"/admin", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	target := modules.Target{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http"}
	scanner := newEndpointsScanner()
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, "Admin") {
			if f.Severity != "INFO" {
				t.Errorf("admin finding after cross-host redirect should be downgraded to INFO, got %s", f.Severity)
			}
			if f.Confidence != "LOW" {
				t.Errorf("admin finding after redirect should have LOW confidence, got %s", f.Confidence)
			}
			return
		}
	}
	t.Error("expected an INFO-level admin finding for cross-host redirect, got none")
}

func TestEndpoints_NonCriticalRedirectToRandomPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			http.Redirect(w, r, "/home", http.StatusFound)
			return
		}
		if r.URL.Path == "/home" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Welcome home</body></html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	target := modules.Target{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http"}
	scanner := newEndpointsScanner()
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, "Admin") {
			if f.Severity != "INFO" {
				t.Errorf("redirected non-critical probe should be INFO, got %s", f.Severity)
			}
			if f.Confidence != "LOW" {
				t.Errorf("redirected non-critical probe should have LOW confidence, got %s", f.Confidence)
			}
			return
		}
	}
	t.Error("expected an INFO-level admin finding for redirect to random page, got none")
}

func TestEndpoints_CriticalRedirectStaysCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			http.Redirect(w, r, "/home", http.StatusFound)
			return
		}
		if r.URL.Path == "/home" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("DB_PASSWORD=secret123\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	target := modules.Target{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http"}
	scanner := newEndpointsScanner()
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, ".env") {
			if f.Severity != "CRITICAL" {
				t.Errorf("critical probe should stay CRITICAL even after redirect, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("expected a CRITICAL .env finding even after redirect, got none")
}

func TestEndpoints_EnvFileExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("DB_PASSWORD=secret123\nAPI_KEY=abc\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	target := modules.Target{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http"}
	scanner := newEndpointsScanner()
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, ".env") {
			found = true
			if f.Severity != "CRITICAL" {
				t.Errorf(".env exposure should be CRITICAL, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected .env file finding")
	}
}
