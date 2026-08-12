package headers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"idenaro/internal/modules"
	"idenaro/internal/modules/free/headers"
	"idenaro/pkg/httpclient"
)

func TestHeaders_AllMissing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := httpclient.DefaultOptions()
	opts.SkipTLSVerify = true
	scanner := headers.New(opts)

	target := modules.Target{Host: srv.Listener.Addr().String(), Scheme: "https"}
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should find at least HSTS, CSP, X-Frame-Options, X-Content-Type-Options
	if len(findings) < 4 {
		t.Errorf("expected at least 4 header findings, got %d", len(findings))
	}
}

func TestHeaders_HSTSPresent(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := httpclient.DefaultOptions()
	opts.SkipTLSVerify = true
	scanner := headers.New(opts)

	target := modules.Target{Host: srv.Listener.Addr().String(), Scheme: "https"}
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Title == "Missing Strict-Transport-Security (HSTS) header" {
			t.Error("should not find HSTS missing when header is present")
		}
	}
}

func TestHeaders_InformationLeakage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.51 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := httpclient.DefaultOptions()
	opts.SkipTLSVerify = true
	scanner := headers.New(opts)

	target := modules.Target{Host: srv.Listener.Addr().String(), Scheme: "https"}
	findings, err := scanner.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	serverLeak, poweredByLeak := false, false
	for _, f := range findings {
		if f.Title == `Information disclosure via "Server" header` {
			serverLeak = true
		}
		if f.Title == `Information disclosure via "X-Powered-By" header` {
			poweredByLeak = true
		}
	}
	if !serverLeak {
		t.Error("expected Server header information disclosure finding")
	}
	if !poweredByLeak {
		t.Error("expected X-Powered-By information disclosure finding")
	}
}
