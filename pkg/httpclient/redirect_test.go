package httpclient

import (
	"net/http"
	"net/url"
	"testing"
)

func TestRedirectLooksSafe(t *testing.T) {
	requested, _ := url.Parse("https://example.com/admin")
	final, _ := url.Parse("https://example.com/login")
	body := []byte("<html><body><h1>Login</h1><form><input name=\"username\"><input name=\"password\"></form></body></html>")

	if !RedirectLooksSafe(requested, final, "text/html", body) {
		t.Fatal("expected redirect to login page to be treated as safe")
	}
}

func TestRedirectLooksUnsafeWhenNotLoginPage(t *testing.T) {
	requested, _ := url.Parse("https://example.com/admin")
	final, _ := url.Parse("https://example.com/dashboard")

	if RedirectLooksSafe(requested, final, "text/html", []byte("<html><body>Welcome</body></html>")) {
		t.Fatal("expected redirect to non-login page to remain unsafe")
	}
}

func makeResp(base string, refreshHeader string) *http.Response {
	u, _ := url.Parse(base)
	h := http.Header{}
	if refreshHeader != "" {
		h.Set("Refresh", refreshHeader)
	}
	return &http.Response{
		Header:  h,
		Request: &http.Request{URL: u},
	}
}

func TestEffectiveFinalURL_RefreshHeader(t *testing.T) {
	resp := makeResp("https://example.com/admin", "0; url=/login")
	got := EffectiveFinalURL(resp, nil)
	if got.Path != "/login" {
		t.Fatalf("expected /login, got %s", got.Path)
	}
}

func TestEffectiveFinalURL_RefreshHeaderAbsolute(t *testing.T) {
	resp := makeResp("https://example.com/admin", `0; url="https://example.com/sso/login"`)
	got := EffectiveFinalURL(resp, nil)
	if got.Path != "/sso/login" {
		t.Fatalf("expected /sso/login, got %s", got.Path)
	}
}

func TestEffectiveFinalURL_MetaRefresh(t *testing.T) {
	body := []byte(`<html><head><meta http-equiv="refresh" content="0; url=/login"></head></html>`)
	resp := makeResp("https://example.com/admin", "")
	got := EffectiveFinalURL(resp, body)
	if got.Path != "/login" {
		t.Fatalf("expected /login, got %s", got.Path)
	}
}

func TestEffectiveFinalURL_MetaRefreshReverseAttrOrder(t *testing.T) {
	body := []byte(`<html><head><meta content="0;url=/signin" http-equiv="refresh"/></head></html>`)
	resp := makeResp("https://example.com/admin", "")
	got := EffectiveFinalURL(resp, body)
	if got.Path != "/signin" {
		t.Fatalf("expected /signin, got %s", got.Path)
	}
}

func TestEffectiveFinalURL_NoRedirect(t *testing.T) {
	resp := makeResp("https://example.com/admin", "")
	got := EffectiveFinalURL(resp, []byte("<html><body>Admin</body></html>"))
	if got.String() != "https://example.com/admin" {
		t.Fatalf("expected original URL, got %s", got.String())
	}
}
