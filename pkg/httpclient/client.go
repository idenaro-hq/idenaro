package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"
)

const (
	DefaultTimeout   = 15 * time.Second
	DefaultUserAgent = "Apache-HttpClient/1.0"
)

// Options configures the shared HTTP client used by all scanner modules.
type Options struct {
	Timeout         time.Duration
	SkipTLSVerify   bool
	FollowRedirects bool
	UserAgent       string
}

// DefaultOptions returns safe, conservative client settings suitable for
// scanning without credential input.
func DefaultOptions() Options {
	return Options{
		Timeout:         DefaultTimeout,
		SkipTLSVerify:   false,
		FollowRedirects: true,
		UserAgent:       DefaultUserAgent,
	}
}

// New builds an http.Client from the given options. All scanner modules must
// call this rather than constructing http.Client directly, so timeout and TLS
// policy are applied consistently.
func New(opts Options) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.SkipTLSVerify, //nolint:gosec // intentional for audit mode
	}

	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		DisableKeepAlives: true, // prevent connection reuse between modules
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}

	if !opts.FollowRedirects {
		httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return httpClient
}

// Get sends a GET request with the scanner User-Agent and broad Accept header.
// All modules should use this instead of http.Get so every request is
// identifiable as an audit tool in server logs.
func Get(httpClient *http.Client, targetURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("Accept", "application/json, text/html, */*")
	return httpClient.Do(req)
}
