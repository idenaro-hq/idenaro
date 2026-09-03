package tls

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	tlschecks "idenaro/internal/modules/pro/tls/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "tls"

type Scanner struct {
	insecureClient *http.Client
	httpClient     *http.Client
	noFollowClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	insecureOpts := opts
	insecureOpts.SkipTLSVerify = true

	noFollowOpts := opts
	noFollowOpts.SkipTLSVerify = true
	noFollowOpts.FollowRedirects = false

	return &Scanner{
		insecureClient: httpclient.New(insecureOpts),
		httpClient:     httpclient.New(opts),
		noFollowClient: httpclient.New(noFollowOpts),
	}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding

	if target.Scheme != "https" {
		return findings, nil
	}

	host := target.Host
	port := "443"
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}
	tlsAddr := host + ":" + port

	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional for audit
			ServerName:         host,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", tlsAddr)
	if err != nil {
		return findings, nil
	}
	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	conn.Close()

	if len(state.PeerCertificates) == 0 {
		return findings, nil
	}

	findings = append(findings, tlschecks.Certificate(target.Host, state.PeerCertificates[0], state.PeerCertificates)...)
	findings = append(findings, tlschecks.Version(target.Host, state.Version)...)
	findings = append(findings, tlschecks.WeakCipher(target.Host, state.CipherSuite)...)
	findings = append(findings, tlschecks.LegacyVersionAccepted(ctx, target.Host, tlsAddr, host)...)

	httpURL := "http://" + target.Host + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		if resp, err := s.noFollowClient.Do(req); err == nil {
			resp.Body.Close()
			findings = append(findings, tlschecks.HTTPRedirect(
				target.Host, httpURL,
				resp.StatusCode,
				resp.Header.Get("Location"),
			)...)
		}
	}

	httpsURL := target.BaseURL() + "/"
	fallbackReq, err := http.NewRequestWithContext(ctx, http.MethodGet, httpsURL, nil)
	if err == nil {
		fallbackReq.Header.Set("User-Agent", httpclient.DefaultUserAgent)
		if fallbackResp, err := s.insecureClient.Do(fallbackReq); err == nil {
			responseBody, _ := io.ReadAll(io.LimitReader(fallbackResp.Body, 512*1024))
			fallbackResp.Body.Close()
			findings = append(findings, tlschecks.MixedContent(
				target.Host, httpsURL,
				strings.ToLower(string(responseBody)),
			)...)
		}
	}

	return findings, nil
}
