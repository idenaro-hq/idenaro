package tokens

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/pro/tokens/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "tokens"

var pagesWithJS = []string{"/", "/login", "/signin", "/auth", "/app", "/dashboard"}

type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding
	seenPatterns := map[string]bool{}

	var jsSources []string
	var inlineJS []string

	for _, path := range pagesWithJS {
		pageURL := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyStr := string(responseBody)

		scriptSrcRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
		for _, m := range scriptSrcRe.FindAllStringSubmatch(bodyStr, -1) {
			if len(m) > 1 {
				src := m[1]
				switch {
				case strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://"):
					jsSources = append(jsSources, src)
				case strings.HasPrefix(src, "/"):
					jsSources = append(jsSources, target.BaseURL()+src)
				default:
					jsSources = append(jsSources, target.BaseURL()+"/"+src)
				}
			}
		}

		inlineRe := regexp.MustCompile(`(?is)<script([^>]*)>(.*?)</script>`)
		for _, m := range inlineRe.FindAllStringSubmatch(bodyStr, -1) {
			if len(m) > 2 && !strings.Contains(strings.ToLower(m[1]), "src=") {
				if content := strings.TrimSpace(m[2]); content != "" {
					inlineJS = append(inlineJS, content)
				}
			}
		}
	}

	for _, jsContent := range inlineJS {
		findings = append(findings, checks.ScanContent(jsContent, "inline script", target.Host, seenPatterns)...)
	}

	fetched := 0
	for _, jsURL := range checks.Dedup(jsSources) {
		if fetched >= 10 {
			break
		}
		if !strings.Contains(jsURL, target.Host) {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if err != nil {
			continue
		}
		fetched++

		findings = append(findings, checks.ScanContent(string(responseBody), jsURL, target.Host, seenPatterns)...)
	}

	return findings, nil
}
