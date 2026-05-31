// Package bypass403 tests 401/403 access control bypass techniques.
// Covers header spoofing, path normalization tricks, HTTP method switching,
// and X-Original-URL / X-Rewrite-URL header-based routing bypasses.
package bypass403

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

type bypass struct {
	technique string
	apply     func(req *http.Request, rawURL string, u *url.URL)
}

var headerBypasses = []bypass{
	{"X-Original-URL", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-Original-URL", u.RequestURI())
	}},
	{"X-Rewrite-URL", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-Rewrite-URL", u.RequestURI())
	}},
	{"X-Custom-IP-Authorization: 127.0.0.1", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-Custom-IP-Authorization", "127.0.0.1")
	}},
	{"X-Forwarded-For: 127.0.0.1", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
	}},
	{"X-Forwarded-For: localhost", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-Forwarded-For", "localhost")
	}},
	{"X-Remote-IP: 127.0.0.1", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-Remote-IP", "127.0.0.1")
	}},
	{"X-Client-IP: 127.0.0.1", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-Client-IP", "127.0.0.1")
	}},
	{"X-ProxyUser-Ip: 127.0.0.1", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-ProxyUser-Ip", "127.0.0.1")
	}},
	{"X-Original-URL: /", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-Original-URL", "/")
		req.URL.Path = u.Path
	}},
	{"X-Forwarded-Host: localhost", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("X-Forwarded-Host", "localhost")
	}},
	{"Content-Length: 0", func(req *http.Request, rawURL string, u *url.URL) {
		req.Header.Set("Content-Length", "0")
		req.Method = http.MethodPost
	}},
}

// pathVariants builds URL variations that may bypass path-based access controls
func pathVariants(u *url.URL) []string {
	p := u.Path
	base := u.Scheme + "://" + u.Host

	variants := []string{
		base + p + "/.",
		base + p + "/",
		base + "//" + strings.TrimPrefix(p, "/"),
		base + p + "/..",
		base + strings.ToUpper(p),
		base + strings.ToLower(p),
	}

	// URL-encode first character of path
	if len(p) > 1 {
		encoded := fmt.Sprintf("/%c%s", p[1], p[2:])
		// Try %2f-based bypasses
		variants = append(variants,
			base+"/"+url.PathEscape(strings.TrimPrefix(p, "/")),
			base+strings.Replace(p, "/", "/%2f", 1),
			base+p+"%20",
			base+p+"%09",
			base+p+"#",
		)
		_ = encoded
	}

	// Add path prefix tricks
	variants = append(variants,
		base+"/;"+strings.TrimPrefix(p, "/"),
		base+"/."+p,
		base+"/..;/"+strings.TrimPrefix(p, "/"),
		base+p+";.json",
		base+p+"/.json",
	)

	return variants
}

type Module struct {
	client    *client.Client
	seenPaths sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "bypass403" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	// Only test paths that actually return 403 or 401
	if page.StatusCode != 403 && page.StatusCode != 401 {
		return nil, nil
	}

	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}

	key := u.Host + "|" + u.Path
	if _, loaded := m.seenPaths.LoadOrStore(key, struct{}{}); loaded {
		return nil, nil
	}

	var findings []modules.Finding

	// Phase 1: Header-based bypasses
	for _, bp := range headerBypasses {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, page.URL, nil)
		if err != nil {
			continue
		}
		bp.apply(req, page.URL, u)
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)

		if isBypass(resp.StatusCode, page.StatusCode, body) {
			findings = append(findings, modules.Finding{
				Module:  "bypass403",
				Severity: modules.High,
				URL:     page.URL,
				Param:   "HTTP header",
				Payload: bp.technique,
				Evidence: fmt.Sprintf("HTTP %d → %d via header %q — protected resource bypassed",
					page.StatusCode, resp.StatusCode, bp.technique),
				Detail: fmt.Sprintf("Access control bypass: adding the %q header to a request that previously returned HTTP %d "+
					"resulted in HTTP %d. The server's access control checks are not applied consistently — a header "+
					"injected by an attacker triggers a different code path that skips authorization.",
					bp.technique, page.StatusCode, resp.StatusCode),
				CWE:         "CWE-284",
				CVSS:        8.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Perform authorization checks on the origin of requests, not on HTTP headers that can be spoofed; reject X-Original-URL and X-Rewrite-URL from untrusted sources; validate IP source at the load balancer, not in application code",
				Tags:        []string{"access-control", "bypass-403", "header-injection", "broken-access-control"},
			})
			break
		}
	}

	// Phase 2: Path normalization bypasses
	for _, variant := range pathVariants(u) {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, variant, nil)
		if err != nil {
			continue
		}
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)

		if isBypass(resp.StatusCode, page.StatusCode, body) {
			findings = append(findings, modules.Finding{
				Module:  "bypass403",
				Severity: modules.High,
				URL:     page.URL,
				Param:   "URL path",
				Payload: variant,
				Evidence: fmt.Sprintf("HTTP %d → %d via path variation %q — protected resource accessible",
					page.StatusCode, resp.StatusCode, variant),
				Detail: fmt.Sprintf("URL path normalization bypass: the path variant %q bypassed access control that blocked the original URL. "+
					"The application or web framework applies URL normalization after access control checks, allowing attackers to access "+
					"protected resources via alternative path representations.", variant),
				CWE:         "CWE-284",
				CVSS:        7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Normalize URLs before applying access control; use framework middleware that applies authz to all path variants; test with path traversal and encoding in authorization test suites",
				Tags:        []string{"access-control", "bypass-403", "path-normalization", "broken-access-control"},
			})
			break
		}
	}

	// Phase 3: HTTP method switching
	for _, method := range []string{http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut} {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, method, page.URL, nil)
		if err != nil {
			continue
		}
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)

		if isBypass(resp.StatusCode, page.StatusCode, body) {
			findings = append(findings, modules.Finding{
				Module:      "bypass403",
				Severity:    modules.Medium,
				URL:         page.URL,
				Param:       "HTTP method",
				Payload:     method,
				Evidence:    fmt.Sprintf("HTTP %d (GET) → %d (%s) — method switching bypassed access control", page.StatusCode, resp.StatusCode, method),
				Detail:      fmt.Sprintf("HTTP method bypass: the %s method bypasses access control that blocked GET; the server applies authorization checks inconsistently across HTTP methods", method),
				CWE:         "CWE-284",
				CVSS:        6.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Apply access control checks uniformly across all HTTP methods; deny unexpected methods (OPTIONS/HEAD/PUT on read-only resources) at the framework or WAF layer",
				Tags:        []string{"access-control", "bypass-403", "method-bypass", "broken-access-control"},
			})
			break
		}
	}

	return findings, nil
}

func isBypass(newStatus, originalStatus int, body []byte) bool {
	if newStatus >= 200 && newStatus < 300 && len(body) > 100 {
		return true
	}
	// 302 to a non-login page can also be a bypass
	if newStatus == 302 && originalStatus == 401 {
		return true
	}
	return false
}
