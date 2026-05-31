// Package ratelimit detects missing or bypassable rate limiting on sensitive endpoints.
// First it confirms rate limiting exists, then tries common bypass techniques.
package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

// Sensitive path patterns where rate limiting matters most.
var sensitivePatterns = []string{
	"login", "signin", "auth", "token", "password", "reset",
	"forgot", "register", "signup", "verify", "otp", "2fa", "mfa",
}

// IP spoofing headers commonly trusted by servers / load balancers.
var ipHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"X-Client-IP",
	"CF-Connecting-IP",
	"True-Client-IP",
	"Fastly-Client-IP",
}

type Module struct {
	client    *client.Client
	seenPaths sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "ratelimit" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}

	// Only test sensitive endpoints
	if !isSensitivePath(u.Path) {
		return nil, nil
	}

	// Dedup per (host+structuralPath)
	key := u.Host + "|" + u.Path
	if _, loaded := m.seenPaths.LoadOrStore(key, struct{}{}); loaded {
		return nil, nil
	}

	var findings []modules.Finding

	// Phase 1: detect if rate limiting exists
	hits, limited := m.detectRateLimit(ctx, page.URL, 20)
	if !limited {
		findings = append(findings, modules.Finding{
			Module:      "ratelimit",
			Severity:    modules.Medium,
			URL:         page.URL,
			Param:       "request rate",
			Payload:     "20 rapid requests",
			Evidence:    fmt.Sprintf("Sent 20 rapid requests, %d succeeded with HTTP 2xx — no rate limiting detected", hits),
			Detail:      "No rate limiting detected on a sensitive endpoint — brute force / credential stuffing attacks are unrestricted",
			CWE:         "CWE-307",
			CVSS:        7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Confidence:  modules.Likely,
			Remediation: "Implement rate limiting per IP and per user on all authentication endpoints; use progressive delays and account lockout",
			Tags:        []string{"rate-limit", "brute-force", "api4", "owasp-api"},
		})
		return findings, nil
	}

	// Phase 2: if rate limiting exists, try bypass techniques
	if ctx.Err() != nil {
		return findings, nil
	}
	findings = append(findings, m.testBypassTechniques(ctx, page.URL)...)
	return findings, nil
}

// detectRateLimit fires n requests rapidly and returns (successCount, rateLimitDetected).
func (m *Module) detectRateLimit(ctx context.Context, pageURL string, n int) (int, bool) {
	var successCount int32
	var rateLimited int32
	var wg sync.WaitGroup
	sem := make(chan struct{}, n)

	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
			if err != nil {
				return
			}
			resp, err := m.client.Do(req)
			if err != nil {
				return
			}
			client.DrainClose(resp)
			if resp.StatusCode == 429 ||
				(resp.StatusCode == 503 && resp.Header.Get("Retry-After") != "") {
				atomic.AddInt32(&rateLimited, 1)
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}
	wg.Wait()
	return int(successCount), atomic.LoadInt32(&rateLimited) > 0
}

// testBypassTechniques attempts to bypass detected rate limiting.
func (m *Module) testBypassTechniques(ctx context.Context, pageURL string) []modules.Finding {
	var findings []modules.Finding

	// First: confirm we're currently rate limited
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	client.DrainClose(resp)
	if resp.StatusCode != 429 && resp.StatusCode != 503 {
		return nil // no longer rate limited, not useful to test bypass
	}

	// Technique 1: IP spoofing via X-Forwarded-For etc.
	// Generate a diverse set of fake IPs
	fakeIPs := []string{
		"1.2.3.4", "5.6.7.8", "9.10.11.12", "203.0.113.1", "198.51.100.1",
	}
	for _, h := range ipHeaders {
		if ctx.Err() != nil {
			break
		}
		for _, ip := range fakeIPs {
			req2, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
			if err != nil {
				continue
			}
			req2.Header.Set(h, ip)
			resp2, err := m.client.Do(req2)
			if err != nil {
				continue
			}
			client.DrainClose(resp2)

			if resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
				findings = append(findings, modules.Finding{
					Module:      "ratelimit",
					Severity:    modules.High,
					URL:         pageURL,
					Param:       h,
					Payload:     ip,
					Evidence:    fmt.Sprintf("Rate limit bypassed via %s: %s → HTTP %d (was 429)", h, ip, resp2.StatusCode),
					Detail:      fmt.Sprintf("IP-based rate limiting bypass: adding %s header with a fake IP address circumvents the rate limiter — the server trusts unvalidated client-supplied IP headers to track request counts", h),
					CWE:         "CWE-307",
					CVSS:        7.5,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					Confidence:  modules.Confirmed,
					Remediation: "Never trust client-supplied IP headers for rate limiting; only trust X-Forwarded-For from verified reverse proxies; rate limit per authenticated user, not per IP",
					Tags:        []string{"rate-limit-bypass", "ip-spoofing", "api4", "owasp-api"},
				})
				goto nextHeader
			}
		}
	nextHeader:
	}

	// Technique 2: Path variation (trailing slash, URL encoding, case)
	pathVariants := func(rawURL string) []string {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil
		}
		p := u.Path
		variants := []string{
			p + "/",
			strings.ToUpper(p[:1]) + p[1:],
			p + "%20",
			p + ".",
		}
		var out []string
		for _, v := range variants {
			cu := *u
			cu.Path = v
			out = append(out, cu.String())
		}
		return out
	}

	for _, variant := range pathVariants(pageURL) {
		if ctx.Err() != nil {
			break
		}
		req3, err := http.NewRequestWithContext(ctx, http.MethodGet, variant, nil)
		if err != nil {
			continue
		}
		resp3, err := m.client.Do(req3)
		if err != nil {
			continue
		}
		client.DrainClose(resp3)
		if resp3.StatusCode >= 200 && resp3.StatusCode < 300 {
			findings = append(findings, modules.Finding{
				Module:     "ratelimit",
				Severity:   modules.Medium,
				URL:        variant,
				Param:      "URL path variation",
				Payload:    variant,
				Evidence:   fmt.Sprintf("Rate limit bypassed via URL variation %s → HTTP %d (was 429)", variant, resp3.StatusCode),
				Detail:     "Rate limiting bypass via URL path normalization: slightly different path variations (trailing slash, case, encoding) are not counted against the same rate limit bucket",
				CWE:         "CWE-307",
				CVSS:        6.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Normalize URL paths before matching to rate-limit buckets; treat trailing slashes and case variants as the same endpoint",
				Tags:        []string{"rate-limit-bypass", "path-normalization", "api4"},
			})
			break
		}
	}

	// Technique 3: Null byte / header injection to split rate-limit tracking key
	nullByteTests := []struct {
		header string
		value  string
	}{
		{"X-Forwarded-For", "127.0.0.1\x00"},
		{"X-Forwarded-For", "127.0.0.1, 1.2.3.4"},
		{"X-Real-IP", "127.0.0.1\r\nX-Forwarded-For: 1.2.3.4"},
	}
	for _, nb := range nullByteTests {
		if ctx.Err() != nil {
			break
		}
		req4, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req4.Header.Set(nb.header, nb.value)
		resp4, err := m.client.Do(req4)
		if err != nil {
			continue
		}
		client.DrainClose(resp4)
		if resp4.StatusCode >= 200 && resp4.StatusCode < 300 {
			findings = append(findings, modules.Finding{
				Module:      "ratelimit",
				Severity:    modules.High,
				URL:         pageURL,
				Param:       nb.header,
				Payload:     nb.value,
				Evidence:    fmt.Sprintf("Rate limit bypassed via header value trick (%s: %q) → HTTP %d", nb.header, nb.value, resp4.StatusCode),
				Detail:      "Rate limiting bypass via header manipulation: injecting special characters or extra IPs in the X-Forwarded-For header confuses the rate-limit tracking logic",
				CWE:         "CWE-307",
				CVSS:        7.5,
				Confidence:  modules.Confirmed,
				Remediation: "Sanitize and validate forwarded IP headers; use the first trusted hop only for rate limiting",
				Tags:        []string{"rate-limit-bypass", "header-injection", "api4"},
			})
			break
		}
	}

	// Brief wait to let rate limit window partially reset before returning
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
	}

	return findings
}

func isSensitivePath(path string) bool {
	low := strings.ToLower(path)
	for _, pat := range sensitivePatterns {
		if strings.Contains(low, pat) {
			return true
		}
	}
	return false
}
