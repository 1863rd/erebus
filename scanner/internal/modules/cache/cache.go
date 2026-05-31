package cache

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

const canary = "erebus-cacheprobe-x7q2"

// unkeyed headers that reverse proxies may include in cache keys but backends reflect
var unkeyed = []struct {
	header string
	value  string
}{
	{"X-Forwarded-Host", canary + ".invalid"},
	{"X-Host", canary + ".invalid"},
	{"X-Forwarded-Scheme", "https://" + canary},
	{"X-Original-URL", "/" + canary + "-path"},
	{"X-Rewrite-URL", "/" + canary + "-path"},
	{"Forwarded", "host=" + canary + ".invalid"},
	{"X-Forwarded-For", "127.0.0.1, " + canary},
	{"X-Http-Method-Override", "GET"},
}

// static suffixes used for cache deception — tricking caches to store dynamic pages
var deceiveSuffixes = []string{
	"/." + canary + ".css",
	"/." + canary + ".js",
	"/." + canary + ".jpg",
	";" + canary + ".css",
	"?" + canary + "=1",
}

type Module struct {
	client    *client.Client
	seenHosts sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "cache" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}
	host := u.Scheme + "://" + u.Host
	if _, loaded := m.seenHosts.LoadOrStore(host, struct{}{}); loaded {
		return nil, nil
	}

	var findings []modules.Finding

	findings = append(findings, m.testUnkeyedHeaders(ctx, page.URL, page.Body)...)
	if ctx.Err() == nil {
		findings = append(findings, m.testCacheDeception(ctx, page.URL, page.Body)...)
	}
	if ctx.Err() == nil {
		if f := m.testHostHeader(ctx, page.URL); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

func (m *Module) testUnkeyedHeaders(ctx context.Context, pageURL string, baseline []byte) []modules.Finding {
	var findings []modules.Finding
	baseStr := string(baseline)

	for _, h := range unkeyed {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set(h.header, h.value)

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, err := client.ReadBody(resp)
		if err != nil {
			continue
		}
		bodyStr := string(body)

		// Canary reflected in body but not in baseline
		reflected := strings.Contains(bodyStr, canary) && !strings.Contains(baseStr, canary)

		// Canary reflected in response headers (e.g. Location redirect)
		headerReflect := false
		for _, vals := range resp.Header {
			for _, v := range vals {
				if strings.Contains(v, canary) {
					headerReflect = true
				}
			}
		}

		if reflected || headerReflect {
			where := "response body"
			if headerReflect {
				where = "response header"
			}

			isCached := m.isCached(resp)
			confidence := modules.Potential
			detail := fmt.Sprintf("Header %s value reflected in %s — injection confirmed but cache poisoning requires this response to be cached", h.header, where)
			if isCached {
				confidence = modules.Confirmed
				detail = fmt.Sprintf("Header %s value reflected in %s AND response appears cached (%s) — web cache poisoning confirmed", h.header, where, m.cacheEvidence(resp))
			}

			findings = append(findings, modules.Finding{
				Module:      "cache",
				Severity:    modules.High,
				URL:         pageURL,
				Param:       h.header,
				Payload:     h.value,
				Evidence:    fmt.Sprintf("Canary %q found in %s (cached=%v)", canary, where, isCached),
				Detail:      detail,
				CWE:         "CWE-601",
				CVSS:        8.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  confidence,
				Remediation: "Strip/ignore unkeyed headers at the CDN/proxy layer; add host-related headers to the cache key; validate Host-family headers server-side",
				Tags:        []string{"cache-poisoning", "unkeyed-header", "web-cache"},
			})
		}
	}
	return findings
}

func (m *Module) testCacheDeception(ctx context.Context, pageURL string, baseline []byte) []modules.Finding {
	var findings []modules.Finding
	baseStr := string(baseline)

	// Only test pages that look dynamic (have query params or path segments that resemble IDs/profiles)
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}

	looksPersonal := strings.ContainsAny(u.Path, "/") &&
		(strings.Contains(u.Path, "profile") || strings.Contains(u.Path, "account") ||
			strings.Contains(u.Path, "user") || strings.Contains(u.Path, "dashboard") ||
			strings.Contains(u.Path, "settings") || len(u.RawQuery) > 0)

	if !looksPersonal {
		return nil
	}

	for _, suffix := range deceiveSuffixes {
		if ctx.Err() != nil {
			break
		}
		testURL := pageURL + suffix
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			continue
		}
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, err := client.ReadBody(resp)
		if err != nil {
			continue
		}

		// The test page returned the same sensitive content as the original
		bodyStr := string(body)
		if resp.StatusCode == 200 && len(body) > 200 &&
			bodyStr == baseStr && m.isCached(resp) {
			findings = append(findings, modules.Finding{
				Module:      "cache",
				Severity:    modules.Medium,
				URL:         testURL,
				Param:       "URL path",
				Payload:     suffix,
				Evidence:    fmt.Sprintf("Dynamic page served at %s and response appears cached (%s)", testURL, m.cacheEvidence(resp)),
				Detail:      "Web cache deception: appending a static-looking suffix returns the same authenticated/dynamic content and the response may be cached — an attacker can steal another user's cached page",
				CWE:         "CWE-525",
				CVSS:        6.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
				Confidence:  modules.Likely,
				Remediation: "Validate cache rules based on Content-Type and response cacheability, not just URL path extension; strip path extensions before routing",
				Tags:        []string{"cache-deception", "web-cache", "info-disclosure"},
			})
			break
		}
	}
	return findings
}

func (m *Module) testHostHeader(ctx context.Context, pageURL string) *modules.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	injectedHost := canary + ".invalid"
	req.Host = injectedHost

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	loc := resp.Header.Get("Location")

	if strings.Contains(bodyStr, canary) || strings.Contains(loc, canary) {
		return &modules.Finding{
			Module:      "cache",
			Severity:    modules.High,
			URL:         pageURL,
			Param:       "Host header",
			Payload:     injectedHost,
			Evidence:    fmt.Sprintf("Host: %s reflected in response — host header injection confirmed (original host: %s)", injectedHost, u.Host),
			Detail:      "Host header injection: the server reflects the Host header value in responses (absolute URLs, redirects). Combined with web caching, this enables cache poisoning to serve attacker-controlled URLs to all users.",
			CWE:         "CWE-20",
			CVSS:        7.4,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Whitelist valid Host header values; never construct absolute URLs from the Host header without validation",
			Tags:        []string{"host-header-injection", "cache-poisoning"},
		}
	}
	return nil
}

func (m *Module) isCached(resp *http.Response) bool {
	xCache := strings.ToLower(resp.Header.Get("X-Cache"))
	cfCache := strings.ToLower(resp.Header.Get("CF-Cache-Status"))
	age := resp.Header.Get("Age")
	via := resp.Header.Get("Via")

	return strings.Contains(xCache, "hit") ||
		cfCache == "hit" || cfCache == "stale" ||
		(age != "" && age != "0") ||
		(via != "" && !strings.Contains(strings.ToLower(via), "miss"))
}

func (m *Module) cacheEvidence(resp *http.Response) string {
	parts := []string{}
	if v := resp.Header.Get("X-Cache"); v != "" {
		parts = append(parts, "X-Cache: "+v)
	}
	if v := resp.Header.Get("CF-Cache-Status"); v != "" {
		parts = append(parts, "CF-Cache-Status: "+v)
	}
	if v := resp.Header.Get("Age"); v != "" {
		parts = append(parts, "Age: "+v)
	}
	if v := resp.Header.Get("Via"); v != "" {
		parts = append(parts, "Via: "+v)
	}
	if len(parts) == 0 {
		return "no cache headers"
	}
	return strings.Join(parts, "; ")
}
