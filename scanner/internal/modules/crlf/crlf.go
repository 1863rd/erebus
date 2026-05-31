// Package crlf detects HTTP response splitting / CRLF injection vulnerabilities.
// Carriage-return + line-feed sequences in request parameters reflected into
// HTTP response headers allow header injection, cache poisoning, XSS, and session fixation.
package crlf

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

const crlfMarker = "erebus-crlf-x7q2"

// payloads ordered by likelihood to bypass server-side filtering
var payloads = []string{
	"%0d%0aX-" + crlfMarker + ": 1",
	"%0aX-" + crlfMarker + ": 1",
	"%0D%0AX-" + crlfMarker + ": 1",
	"%E5%98%8A%E5%98%8DX-" + crlfMarker + ": 1", // unicode CRLF (U+560A U+560D)
	"%23%0d%0aX-" + crlfMarker + ": 1",          // # fragment bypass
	"\r\nX-" + crlfMarker + ": 1",
	"%0d%0a%20X-" + crlfMarker + ": 1",    // SP after CRLF (folded header)
	"%0d%0a%09X-" + crlfMarker + ": 1",    // HT after CRLF
	"crlf%250d%250aX-" + crlfMarker + ": 1", // double-encoded
	"%0d%0aSet-Cookie: " + crlfMarker + "=1", // cookie injection variant
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "crlf" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding
	seen := make(map[string]struct{})

	// Test URL query parameters
	u, err := url.Parse(page.URL)
	if err == nil {
		for k, vs := range u.Query() {
			orig := ""
			if len(vs) > 0 {
				orig = vs[0]
			}
			_ = orig
			if _, ok := seen[k]; ok {
				continue
			}
			for _, payload := range payloads {
				if ctx.Err() != nil {
					return findings, nil
				}
				q := u.Query()
				q.Set(k, payload)
				cu := *u
				cu.RawQuery = q.Encode()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, cu.String(), nil)
				if err != nil {
					continue
				}
				resp, err := m.client.Do(req)
				if err != nil {
					continue
				}
				client.DrainClose(resp)
				if isVulnerable(resp) {
					seen[k] = struct{}{}
					findings = append(findings, buildFinding(page.URL, k, "query", payload))
					break
				}
			}
		}
	}

	// Test form action URLs for redirect parameters
	for _, form := range page.Forms {
		for _, field := range form.Fields {
			if !isRedirectParam(field.Name) {
				continue
			}
			key := form.Action + "|" + field.Name
			if _, ok := seen[key]; ok {
				continue
			}
			for _, payload := range payloads {
				if ctx.Err() != nil {
					return findings, nil
				}
				vals := make(url.Values)
				for _, f := range form.Fields {
					vals.Set(f.Name, f.Value)
				}
				vals.Set(field.Name, payload)
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, form.Action,
					strings.NewReader(vals.Encode()))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				resp, err := m.client.Do(req)
				if err != nil {
					continue
				}
				client.DrainClose(resp)
				if isVulnerable(resp) {
					seen[key] = struct{}{}
					findings = append(findings, buildFinding(form.Action, field.Name, "form", payload))
					break
				}
			}
		}
	}

	// Test Location/redirect parameters in URL itself
	if u != nil {
		for _, paramName := range []string{"redirect", "redirect_uri", "return", "returnUrl", "next", "url", "continue", "location", "to"} {
			if u.Query().Get(paramName) == "" {
				continue
			}
			key := page.URL + "|redir|" + paramName
			if _, ok := seen[key]; ok {
				continue
			}
			for _, payload := range payloads {
				if ctx.Err() != nil {
					return findings, nil
				}
				q := u.Query()
				q.Set(paramName, "https://example.com/"+payload)
				cu := *u
				cu.RawQuery = q.Encode()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, cu.String(), nil)
				if err != nil {
					continue
				}
				resp, err := m.client.Do(req)
				if err != nil {
					continue
				}
				client.DrainClose(resp)
				if isVulnerable(resp) {
					seen[key] = struct{}{}
					findings = append(findings, buildFinding(page.URL, paramName, "redirect-query", payload))
					break
				}
			}
		}
	}

	return findings, nil
}

func isVulnerable(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	markerLow := strings.ToLower(crlfMarker)
	for k, vs := range resp.Header {
		if strings.Contains(strings.ToLower(k), markerLow) {
			return true
		}
		for _, v := range vs {
			if strings.Contains(strings.ToLower(v), markerLow) {
				return true
			}
		}
	}
	for _, ck := range resp.Cookies() {
		if strings.Contains(strings.ToLower(ck.Name), markerLow) ||
			strings.Contains(strings.ToLower(ck.Value), markerLow) {
			return true
		}
	}
	return false
}

func buildFinding(pageURL, param, loc, payload string) modules.Finding {
	return modules.Finding{
		Module:   "crlf",
		Severity: modules.High,
		URL:      pageURL,
		Param:    param,
		Payload:  payload,
		Evidence: fmt.Sprintf("CRLF injection confirmed: injected header '%s' appeared in HTTP response (location: %s)", crlfMarker, loc),
		Detail: "HTTP Response Splitting / CRLF Injection: a CR+LF sequence in the '" + param + "' parameter is reflected " +
			"into response headers unescaped. Attackers can inject arbitrary headers (Set-Cookie for session fixation, " +
			"Location for open redirect), poison reverse-proxy caches, or create a second HTTP response containing " +
			"attacker-controlled HTML/JavaScript.",
		CWE:         "CWE-113",
		CVSS:        6.1,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		Confidence:  modules.Confirmed,
		Remediation: "Strip or reject CR (\\r / %0d) and LF (\\n / %0a) from all user input reflected into response headers; use framework header-encoding APIs; validate redirect targets against a whitelist",
		Tags:        []string{"crlf", "header-injection", "response-splitting", "cache-poisoning"},
	}
}

func isRedirectParam(name string) bool {
	low := strings.ToLower(name)
	for _, kw := range []string{"redirect", "return", "next", "url", "continue", "location", "to", "target", "back", "forward"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}
