package cors

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

type Module struct {
	client    *client.Client
	seenHosts sync.Map
}

func New(c *client.Client) *Module {
	return &Module{client: c}
}

func (m *Module) Name() string { return "cors" }

// pathPrefix returns the first non-empty path segment (e.g. "/api" from "/api/v1/users").
// CORS policies often differ per top-level path, so we test once per host+prefix.
func pathPrefix(path string) string {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) > 0 && parts[0] != "" {
		return "/" + parts[0]
	}
	return "/"
}

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}
	host := u.Scheme + "://" + u.Host

	// Deduplicate by host + first path segment — CORS policies often differ
	// between /api/*, /admin/*, / etc. but testing every sub-path is wasteful.
	scopeKey := host + pathPrefix(u.Path)
	if _, loaded := m.seenHosts.LoadOrStore(scopeKey, struct{}{}); loaded {
		return nil, nil
	}

	var findings []modules.Finding

	testOrigins := []struct {
		origin string
		label  string
	}{
		{"https://evil.example.com", "arbitrary origin"},
		{"null", "null origin"},
		{host + ".evil.com", "suffix bypass (" + host + ".evil.com)"},
		{"https://evil." + u.Host, "subdomain bypass (evil." + u.Host + ")"},
		{"https://not" + u.Host, "prefix bypass (not" + u.Host + ")"},
		{"http://" + u.Host, "scheme downgrade (HTTP)"},
	}

	for _, t := range testOrigins {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, page.URL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", t.origin)
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		client.DrainClose(resp)

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

		if acao == "" {
			continue
		}
		// ACAO=* is low severity on its own (browsers block credentials)
		if acao == "*" {
			if acac == "true" {
				// Invalid combination but some frameworks emit it — flag anyway
				findings = append(findings, modules.Finding{
					Module:      "cors",
					Severity:    modules.Medium,
					URL:         page.URL,
					Param:       "Origin",
					Payload:     t.origin,
					Evidence:    "ACAO: * + ACAC: true (browsers reject this but may indicate misconfiguration)",
					Detail:      "CORS misconfiguration: wildcard Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials: true is an invalid combination per spec; some frameworks emit it anyway, indicating a broken CORS policy that may be exploitable in non-browser contexts",
					CWE:         "CWE-942",
					CVSS:        5.3,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
					Confidence:  modules.Likely,
					Remediation: "Never combine ACAO: * with ACAC: true; use an explicit allowed origin list instead of wildcard when credentials are required",
					Tags:        []string{"cors", "misconfiguration", "information-disclosure"},
				})
			}
			continue
		}

		// Reflected arbitrary origin
		if acao == t.origin || (t.origin == "null" && acao == "null") {
			sev := modules.Medium
			detail := fmt.Sprintf("CORS: %s reflected in Access-Control-Allow-Origin", t.label)
			evidence := fmt.Sprintf("ACAO: %s", acao)

			if acac == "true" {
				sev = modules.High
				detail += " — credentials allowed (authenticated data readable cross-origin)"
				evidence += "  ACAC: true"
			}

			cvss := 6.5
			if acac == "true" {
				cvss = 8.1
			}
			findings = append(findings, modules.Finding{
				Module:      "cors",
				Severity:    sev,
				URL:         page.URL,
				Param:       "Origin",
				Payload:     t.origin,
				Evidence:    evidence,
				Detail:      detail,
				CWE:         "CWE-942",
				CVSS:        cvss,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins; never reflect the request Origin header verbatim; set Vary: Origin when using dynamic CORS",
				Tags:        []string{"cors", "origin-reflection", "cross-origin"},
			})
			break // one confirmed finding per host is sufficient
		}
	}

	// Test preflight for PUT/DELETE from arbitrary origin
	if len(findings) == 0 {
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, page.URL, nil)
		if err == nil {
			req.Header.Set("Origin", "https://evil.example.com")
			req.Header.Set("Access-Control-Request-Method", "PUT")
			req.Header.Set("Access-Control-Request-Headers", "X-Custom-Header")
			resp, err := m.client.Do(req)
			if err == nil {
				client.DrainClose(resp)
				acam := resp.Header.Get("Access-Control-Allow-Methods")
				acao := resp.Header.Get("Access-Control-Allow-Origin")
				if acao == "https://evil.example.com" && strings.Contains(strings.ToUpper(acam), "PUT") {
					findings = append(findings, modules.Finding{
						Module:      "cors",
						Severity:    modules.High,
						URL:         page.URL,
						Param:       "preflight",
						Payload:     "Origin: https://evil.example.com",
						Evidence:    fmt.Sprintf("Preflight allows PUT from arbitrary origin (ACAO: %s, ACAM: %s)", acao, acam),
						Detail:      "CORS preflight misconfiguration: arbitrary cross-origin PUT requests are permitted, enabling state-changing cross-site attacks from any attacker-controlled page",
						CWE:         "CWE-942",
						CVSS:        7.1,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
						Confidence:  modules.Confirmed,
						Remediation: "Restrict Access-Control-Allow-Origin to trusted origins; do not allow state-changing methods (PUT/DELETE/PATCH) from untrusted origins",
						Tags:        []string{"cors", "preflight", "state-change", "cross-origin"},
					})
				}
			}
		}
	}

	return findings, nil
}
