package bfla

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

var privilegedPaths = []string{
	"/admin", "/admin/", "/admin/users", "/admin/settings", "/admin/dashboard",
	"/admin/config", "/admin/logs", "/admin/reports", "/admin/system",
	"/api/admin", "/api/v1/admin", "/api/v2/admin", "/api/admin/users",
	"/api/admin/settings", "/api/admin/config",
	"/manage", "/management", "/management/users", "/management/roles",
	"/internal", "/internal/api", "/internal/metrics",
	"/_debug", "/_admin", "/_internal", "/debug/vars", "/debug/pprof",
	"/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
	"/actuator/mappings", "/actuator/metrics", "/actuator/loggers",
	"/actuator/httptrace", "/actuator/configprops",
	"/metrics", "/health/details", "/status/details",
	"/api/users", "/api/v1/users", "/api/v2/users",
	"/api/roles", "/api/v1/roles", "/api/permissions",
	"/api/export", "/api/import", "/api/backup",
	"/api/config", "/api/settings",
}

// actuatorRequired maps paths to the body substrings that must appear to confirm the finding.
// HTTP 200 alone is not proof — a SPA or non-Spring server returns 200 for everything.
var actuatorRequired = map[string][]string{
	"/actuator":               {"\"_links\"", "\"components\""},
	"/actuator/health":        {"\"status\"", "\"UP\"", "\"DOWN\"", "\"UNKNOWN\""},
	"/actuator/env":           {"activeProfiles", "propertySources"},
	"/actuator/beans":         {"\"beans\"", "\"aliases\"", "\"scope\""},
	"/actuator/mappings":      {"\"mappings\"", "dispatcherServlets"},
	"/actuator/metrics":       {"\"names\"", "\"measurements\""},
	"/actuator/loggers":       {"\"loggers\"", "configuredLevel"},
	"/actuator/httptrace":     {"\"traces\""},
	"/actuator/configprops":   {"\"contexts\"", "\"prefix\""},
	"/debug/pprof":            {"goroutine", "heap", "threadcreate"},
	"/debug/vars":             {"cmdline", "memstats"},
	"/metrics":                {"# HELP", "# TYPE"},
}

var escalationMethods = []string{
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
}

type Module struct {
	client    *client.Client
	seenHosts sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "bfla" }

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
	findings = append(findings, m.probePrivilegedPaths(ctx, host)...)
	if ctx.Err() == nil {
		findings = append(findings, m.testMethodEscalation(ctx, page)...)
	}
	return findings, nil
}

func (m *Module) probePrivilegedPaths(ctx context.Context, host string) []modules.Finding {
	// Baseline: probe a guaranteed non-existent path to detect SPA catch-all and soft-404.
	// Any 2xx response to a privileged path must differ from this baseline to be valid.
	baseBody, baseStatus := m.fetchBody(ctx, host+"/erebus_bfla_nonexistent_9x4f2a")

	var findings []modules.Finding
	for _, path := range privilegedPaths {
		if ctx.Err() != nil {
			break
		}
		body, status, ct := m.fetchBodyFull(ctx, host+path)
		if body == nil || status == 0 {
			continue
		}
		if status == 401 || status == 403 || status == 404 || status == 405 || status == 410 {
			continue
		}
		if status >= 500 {
			continue
		}
		if status < 200 || status >= 300 {
			continue
		}
		if len(body) < 50 {
			continue
		}

		// SPA catch-all / soft-404: same status + similar body size as baseline → skip.
		if baseStatus == status && bodySimilar(body, baseBody) {
			continue
		}

		// For actuator/debug/metrics paths, require specific content markers.
		// An Angular or Express app will 200 these paths with HTML or an empty JSON object.
		if markers, ok := actuatorRequired[path]; ok {
			if !containsAny(string(body), markers) {
				continue
			}
		}

		// For all other paths: reject plain HTML that doesn't carry meaningful admin content.
		// A SPA returns its index.html for every undefined route.
		if isHTML(ct, body) && !meaningfulAdminHTML(path, body) {
			continue
		}

		sev, detail := classifyPath(path, status, body)
		findings = append(findings, modules.Finding{
			Module:      "bfla",
			Severity:    sev,
			URL:         host + path,
			Param:       "URL path",
			Payload:     path,
			Evidence:    fmt.Sprintf("HTTP %d, %d bytes — %s", status, len(body), contentSummary(ct, body)),
			Detail:      detail,
			CWE:         "CWE-285",
			CVSS:        bflaCVSS(sev),
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Implement function-level authorization on every endpoint; use role-based access control middleware; deny by default",
			Tags:        []string{"bfla", "api5", "owasp-api", "privilege-escalation"},
		})
	}
	return findings
}

func (m *Module) testMethodEscalation(ctx context.Context, page crawler.Page) []modules.Finding {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil
	}
	if !looksLikeAPI(u.Path) {
		return nil
	}

	// GET baseline to detect SPA same-content fallback and to compare response body.
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, page.URL, nil)
	if err != nil {
		return nil
	}
	getResp, err := m.client.Do(getReq)
	if err != nil {
		return nil
	}
	baseline, _ := client.ReadBody(getResp)
	baselineCT := getResp.Header.Get("Content-Type")

	// Skip entirely if the GET baseline is HTML — we're on a SPA frontend route.
	if isHTML(baselineCT, baseline) {
		return nil
	}

	var findings []modules.Finding
	for _, method := range escalationMethods {
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

		if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 204 {
			// Reject if same content as GET (SPA fallback or no-op).
			if bodySimilar(body, baseline) {
				continue
			}
			// Reject HTML fallback.
			if isHTML(resp.Header.Get("Content-Type"), body) {
				continue
			}
			findings = append(findings, modules.Finding{
				Module:      "bfla",
				Severity:    modules.High,
				URL:         page.URL,
				Param:       "HTTP method",
				Payload:     method,
				Evidence:    fmt.Sprintf("%s %s → HTTP %d (%d bytes) — method accepted, distinct from GET response", method, page.URL, resp.StatusCode, len(body)),
				Detail:      fmt.Sprintf("Broken function-level authorization via HTTP method escalation: %s method accepted on an endpoint that appeared GET-only. May allow unauthorized resource creation or modification.", method),
				CWE:         "CWE-285",
				CVSS:        8.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
				Confidence:  modules.Likely,
				Remediation: "Restrict HTTP methods per endpoint; return 405 for unsupported methods; enforce authorization per method, not just per path",
				Tags:        []string{"bfla", "method-escalation", "api5", "owasp-api"},
			})
		} else if resp.StatusCode == 405 {
			for _, override := range []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"} {
				if ctx.Err() != nil {
					break
				}
				req2, err := http.NewRequestWithContext(ctx, http.MethodPost, page.URL, nil)
				if err != nil {
					continue
				}
				req2.Header.Set(override, method)
				resp2, err := m.client.Do(req2)
				if err != nil {
					continue
				}
				body2, _ := client.ReadBody(resp2)
				if (resp2.StatusCode == 200 || resp2.StatusCode == 201 || resp2.StatusCode == 204) &&
					!bodySimilar(body2, baseline) &&
					!isHTML(resp2.Header.Get("Content-Type"), body2) {
					findings = append(findings, modules.Finding{
						Module:      "bfla",
						Severity:    modules.High,
						URL:         page.URL,
						Param:       override,
						Payload:     method,
						Evidence:    fmt.Sprintf("POST with %s: %s → HTTP %d — method override bypass succeeded", override, method, resp2.StatusCode),
						Detail:      fmt.Sprintf("HTTP method override bypass via %s: %s method tunneled through POST bypasses method-level access control", override, method),
						CWE:         "CWE-285",
						CVSS:        8.1,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
						Confidence:  modules.Confirmed,
						Remediation: "Do not honor HTTP method override headers on endpoints with function-level authorization; validate the effective method through the same authorization middleware as native methods",
						Tags:        []string{"bfla", "method-override", "api5", "owasp-api"},
						Request:     fmt.Sprintf("POST %s\n%s: %s", page.URL, override, method),
						Response:    string(body2[:minInt(200, len(body2))]),
					})
					break
				}
			}
		}
	}
	return findings
}

func (m *Module) fetchBody(ctx context.Context, fullURL string) ([]byte, int) {
	b, s, _ := m.fetchBodyFull(ctx, fullURL)
	return b, s
}

func (m *Module) fetchBodyFull(ctx context.Context, fullURL string) ([]byte, int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, 0, ""
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, ""
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil, 0, ""
	}
	return body, resp.StatusCode, resp.Header.Get("Content-Type")
}

// isHTML returns true when the response is an HTML document (SPA or static page).
// Checks Content-Type header first, then the body prefix as fallback.
func isHTML(ct string, body []byte) bool {
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return true
	}
	peek := strings.TrimSpace(strings.ToLower(string(body[:minInt(100, len(body))])))
	return strings.HasPrefix(peek, "<!doctype html") || strings.HasPrefix(peek, "<html")
}

// meaningfulAdminHTML returns true only when an HTML response on an admin path contains
// evidence of a real admin interface (login form, user table, admin keywords).
// Prevents flagging a SPA's index.html caught at /admin as a BFLA finding.
func meaningfulAdminHTML(path string, body []byte) bool {
	low := strings.ToLower(string(body))
	pathLow := strings.ToLower(path)
	if strings.Contains(pathLow, "admin") || strings.Contains(pathLow, "manage") {
		// Real admin panel: login form with password field, or admin-specific product keyword
		hasLogin := strings.Contains(low, "password") &&
			(strings.Contains(low, "login") || strings.Contains(low, "username") || strings.Contains(low, "sign in"))
		hasAdminKeyword := strings.Contains(low, "phpmyadmin") ||
			strings.Contains(low, "adminer") ||
			strings.Contains(low, "admin panel") ||
			strings.Contains(low, "administration console")
		return hasLogin || hasAdminKeyword
	}
	return false
}

func containsAny(body string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

// bodySimilar returns true when two bodies are within 15% or 200 bytes of each other.
// Used to detect SPA catch-all responses and soft-404 pages.
func bodySimilar(a, b []byte) bool {
	if len(b) == 0 {
		return len(a) == 0
	}
	diff := len(a) - len(b)
	if diff < 0 {
		diff = -diff
	}
	return diff < 200 || float64(diff)/float64(len(b)) < 0.15
}

func contentSummary(ct string, body []byte) string {
	ctLow := strings.ToLower(ct)
	if strings.Contains(ctLow, "json") {
		snippet := strings.TrimSpace(string(body[:minInt(80, len(body))]))
		return "JSON: " + snippet
	}
	if strings.Contains(ctLow, "text/plain") {
		return "plain text"
	}
	return "non-HTML content"
}

func classifyPath(path string, status int, body []byte) (modules.Severity, string) {
	low := strings.ToLower(path)
	bodyStr := string(body)

	switch {
	case strings.Contains(low, "actuator") || strings.Contains(low, "pprof"):
		return modules.Critical, fmt.Sprintf("Spring Boot Actuator / Go pprof endpoint confirmed at %s — diagnostic data exposed (HTTP %d)", path, status)
	case strings.Contains(low, "debug") || strings.Contains(low, "vars"):
		return modules.High, fmt.Sprintf("Debug endpoint confirmed at %s — runtime data exposed (HTTP %d)", path, status)
	case strings.Contains(low, "admin") || strings.Contains(low, "manage") || strings.Contains(low, "internal"):
		if strings.Contains(bodyStr, "\"email\"") || strings.Contains(bodyStr, "\"password\"") || strings.Contains(bodyStr, "\"role\"") {
			return modules.Critical, fmt.Sprintf("Admin endpoint at %s exposes user credentials/roles in response body (HTTP %d)", path, status)
		}
		return modules.High, fmt.Sprintf("Admin/management endpoint at %s accessible with current session (HTTP %d)", path, status)
	case strings.Contains(low, "role") || strings.Contains(low, "permission"):
		return modules.High, fmt.Sprintf("Role/permission management endpoint at %s accessible (HTTP %d)", path, status)
	case strings.Contains(low, "export") || strings.Contains(low, "backup") || strings.Contains(low, "import"):
		return modules.High, fmt.Sprintf("Data export/backup endpoint at %s accessible — bulk data exfiltration risk (HTTP %d)", path, status)
	default:
		return modules.Medium, fmt.Sprintf("Privileged endpoint %s accessible with current session (HTTP %d)", path, status)
	}
}

func bflaCVSS(sev modules.Severity) float64 {
	switch sev {
	case modules.Critical:
		return 9.8
	case modules.High:
		return 8.1
	default:
		return 6.5
	}
}

func looksLikeAPI(path string) bool {
	low := strings.ToLower(path)
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".ttf", ".svg", ".map"} {
		if strings.HasSuffix(low, ext) {
			return false
		}
	}
	return strings.Contains(low, "/api/") || strings.Contains(low, "/v1/") ||
		strings.Contains(low, "/v2/") || strings.Contains(low, "/v3/") ||
		strings.Contains(low, "/rest/") || strings.Contains(low, "/service/") ||
		strings.Contains(low, "/resource") || strings.Contains(low, "/data/")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
