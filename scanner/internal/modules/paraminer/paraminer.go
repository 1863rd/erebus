// Package paraminer discovers hidden, undocumented, or debug parameters that alter
// application behavior. Tests parameter names not visible in the UI against every
// page URL, looking for status code changes, response size changes, or special content.
package paraminer

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

// candidateParams — parameters commonly accepted by frameworks but not exposed in UI.
// Grouped by category for targeted reporting.
var candidateParams = []struct {
	name     string
	value    string
	category string
}{
	// Debug / diagnostic
	{"debug", "1", "debug"},
	{"debug", "true", "debug"},
	{"trace", "1", "debug"},
	{"test", "1", "debug"},
	{"verbose", "1", "debug"},
	{"internal", "true", "debug"},
	{"dev", "true", "debug"},
	{"preview", "1", "debug"},
	{"staging", "1", "debug"},
	// Admin / privilege
	{"admin", "1", "privilege"},
	{"admin", "true", "privilege"},
	{"is_admin", "true", "privilege"},
	{"role", "admin", "privilege"},
	{"role", "superadmin", "privilege"},
	{"user_role", "admin", "privilege"},
	// Format / content negotiation
	{"format", "json", "format"},
	{"format", "xml", "format"},
	{"format", "csv", "format"},
	{"output", "json", "format"},
	{"type", "json", "format"},
	{"response_format", "json", "format"},
	// JSONP / callback
	{"callback", "erebusTest", "jsonp"},
	{"jsonp", "erebusTest", "jsonp"},
	{"cb", "erebusTest", "jsonp"},
	// Version / API
	{"v", "2", "version"},
	{"version", "2", "version"},
	{"api_version", "2", "version"},
	// Language / locale
	{"lang", "en", "locale"},
	{"locale", "en_US", "locale"},
	{"language", "en", "locale"},
	// ID / reference
	{"id", "1", "id"},
	{"user_id", "1", "id"},
	{"userId", "1", "id"},
	{"account_id", "1", "id"},
	// Cache / bypass
	{"cache", "0", "cache"},
	{"nocache", "1", "cache"},
	{"_", "1", "cache"},
	// Source / origin
	{"source", "api", "misc"},
	{"origin", "api", "misc"},
	{"ref", "internal", "misc"},
	{"from", "app", "misc"},
	// Search / filter
	{"q", "erebusTestMine", "search"},
	{"search", "erebusTestMine", "search"},
	{"query", "erebusTestMine", "search"},
	{"filter", "all", "search"},
	// Pagination
	{"page", "1", "pagination"},
	{"limit", "9999", "pagination"},
	{"offset", "0", "pagination"},
	{"per_page", "9999", "pagination"},
	{"count", "9999", "pagination"},
	// Feature flags / toggles
	{"feature", "all", "feature"},
	{"flag", "all", "feature"},
	{"mode", "debug", "feature"},
	{"beta", "1", "feature"},
	{"experimental", "1", "feature"},
}

// interestingPatterns — response body patterns that indicate something meaningful happened
var interestingPatterns = []string{
	"debug", "trace", "stack", "error", "exception", "internal",
	"admin", "password", "secret", "token", "key", "credential",
	"uid=", "root:", "PRIVATE KEY", "BEGIN RSA", "access_key",
	"SELECT ", "INSERT ", "UPDATE ", "DELETE ", "FROM ",
}

type Module struct {
	client   *client.Client
	seenURLs sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "paraminer" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}

	// Only test API-looking paths — skip static assets and HTML pages
	if !looksLikeTestable(u.Path, page.Headers) {
		return nil, nil
	}

	// Structural dedup — one test per normalized path pattern
	structural := structuralPattern(u.Path)
	key := u.Host + "|" + structural
	if _, loaded := m.seenURLs.LoadOrStore(key, struct{}{}); loaded {
		return nil, nil
	}

	// Baseline: GET the page as-is
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, page.URL, nil)
	if err != nil {
		return nil, nil
	}
	baseResp, err := m.client.Do(baseReq)
	if err != nil {
		return nil, nil
	}
	baseBody, _ := client.ReadBody(baseResp)
	if baseResp.StatusCode >= 400 {
		return nil, nil
	}
	if isHTMLBody(baseBody) {
		return nil, nil
	}

	var findings []modules.Finding
	seen := make(map[string]struct{})

	sem := make(chan struct{}, 10)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, cp := range candidateParams {
		if ctx.Err() != nil {
			break
		}
		// Skip if this exact param already exists on the URL
		if _, exists := u.Query()[cp.name]; exists {
			continue
		}
		// Skip duplicate param+value combos
		dk := cp.name + "=" + cp.value
		if _, ok := seen[dk]; ok {
			continue
		}
		seen[dk] = struct{}{}

		wg.Add(1)
		sem <- struct{}{}
		cp := cp // capture
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			testU := *u
			q := testU.Query()
			q.Set(cp.name, cp.value)
			testU.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, testU.String(), nil)
			if err != nil {
				return
			}
			resp, err := m.client.Do(req)
			if err != nil {
				return
			}
			body, _ := client.ReadBody(resp)

			f := analyzeParamResponse(page.URL, cp.name, cp.value, cp.category, baseResp.StatusCode, len(baseBody), baseBody, resp.StatusCode, body)
			if f != nil {
				mu.Lock()
				findings = append(findings, *f)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Test Accept header content-type negotiation (JSON/XML format switching)
	if modules.GetMode(ctx) == modules.ModeDeep {
		findings = append(findings, m.testContentNegotiation(ctx, page.URL, baseResp.StatusCode, baseBody)...)
	}

	return findings, nil
}

func analyzeParamResponse(pageURL, param, value, category string, baseStatus, baseLen int, baseBody []byte, altStatus int, altBody []byte) *modules.Finding {
	altLen := len(altBody)
	altStr := string(altBody)
	baseStr := strings.ToLower(string(baseBody))

	// Case 1: status code change (e.g., 200→403 means param was recognized, or 404→200 = hidden endpoint revealed)
	if altStatus != baseStatus {
		sev := modules.Low
		if baseStatus >= 400 && altStatus < 400 {
			sev = modules.High // was blocked, now accessible
		} else if baseStatus < 400 && altStatus == 200 && altLen > 100 && !isHTMLBody(altBody) {
			sev = modules.Medium
		}
		if sev != modules.Low || (altStatus >= 200 && altStatus < 300) {
			return &modules.Finding{
				Module:   "paraminer",
				Severity: sev,
				URL:      pageURL + "?" + param + "=" + value,
				Param:    param,
				Payload:  value,
				Evidence: fmt.Sprintf("Adding ?%s=%s changed HTTP status from %d to %d", param, value, baseStatus, altStatus),
				Detail:   fmt.Sprintf("Hidden parameter discovered: ?%s=%s changed the HTTP response status code, indicating the parameter is processed by the server but not exposed in the UI. Category: %s", param, value, category),
				CWE:         "CWE-235",
				CVSS:        paramCVSS(sev),
				CVSSVector:  paramCVSSVector(sev),
				Confidence:  modules.Likely,
				Remediation: "Remove or disable undocumented debug/admin parameters in production; implement proper authorization on any internal parameters",
				Tags:        []string{"paraminer", "hidden-param", category, "api-discovery"},
			}
		}
	}

	// Case 2: response contains interesting/sensitive patterns that baseline didn't
	for _, pattern := range interestingPatterns {
		if strings.Contains(strings.ToLower(altStr), strings.ToLower(pattern)) &&
			!strings.Contains(baseStr, strings.ToLower(pattern)) {
			sev := modules.Medium
			if pattern == "uid=" || pattern == "root:" || strings.Contains(pattern, "KEY") ||
				strings.Contains(pattern, "credential") || strings.Contains(pattern, "secret") {
				sev = modules.High
			}
			return &modules.Finding{
				Module:   "paraminer",
				Severity: sev,
				URL:      pageURL + "?" + param + "=" + value,
				Param:    param,
				Payload:  value,
				Evidence: fmt.Sprintf("Adding ?%s=%s triggered new response pattern %q not present in baseline", param, value, pattern),
				Detail:   fmt.Sprintf("Hidden parameter %q=%q exposed sensitive information (%s) not present in normal response. Category: %s", param, value, pattern, category),
				CWE:         "CWE-235",
				CVSS:        paramCVSS(sev),
				CVSSVector:  paramCVSSVector(sev),
				Confidence:  modules.Likely,
				Remediation: "Remove debug and admin parameters from production builds; never expose internal information via query parameters",
				Tags:     []string{"paraminer", "hidden-param", "info-disclosure", category},
			}
		}
	}

	// Case 3: JSONP callback reflected — potential JSONP hijacking
	if category == "jsonp" && strings.Contains(altStr, "erebusTest(") {
		return &modules.Finding{
			Module:   "paraminer",
			Severity: modules.Medium,
			URL:      pageURL + "?" + param + "=" + value,
			Param:    param,
			Payload:  value,
			Evidence: fmt.Sprintf("JSONP callback %q reflected in response — endpoint supports JSONP", "erebusTest"),
			Detail:   "JSONP endpoint discovered: the server wraps its JSON response in a callback function named by the caller. This allows cross-origin data theft if the endpoint returns sensitive data and CORS is not enforced.",
			CWE:      "CWE-346",
			CVSS:     6.1,
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			Confidence: modules.Confirmed,
			Remediation: "Remove JSONP support; use CORS with explicit allowed origins instead",
			Tags:     []string{"paraminer", "jsonp", "cors", "data-theft"},
		}
	}

	// Case 4: significant size increase with non-HTML content (debug data exposed)
	if altStatus == baseStatus && altStatus < 400 && !isHTMLBody(altBody) && baseLen > 0 {
		growth := altLen - baseLen
		if growth > 500 && float64(growth)/float64(baseLen) > 0.50 {
			return &modules.Finding{
				Module:   "paraminer",
				Severity: modules.Low,
				URL:      pageURL + "?" + param + "=" + value,
				Param:    param,
				Payload:  value,
				Evidence: fmt.Sprintf("Response grew %d→%d bytes (+%.0f%%) with ?%s=%s — possible extra data returned", baseLen, altLen, float64(growth)/float64(baseLen)*100, param, value),
				Detail:   fmt.Sprintf("Adding parameter ?%s=%s significantly increased the response size, suggesting undocumented functionality or debug data exposure. Category: %s", param, value, category),
				CWE:         "CWE-235",
				CVSS:        3.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
				Confidence:  modules.Potential,
				Remediation: "Audit undocumented parameters; do not expose internal data based on query parameters in production",
				Tags:     []string{"paraminer", "hidden-param", "info-disclosure", category},
			}
		}
	}

	return nil
}

// testContentNegotiation checks if Accept header switching reveals alternative response formats.
func (m *Module) testContentNegotiation(ctx context.Context, pageURL string, baseStatus int, baseBody []byte) []modules.Finding {
	var findings []modules.Finding
	for _, accept := range []string{"application/xml", "text/xml"} {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", accept)
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)
		ct := resp.Header.Get("Content-Type")

		if resp.StatusCode == baseStatus && strings.Contains(strings.ToLower(ct), "xml") && !isHTMLBody(body) {
			findings = append(findings, modules.Finding{
				Module:   "paraminer",
				Severity: modules.Low,
				URL:      pageURL,
				Param:    "Accept",
				Payload:  accept,
				Evidence: fmt.Sprintf("Accept: %s returned Content-Type: %s — endpoint supports XML", accept, ct),
				Detail:   "Content negotiation: the endpoint serves XML responses when requested, which may expose different data fields or be vulnerable to XML-specific attacks (XXE, entity expansion)",
				CWE:         "CWE-611",
				CVSS:        3.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Disable XML content negotiation if not required; validate and restrict Accept header handling",
				Tags:        []string{"paraminer", "content-negotiation", "xxe-surface"},
			})
		}
	}
	return findings
}

func looksLikeTestable(path string, headers map[string][]string) bool {
	// Skip static assets
	low := strings.ToLower(path)
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".ttf", ".svg", ".map", ".txt"} {
		if strings.HasSuffix(low, ext) {
			return false
		}
	}
	// Prefer API paths, but test anything with params
	return true
}

func isHTMLBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	n := len(body)
	if n > 100 {
		n = 100
	}
	peek := strings.TrimSpace(strings.ToLower(string(body[:n])))
	return strings.HasPrefix(peek, "<!doctype html") || strings.HasPrefix(peek, "<html")
}

func structuralPattern(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if isID(seg) {
			segments[i] = "{id}"
		}
	}
	return strings.Join(segments, "/")
}

func isID(s string) bool {
	if len(s) == 0 {
		return false
	}
	allNum := true
	for _, c := range s {
		if c < '0' || c > '9' {
			allNum = false
			break
		}
	}
	return allNum || len(s) == 36 // UUID
}

func paramCVSS(sev modules.Severity) float64 {
	switch sev {
	case modules.High:
		return 7.5
	case modules.Medium:
		return 5.3
	default:
		return 3.5
	}
}

func paramCVSSVector(sev modules.Severity) string {
	switch sev {
	case modules.High:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
	case modules.Medium:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
	default:
		return "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
	}
}
