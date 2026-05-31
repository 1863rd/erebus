package openredirect

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

const attackerDomain = "erebus-redirect-test.invalid"
const attackerURL = "https://" + attackerDomain

var redirectParams = []string{
	"redirect", "redirect_uri", "redirect_url", "next", "url", "return",
	"returnUrl", "return_url", "goto", "destination", "dest", "target",
	"redir", "ref", "callback", "continue", "forward", "location",
	"successUrl", "failureUrl", "loginUrl", "logoutUrl", "r", "u",
	"link", "to", "out", "view", "dir", "show", "navigate", "path",
}

// bypassProbes are variants of attackerURL designed to evade naive allow-list filters.
var bypassProbes = []struct {
	value string
	label string
}{
	{attackerURL, "direct"},
	{"/" + attackerDomain, "root-relative"},
	{"//" + attackerDomain, "scheme-relative"},
	{"\\/" + attackerDomain, "backslash-slash"},
	{"\\\\" + attackerDomain, "double-backslash"},
	{"https:\\" + attackerDomain, "https backslash"},
	{"https://x@" + attackerDomain, "@ bypass"},
	{"https://" + attackerDomain + ".target.com", "subdomain confusion"},
	{"https://" + attackerDomain + "%0a.target.com", "newline in host"},
	{"%2F%2F" + attackerDomain, "double-encoded //"},
	{"%5C%5C" + attackerDomain, "encoded backslash"},
	{"java%0Ascript:alert(1)", "javascript: newline"},
	{"data:text/html,<script>location='https://" + attackerDomain + "'</script>", "data: URI redirect"},
	{" " + attackerURL, "leading space"},
	{"\t" + attackerURL, "leading tab"},
}

type Module struct {
	noFollow *http.Client
}

func New(noVerify bool) *Module {
	return &Module{
		noFollow: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: noVerify},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (m *Module) Name() string { return "openredirect" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Test query parameters
	u, err := url.Parse(page.URL)
	if err == nil {
		tested := make(map[string]struct{})
		for key := range u.Query() {
			if ctx.Err() != nil {
				break
			}
			if _, ok := tested[key]; ok {
				continue
			}
			if isRedirectParam(key) {
				tested[key] = struct{}{}
				findings = append(findings, m.testParam(ctx, page.URL, key)...)
			}
		}
	}

	// Test form hidden fields and text fields
	for _, form := range page.Forms {
		if ctx.Err() != nil {
			break
		}
		for _, f := range form.Fields {
			if !isRedirectParam(f.Name) {
				continue
			}
			findings = append(findings, m.testFormField(ctx, form, f.Name)...)
		}
	}

	// Check page body for JS-based open redirect patterns
	findings = append(findings, m.scanBodyRedirect(page)...)

	return findings, nil
}

func (m *Module) testParam(ctx context.Context, pageURL, param string) []modules.Finding {
	var findings []modules.Finding

	for _, probe := range bypassProbes {
		if ctx.Err() != nil {
			break
		}
		u, err := url.Parse(pageURL)
		if err != nil {
			continue
		}
		q := u.Query()
		q.Set(param, probe.value)
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			continue
		}
		resp, err := m.noFollow.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if f := m.checkResponse(resp, param, probe.value, probe.label, u.String()); f != nil {
			findings = append(findings, *f)
			break
		}
	}
	return findings
}

func (m *Module) testFormField(ctx context.Context, form crawler.Form, fieldName string) []modules.Finding {
	var findings []modules.Finding

	for _, probe := range bypassProbes[:6] { // limit form probes
		if ctx.Err() != nil {
			break
		}
		vals := make(url.Values)
		for _, f := range form.Fields {
			if f.Name == fieldName {
				vals.Set(f.Name, probe.value)
			} else if f.Value != "" {
				vals.Set(f.Name, f.Value)
			} else {
				vals.Set(f.Name, "test")
			}
		}

		var req *http.Request
		var err error
		method := strings.ToUpper(form.Method)
		if method == "" {
			method = "GET"
		}
		if method == "POST" {
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, form.Action, strings.NewReader(vals.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			u, err2 := url.Parse(form.Action)
			if err2 != nil {
				continue
			}
			u.RawQuery = vals.Encode()
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				continue
			}
		}

		resp, err := m.noFollow.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if f := m.checkResponse(resp, fieldName, probe.value, probe.label, form.Action); f != nil {
			findings = append(findings, *f)
			break
		}
	}
	return findings
}

func (m *Module) checkResponse(resp *http.Response, param, value, label, reqURL string) *modules.Finding {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, attackerDomain) {
			sev := modules.Medium
			if label != "direct" {
				sev = modules.High // bypass technique is more severe
			}
			return &modules.Finding{
				Module:   "openredirect",
				Severity: sev,
				URL:      reqURL,
				Param:    param,
				Payload:  value,
				Evidence: fmt.Sprintf("HTTP %d → Location: %s (%s bypass)", resp.StatusCode, loc, label),
				Detail: fmt.Sprintf("Open redirect via parameter %q using %s: server redirects to attacker-controlled domain %q. "+
					"Exploitable for phishing, OAuth token theft, and post-auth redirect hijacking.", param, label, attackerDomain),
				CWE:         "CWE-601",
				CVSS:        6.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Validate redirect destinations against an allow-list of trusted domains; reject external URLs; use a token-based redirect system",
				Tags:        []string{"redirect", "open-redirect", "phishing"},
			}
		}
	}
	return nil
}

// scanBodyRedirect detects open redirect vulnerabilities that operate via JS (location.href, meta refresh)
// rather than HTTP 3xx headers — these are often missed by header-only checks.
func (m *Module) scanBodyRedirect(page crawler.Page) []modules.Finding {
	body := string(page.Body)
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil
	}

	var findings []modules.Finding

	// Patterns that reflect a query param into a JS redirect or meta refresh
	jsRedirectPatterns := []string{
		"location.href", "location.replace", "location.assign",
		"window.location", "document.location",
	}
	metaPattern := `http-equiv="refresh"`

	for _, pattern := range jsRedirectPatterns {
		if strings.Contains(body, pattern) {
			// Check if a known redirect param value appears near the pattern
			for key, vs := range u.Query() {
				if !isRedirectParam(key) || len(vs) == 0 {
					continue
				}
				if strings.Contains(body, vs[0]) {
					findings = append(findings, modules.Finding{
						Module:      "openredirect",
						Severity:    modules.Medium,
						URL:         page.URL,
						Param:       key,
						Payload:     vs[0],
						Evidence:    fmt.Sprintf("Parameter value %q reflected near %q in page body — possible JS-based open redirect", vs[0], pattern),
						Detail:      fmt.Sprintf("Potential JS-based open redirect: parameter %q is reflected near a %s call — manual confirmation recommended", key, pattern),
						CWE:         "CWE-601",
						CVSS:        5.4,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
						Confidence:  modules.Potential,
						Remediation: "Validate redirect destinations against an allow-list; avoid reflecting URL parameters directly into JavaScript location assignments",
						Tags:        []string{"redirect", "open-redirect", "js-redirect"},
					})
				}
			}
		}
	}

	if strings.Contains(strings.ToLower(body), metaPattern) {
		for key, vs := range u.Query() {
			if !isRedirectParam(key) || len(vs) == 0 {
				continue
			}
			if strings.Contains(body, vs[0]) {
				findings = append(findings, modules.Finding{
					Module:      "openredirect",
					Severity:    modules.Medium,
					URL:         page.URL,
					Param:       key,
					Payload:     vs[0],
					Evidence:    fmt.Sprintf("Parameter value %q reflected in meta refresh tag", vs[0]),
					Detail:      fmt.Sprintf("Potential meta-refresh open redirect: parameter %q is reflected in a meta http-equiv=refresh tag", key),
					CWE:         "CWE-601",
					CVSS:        5.4,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
					Confidence:  modules.Potential,
					Remediation: "Validate redirect destinations against an allow-list; avoid reflecting URL parameters into meta refresh tags",
					Tags:        []string{"redirect", "open-redirect", "meta-refresh"},
				})
			}
		}
	}

	return findings
}

func isRedirectParam(name string) bool {
	lower := strings.ToLower(name)
	for _, rp := range redirectParams {
		if lower == rp || strings.Contains(lower, rp) {
			return true
		}
	}
	return false
}
