package headers

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

type missingCheck struct {
	header      string
	severity    modules.Severity
	detail      string
	cwe         string
	cvss        float64
	cvssVector  string
	remediation string
	tags        []string
}

var requiredHeaders = []missingCheck{
	{
		"Strict-Transport-Security", modules.Medium,
		"Missing HSTS — TLS downgrade and MITM attacks possible; clients may connect over HTTP even when HTTPS is available",
		"CWE-311", 6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		"Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses",
		[]string{"headers", "hsts", "tls", "transport-security"},
	},
	{
		"X-Frame-Options", modules.Medium,
		"Missing X-Frame-Options — page can be embedded in an iframe; clickjacking attacks possible",
		"CWE-1021", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		"Add 'X-Frame-Options: DENY' or use CSP frame-ancestors directive; prefer CSP for modern browsers",
		[]string{"headers", "clickjacking", "x-frame-options"},
	},
	{
		"X-Content-Type-Options", modules.Low,
		"Missing X-Content-Type-Options — browsers may MIME-sniff responses away from declared content-type",
		"CWE-16", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
		"Add 'X-Content-Type-Options: nosniff' to all responses",
		[]string{"headers", "mime-sniffing", "x-content-type-options"},
	},
	{
		"Content-Security-Policy", modules.Medium,
		"Missing Content-Security-Policy — no browser-enforced XSS mitigation policy; inline scripts and arbitrary origins allowed",
		"CWE-693", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		"Define a strict Content-Security-Policy: restrict script-src, object-src, and base-uri; avoid 'unsafe-inline'",
		[]string{"headers", "csp", "xss-mitigation"},
	},
	{
		"Referrer-Policy", modules.Low,
		"Missing Referrer-Policy — full URL (including query params and path) may leak to third parties via Referer header",
		"CWE-200", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
		"Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' to prevent URL leakage",
		[]string{"headers", "referrer-policy", "information-disclosure"},
	},
	{
		"Permissions-Policy", modules.Low,
		"Missing Permissions-Policy — browser features (camera, microphone, geolocation) unrestricted for embedded/third-party frames",
		"CWE-16", 2.7, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
		"Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to restrict feature access",
		[]string{"headers", "permissions-policy", "feature-policy"},
	},
}

type valueCheck struct {
	header      string
	badValue    string
	severity    modules.Severity
	detail      string
	cwe         string
	cvss        float64
	cvssVector  string
	remediation string
	tags        []string
}

var badValueChecks = []valueCheck{
	{
		"Access-Control-Allow-Origin", "*", modules.Medium,
		"CORS wildcard — any origin can read non-credentialed responses from this endpoint",
		"CWE-942", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		"Replace the wildcard with an explicit list of trusted origins; never combine ACAO: * with ACAC: true",
		[]string{"headers", "cors", "origin-wildcard"},
	},
	{
		"X-Powered-By", "", modules.Info,
		"Technology stack disclosed via X-Powered-By header — aids attacker fingerprinting and CVE targeting",
		"CWE-200", 2.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
		"Remove or suppress the X-Powered-By header in framework/server configuration",
		[]string{"headers", "information-disclosure", "fingerprinting"},
	},
	{
		"Server", "", modules.Info,
		"Server version banner disclosed — version info helps attackers identify matching CVEs",
		"CWE-200", 2.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
		"Configure the web server to omit or genericize the Server header (Apache: ServerTokens Prod; nginx: server_tokens off)",
		[]string{"headers", "information-disclosure", "fingerprinting", "server-banner"},
	},
	{
		"X-AspNet-Version", "", modules.Info,
		"ASP.NET runtime version disclosed — assists targeted vulnerability research",
		"CWE-200", 2.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
		"Add <httpRuntime enableVersionHeader=\"false\" /> in web.config to suppress this header",
		[]string{"headers", "information-disclosure", "aspnet", "fingerprinting"},
	},
	{
		"X-AspNetMvc-Version", "", modules.Info,
		"ASP.NET MVC version disclosed — assists targeted vulnerability research",
		"CWE-200", 2.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
		"Call MvcHandler.DisableMvcResponseHeader = true in Application_Start to suppress this header",
		[]string{"headers", "information-disclosure", "aspnet", "fingerprinting"},
	},
}

type Module struct {
	client    *client.Client
	seenHosts sync.Map
}

func New(c *client.Client) *Module {
	return &Module{client: c}
}

func (m *Module) Name() string { return "headers" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}
	host := u.Scheme + "://" + u.Host

	// Security header checks only need to run once per host
	if _, loaded := m.seenHosts.LoadOrStore(host, struct{}{}); loaded {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, page.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	client.DrainClose(resp)

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
		return nil, nil
	}

	var findings []modules.Finding

	// Missing security headers
	for _, c := range requiredHeaders {
		if resp.Header.Get(c.header) == "" {
			findings = append(findings, modules.Finding{
				Module:      "headers",
				Severity:    c.severity,
				URL:         page.URL,
				Param:       c.header,
				Evidence:    fmt.Sprintf("Header %q absent from response", c.header),
				Detail:      c.detail,
				CWE:         c.cwe,
				CVSS:        c.cvss,
				CVSSVector:  c.cvssVector,
				Confidence:  modules.Confirmed,
				Remediation: c.remediation,
				Tags:        c.tags,
			})
		}
	}

	// Bad header values
	for _, b := range badValueChecks {
		val := resp.Header.Get(b.header)
		if val == "" {
			continue
		}
		if b.badValue == "" || strings.EqualFold(val, b.badValue) {
			findings = append(findings, modules.Finding{
				Module:      "headers",
				Severity:    b.severity,
				URL:         page.URL,
				Param:       b.header,
				Evidence:    fmt.Sprintf("%s: %s", b.header, val),
				Detail:      b.detail,
				CWE:         b.cwe,
				CVSS:        b.cvss,
				CVSSVector:  b.cvssVector,
				Confidence:  modules.Confirmed,
				Remediation: b.remediation,
				Tags:        b.tags,
			})
		}
	}

	// Cookie security — check Set-Cookie headers
	findings = append(findings, checkCookies(resp, page.URL)...)

	return findings, nil
}

func checkCookies(resp *http.Response, pageURL string) []modules.Finding {
	u, _ := url.Parse(pageURL)
	isHTTPS := u != nil && u.Scheme == "https"

	var findings []modules.Finding

	for _, raw := range resp.Header["Set-Cookie"] {
		name := cookieName(raw)
		lower := strings.ToLower(raw)

		if isHTTPS && !strings.Contains(lower, "secure") {
			findings = append(findings, modules.Finding{
				Module:      "headers",
				Severity:    modules.Medium,
				URL:         pageURL,
				Param:       "Set-Cookie:" + name,
				Evidence:    fmt.Sprintf("Cookie %q missing Secure flag — transmitted over HTTP", name),
				Detail:      "Cookie without Secure flag — can be stolen in plaintext over unencrypted HTTP connections or by a network attacker performing TLS stripping",
				CWE:         "CWE-614",
				CVSS:        5.3,
				CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Add the Secure flag to all cookies set over HTTPS; use HSTS to prevent TLS stripping",
				Tags:        []string{"headers", "cookie", "secure-flag", "transport-security"},
			})
		}

		if !strings.Contains(lower, "httponly") {
			findings = append(findings, modules.Finding{
				Module:      "headers",
				Severity:    modules.Medium,
				URL:         pageURL,
				Param:       "Set-Cookie:" + name,
				Evidence:    fmt.Sprintf("Cookie %q missing HttpOnly flag — readable by JavaScript", name),
				Detail:      "Cookie without HttpOnly flag — accessible via document.cookie; allows session token theft in any XSS scenario",
				CWE:         "CWE-1004",
				CVSS:        5.3,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Add HttpOnly to all session and authentication cookies to prevent JavaScript access",
				Tags:        []string{"headers", "cookie", "httponly", "xss-mitigation"},
			})
		}

		if !strings.Contains(lower, "samesite") {
			findings = append(findings, modules.Finding{
				Module:      "headers",
				Severity:    modules.Low,
				URL:         pageURL,
				Param:       "Set-Cookie:" + name,
				Evidence:    fmt.Sprintf("Cookie %q missing SameSite attribute", name),
				Detail:      "Cookie without SameSite attribute — CSRF attacks may be possible; default browser behavior varies (Chrome 80+ defaults to Lax, but older browsers send cookies cross-site)",
				CWE:         "CWE-352",
				CVSS:        4.3,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Set SameSite=Strict for session cookies or SameSite=Lax as a minimum; combine with CSRF tokens for state-changing operations",
				Tags:        []string{"headers", "cookie", "samesite", "csrf"},
			})
		}

		// Warn on SameSite=None without Secure
		if strings.Contains(lower, "samesite=none") && !strings.Contains(lower, "secure") {
			findings = append(findings, modules.Finding{
				Module:      "headers",
				Severity:    modules.Medium,
				URL:         pageURL,
				Param:       "Set-Cookie:" + name,
				Evidence:    fmt.Sprintf("Cookie %q SameSite=None without Secure", name),
				Detail:      "SameSite=None requires the Secure flag per spec — modern browsers reject the cookie without it; this combination also enables cross-site sending without TLS protection",
				CWE:         "CWE-614",
				CVSS:        5.3,
				CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Add the Secure flag to any cookie using SameSite=None; reconsider whether SameSite=None is required at all",
				Tags:        []string{"headers", "cookie", "samesite-none", "transport-security"},
			})
		}
	}

	return findings
}

func cookieName(raw string) string {
	if idx := strings.Index(raw, "="); idx != -1 {
		return strings.TrimSpace(raw[:idx])
	}
	return raw
}
