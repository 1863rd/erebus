package hostheader

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

const attackerHost = "erebus-hhi-test.invalid"

var resetPaths = []string{
	"/password-reset", "/forgot-password", "/reset-password", "/account/password",
	"/api/password-reset", "/auth/reset", "/user/forgot", "/users/password",
	"/api/v1/auth/reset-password", "/api/v2/auth/reset-password",
	"/forgot", "/reset", "/recover",
}

type Module struct {
	client    *client.Client
	seenHosts sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "hostheader" }

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

	if f := m.testReflection(ctx, page.URL, u.Host); f != nil {
		findings = append(findings, *f)
	}
	if f := m.testXForwardedHost(ctx, page.URL); f != nil {
		findings = append(findings, *f)
	}
	for _, path := range resetPaths {
		if ctx.Err() != nil {
			break
		}
		findings = append(findings, m.testPasswordReset(ctx, host, path)...)
	}
	if f := m.testAmbiguousHost(ctx, page.URL, u.Host); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

func (m *Module) testReflection(ctx context.Context, pageURL, originalHost string) *modules.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	req.Host = attackerHost
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := client.ReadBody(resp)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, attackerHost) {
		return nil
	}

	reflectCtx := detectReflectContext(bodyStr, attackerHost)
	sev := modules.Medium
	if reflectCtx == "href" || reflectCtx == "action" || reflectCtx == "src" {
		sev = modules.High
	}

	return &modules.Finding{
		Module:   "hostheader",
		Severity: sev,
		URL:      pageURL,
		Param:    "Host",
		Payload:  attackerHost,
		Evidence: fmt.Sprintf("Injected Host %q reflected in response (context: %s) — HTTP %d",
			attackerHost, reflectCtx, resp.StatusCode),
		Detail: "Host header injection: the application constructs absolute URLs from the Host header without " +
			"validation. An attacker controlling the Host header can inject an attacker-controlled domain into " +
			"links, enabling password reset poisoning, open redirects, and web cache poisoning.",
		CWE:         "CWE-113",
		CVSS:        hostCVSS(sev),
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
		Confidence:  modules.Confirmed,
		Remediation: "Use a hardcoded trusted origin for URL generation; validate the Host header against an ALLOWED_HOSTS whitelist",
		Tags:        []string{"host-header-injection", "password-reset-poisoning", "cache-poisoning"},
	}
}

func (m *Module) testXForwardedHost(ctx context.Context, pageURL string) *modules.Finding {
	for _, header := range []string{"X-Forwarded-Host", "X-Host", "X-HTTP-Host-Override", "Forwarded"} {
		if ctx.Err() != nil {
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		if header == "Forwarded" {
			req.Header.Set(header, "host="+attackerHost)
		} else {
			req.Header.Set(header, attackerHost)
		}
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)

		if strings.Contains(string(body), attackerHost) {
			return &modules.Finding{
				Module:   "hostheader",
				Severity: modules.High,
				URL:      pageURL,
				Param:    header,
				Payload:  attackerHost,
				Evidence: fmt.Sprintf("Injected %s: %s reflected in response — HTTP %d", header, attackerHost, resp.StatusCode),
				Detail: fmt.Sprintf("Host override header injection via %s: the application trusts %s to determine "+
					"its own hostname, allowing external control of generated URLs. Enables password reset poisoning, "+
					"cache poisoning, and SSRF via internal routing.", header, header),
				CWE:         "CWE-113",
				CVSS:        7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Only trust X-Forwarded-Host from verified reverse proxies; validate the effective host against an ALLOWED_HOSTS list",
				Tags:        []string{"host-header-injection", "x-forwarded-host", "cache-poisoning"},
			}
		}
	}
	return nil
}

func (m *Module) testPasswordReset(ctx context.Context, host, path string) []modules.Finding {
	var findings []modules.Finding
	testURL := host + path

	// Step 1: baseline request without any Host manipulation.
	// If the endpoint doesn't exist or returns HTML (SPA catch-all), skip entirely.
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodPost, testURL, strings.NewReader("email=test@erebus.invalid"))
	if err != nil {
		return nil
	}
	baseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	baseResp, err := m.client.Do(baseReq)
	if err != nil {
		return nil
	}
	baseBody, _ := client.ReadBody(baseResp)

	// Endpoint doesn't exist or rejects the method.
	if baseResp.StatusCode == 404 || baseResp.StatusCode == 405 || baseResp.StatusCode == 410 {
		return nil
	}
	// SPA catch-all: HTML responses are frontend routes, not real API endpoints.
	if isHTMLBody(baseResp.Header.Get("Content-Type"), baseBody) {
		return nil
	}
	// Server errors don't confirm the endpoint exists.
	if baseResp.StatusCode >= 500 {
		return nil
	}

	// Step 2: same request with poisoned Host header.
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, testURL, strings.NewReader("email=test@erebus.invalid"))
	if err != nil {
		return nil
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Host = attackerHost
	resp2, err := m.client.Do(req2)
	if err != nil {
		return nil
	}
	body2, _ := client.ReadBody(resp2)
	body2Str := string(body2)

	// Skip HTML responses from the poisoned request too.
	if isHTMLBody(resp2.Header.Get("Content-Type"), body2) {
		return nil
	}

	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		return nil
	}

	if strings.Contains(body2Str, attackerHost) {
		// Attacker domain is reflected in the response body — the reset link URL is built
		// from the Host header and will appear in the outgoing email. Confirmed poisoning.
		findings = append(findings, modules.Finding{
			Module:   "hostheader",
			Severity: modules.Critical,
			URL:      testURL,
			Param:    "Host",
			Payload:  attackerHost,
			Evidence: fmt.Sprintf("Poisoned Host %q reflected in response body (HTTP %d) — reset link will contain attacker domain",
				attackerHost, resp2.StatusCode),
			Detail: "Password reset poisoning confirmed: the reset endpoint reflects the forged Host header in the response, " +
				"indicating the password reset link is constructed from the Host header. Any victim triggering a reset " +
				"will receive an email with a link pointing to the attacker's domain — full account takeover without any further interaction.",
			CWE:         "CWE-640",
			CVSS:        9.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Confidence:  modules.Confirmed,
			Remediation: "Hardcode the base URL in application config; never construct reset links from the Host header; enforce ALLOWED_HOSTS validation",
			Tags:        []string{"host-header-injection", "password-reset-poisoning", "account-takeover"},
		})
	} else {
		// Endpoint accepted the poisoned request but didn't reflect the host in the response.
		// Without OOB callback (e.g. Burp Collaborator), poisoning is unconfirmed.
		// The email may still contain the attacker domain — manual verification required.
		findings = append(findings, modules.Finding{
			Module:   "hostheader",
			Severity: modules.Medium,
			URL:      testURL,
			Param:    "Host",
			Payload:  attackerHost,
			Evidence: fmt.Sprintf("Password reset endpoint accepted POST with forged Host %q (HTTP %d) — OOB verification required to confirm email poisoning",
				attackerHost, resp2.StatusCode),
			Detail: "Potential password reset poisoning: the reset endpoint accepted a POST request with a forged Host header. " +
				"The server did not reflect the attacker domain in the response body, so poisoning cannot be confirmed " +
				"without out-of-band callback verification (e.g. Burp Collaborator). Manual testing recommended.",
			CWE:         "CWE-640",
			CVSS:        5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Confidence:  modules.Potential,
			Remediation: "Hardcode the base URL in application config; never construct reset links from the Host header; enforce ALLOWED_HOSTS validation",
			Tags:        []string{"host-header-injection", "password-reset-poisoning"},
		})
	}

	return findings
}

func (m *Module) testAmbiguousHost(ctx context.Context, pageURL, originalHost string) *modules.Finding {
	for _, variant := range []string{
		originalHost + ":443@" + attackerHost,
		originalHost + " " + attackerHost,
	} {
		if ctx.Err() != nil {
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Host = variant
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)

		if strings.Contains(string(body), attackerHost) {
			return &modules.Finding{
				Module:   "hostheader",
				Severity: modules.High,
				URL:      pageURL,
				Param:    "Host",
				Payload:  variant,
				Evidence: fmt.Sprintf("Ambiguous Host %q — attacker domain reflected in response", variant),
				Detail:   "Host header ambiguity bypass: a malformed Host combining the legitimate host and attacker domain caused the attacker domain to be reflected. Routing and authorization code may disagree on which host was requested.",
				CWE:         "CWE-113",
				CVSS:        7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Normalize and validate the Host header on ingress; reject requests with malformed or ambiguous Host values; use strict server-name binding",
				Tags:        []string{"host-header-injection", "host-ambiguity"},
			}
		}
	}
	return nil
}

// isHTMLBody returns true when the response is an HTML document rather than API data.
func isHTMLBody(ct string, body []byte) bool {
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return true
	}
	if len(body) == 0 {
		return false
	}
	peek := strings.TrimSpace(strings.ToLower(string(body[:minInt(100, len(body))])))
	return strings.HasPrefix(peek, "<!doctype html") || strings.HasPrefix(peek, "<html")
}

func detectReflectContext(body, needle string) string {
	idx := strings.Index(body, needle)
	if idx < 0 {
		return "body"
	}
	before := ""
	if idx > 20 {
		before = body[idx-20 : idx]
	}
	switch {
	case strings.Contains(before, "href=") || strings.Contains(before, "href ="):
		return "href"
	case strings.Contains(before, "src=") || strings.Contains(before, "src ="):
		return "src"
	case strings.Contains(before, "action="):
		return "action"
	case strings.Contains(before, "url("):
		return "css-url"
	default:
		return "body"
	}
}

func hostCVSS(sev modules.Severity) float64 {
	switch sev {
	case modules.Critical:
		return 9.8
	case modules.High:
		return 7.5
	default:
		return 5.3
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
