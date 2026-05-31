// Package oauth detects OAuth 2.0 / OpenID Connect implementation weaknesses.
// Tested: open redirect in redirect_uri, missing/predictable state parameter,
// token leakage via Referer, implicit flow token in fragment, PKCE downgrade.
package oauth

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

const attackerDomain = "evil.erebus-oauth-test.invalid"

var oauthPaths = []string{
	"/oauth/authorize", "/oauth2/authorize", "/authorize", "/auth/authorize",
	"/login/oauth/authorize", "/connect/authorize", "/oidc/authorize",
	"/v1/authorize", "/v2/authorize", "/api/oauth/authorize",
}

type Module struct {
	client    *client.Client
	seenHosts sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "oauth" }

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

	// Discover OAuth endpoints from page body and well-known
	endpoints := m.discoverEndpoints(ctx, host, page)

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}
		findings = append(findings, m.auditEndpoint(ctx, host, ep)...)
	}

	// Check for token leakage in current page URL fragment / query
	findings = append(findings, m.checkTokenLeakage(page)...)

	return findings, nil
}

func (m *Module) discoverEndpoints(ctx context.Context, host string, page crawler.Page) []string {
	seen := make(map[string]struct{})
	var eps []string

	add := func(ep string) {
		if _, ok := seen[ep]; !ok {
			seen[ep] = struct{}{}
			eps = append(eps, ep)
		}
	}

	// Well-known OpenID config
	oidcURL := host + "/.well-known/openid-configuration"
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcURL, nil); err == nil {
		if resp, err := m.client.Do(req); err == nil {
			body, _ := client.ReadBody(resp)
			if ep := extractJSONString(string(body), "authorization_endpoint"); ep != "" {
				add(ep)
			}
			if ep := extractJSONString(string(body), "token_endpoint"); ep != "" {
				add(ep)
			}
		}
	}

	// Probe known OAuth paths
	for _, path := range oauthPaths {
		add(host + path)
	}

	// Extract OAuth-looking URLs from page body
	body := string(page.Body)
	for _, line := range strings.Split(body, "\n") {
		if !strings.Contains(line, "client_id") && !strings.Contains(line, "response_type") {
			continue
		}
		if u, err := url.Parse(strings.Trim(strings.Fields(line)[0], `"'`)); err == nil && u.Host != "" {
			add(u.Scheme + "://" + u.Host + u.Path)
		}
	}

	// OAuth links in crawled page
	for _, link := range page.Links {
		if isOAuthURL(link) {
			if u, err := url.Parse(link); err == nil {
				add(u.Scheme + "://" + u.Host + u.Path)
			}
		}
	}

	return eps
}

func (m *Module) auditEndpoint(ctx context.Context, host, endpoint string) []modules.Finding {
	var findings []modules.Finding

	// Fetch the authorize endpoint to discover real params
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := client.ReadBody(resp)

	// Build base params (discovered or synthetic)
	params := extractOAuthParams(endpoint, string(body), resp.Header)
	if params.Get("client_id") == "" {
		params.Set("client_id", "erebus_test_client")
	}
	if params.Get("response_type") == "" {
		params.Set("response_type", "code")
	}
	originalRedirectURI := params.Get("redirect_uri")
	if originalRedirectURI == "" {
		originalRedirectURI = host + "/callback"
		params.Set("redirect_uri", originalRedirectURI)
	}

	// Test 1: redirect_uri — replace host with attacker domain
	if f := m.testRedirectURIHijack(ctx, endpoint, params, host, originalRedirectURI); f != nil {
		findings = append(findings, *f)
	}

	// Test 2: redirect_uri — path traversal variants
	findings = append(findings, m.testRedirectURIVariants(ctx, endpoint, params, host, originalRedirectURI)...)

	// Test 3: missing state parameter (CSRF)
	if f := m.testMissingState(ctx, endpoint, params); f != nil {
		findings = append(findings, *f)
	}

	// Test 4: implicit flow — token in URL
	if f := m.testImplicitFlow(ctx, endpoint, params); f != nil {
		findings = append(findings, *f)
	}

	// Test 5: PKCE downgrade
	findings = append(findings, m.testPKCEDowngrade(ctx, endpoint, params)...)

	return findings
}

func (m *Module) testRedirectURIHijack(ctx context.Context, endpoint string, params url.Values, host, origRedirect string) *modules.Finding {
	p := cloneValues(params)
	p.Set("redirect_uri", "https://"+attackerDomain+"/callback")

	testURL := endpoint + "?" + p.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	client.DrainClose(resp)

	if isOAuthRedirectAccepted(resp, attackerDomain) {
		return &modules.Finding{
			Module:  "oauth",
			Severity: modules.Critical,
			URL:     endpoint,
			Param:   "redirect_uri",
			Payload: "https://" + attackerDomain + "/callback",
			Evidence: fmt.Sprintf("OAuth redirect_uri accepted external domain (%s) → HTTP %d — authorization code may be delivered to attacker",
				attackerDomain, resp.StatusCode),
			Detail:      "OAuth redirect_uri hijacking: the authorization server accepts an attacker-controlled redirect URI. An attacker can redirect the victim's authorization code to their own server, then exchange it for tokens — full account takeover without any user interaction beyond clicking the OAuth login link.",
			CWE:         "CWE-601",
			CVSS:        9.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Enforce exact redirect_uri matching against a pre-registered allowlist; reject any URI not previously registered for the client_id; never allow wildcards or pattern matching in redirect URIs",
			Tags:        []string{"oauth", "redirect-uri", "account-takeover", "oidc"},
		}
	}
	return nil
}

func (m *Module) testRedirectURIVariants(ctx context.Context, endpoint string, params url.Values, host, origRedirect string) []modules.Finding {
	parsed, err := url.Parse(origRedirect)
	if err != nil {
		return nil
	}

	variants := []struct {
		uri    string
		attack string
	}{
		{
			// subdomain confusion: legitimate.com.evil.com
			"https://" + parsed.Host + "." + attackerDomain + "/callback",
			"subdomain confusion",
		},
		{
			// path traversal: legitimate.com/../../evil
			parsed.Scheme + "://" + parsed.Host + "/callback/../../../erebus",
			"path traversal",
		},
		{
			// open redirect chaining
			origRedirect + "?next=https://" + attackerDomain,
			"open redirect chaining",
		},
		{
			// at-sign trick: user@attacker.com
			"https://legitimate@" + attackerDomain + "/callback",
			"@-sign bypass",
		},
	}

	var findings []modules.Finding
	for _, v := range variants {
		if ctx.Err() != nil {
			break
		}
		p := cloneValues(params)
		p.Set("redirect_uri", v.uri)
		testURL := endpoint + "?" + p.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			continue
		}
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		client.DrainClose(resp)

		if isOAuthRedirectAccepted(resp, attackerDomain) {
			findings = append(findings, modules.Finding{
				Module:  "oauth",
				Severity: modules.High,
				URL:     endpoint,
				Param:   "redirect_uri",
				Payload: v.uri,
				Evidence: fmt.Sprintf("OAuth redirect_uri variant accepted (%s technique) → HTTP %d", v.attack, resp.StatusCode),
				Detail: fmt.Sprintf("OAuth redirect_uri bypass via %s: the authorization server does not correctly validate the redirect URI. "+
					"Attacker can abuse %s to exfiltrate authorization codes.", v.attack, v.attack),
				CWE:         "CWE-601",
				CVSS:        8.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Enforce exact redirect_uri matching against a pre-registered allowlist; reject any URI not previously registered for the client_id",
				Tags:        []string{"oauth", "redirect-uri-bypass", v.attack},
			})
			break
		}
	}
	return findings
}

func (m *Module) testMissingState(ctx context.Context, endpoint string, params url.Values) *modules.Finding {
	hasState := params.Get("state") != ""

	p := cloneValues(params)
	p.Del("state")
	testURL := endpoint + "?" + p.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := client.ReadBody(resp)

	// Flag whenever the server accepts a stateless request with 2xx/3xx —
	// regardless of whether the original had a state param.
	// SPA catch-all HTML responses are excluded (they don't represent real auth endpoints).
	if resp.StatusCode >= 200 && resp.StatusCode < 400 && !isHTMLBody(body) {
		_ = hasState // consumed above
		return &modules.Finding{
			Module:  "oauth",
			Severity: modules.Medium,
			URL:     endpoint,
			Param:   "state",
			Payload: "(state parameter omitted)",
			Evidence: fmt.Sprintf("OAuth authorization endpoint accepted request without state parameter → HTTP %d — CSRF attack possible", resp.StatusCode),
			Detail: "Missing OAuth state parameter: the authorization server does not require or validate the 'state' parameter. " +
				"An attacker can perform a CSRF attack by tricking a victim into authorizing the attacker's application — " +
				"the attacker then links/binds their account or hijacks the victim's OAuth session.",
			CWE:         "CWE-352",
			CVSS:        6.5,
			Confidence:  modules.Likely,
			Remediation: "Require the state parameter on all authorization requests; validate it server-side against the session before accepting the callback; use cryptographically random values",
			Tags:        []string{"oauth", "csrf", "state", "oidc"},
		}
	}
	return nil
}

func (m *Module) testImplicitFlow(ctx context.Context, endpoint string, params url.Values) *modules.Finding {
	p := cloneValues(params)
	p.Set("response_type", "token")
	testURL := endpoint + "?" + p.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	loc := resp.Header.Get("Location")
	client.DrainClose(resp)

	if strings.Contains(loc, "access_token=") || strings.Contains(loc, "#access_token") {
		return &modules.Finding{
			Module:  "oauth",
			Severity: modules.High,
			URL:     endpoint,
			Param:   "response_type",
			Payload: "token",
			Evidence: fmt.Sprintf("Implicit flow accepted: access_token delivered in Location redirect fragment — HTTP %d", resp.StatusCode),
			Detail: "OAuth implicit flow enabled: access tokens are delivered directly in URL fragments, which are accessible " +
				"to JavaScript, logged in browser history, and may leak via Referer headers. The implicit flow is deprecated " +
				"in OAuth 2.1 due to these token leakage risks.",
			CWE:        "CWE-200",
			CVSS:       6.5,
			Confidence: modules.Confirmed,
			Tags:       []string{"oauth", "implicit-flow", "token-leakage"},
		}
	}
	return nil
}

func (m *Module) testPKCEDowngrade(ctx context.Context, endpoint string, params url.Values) []modules.Finding {
	var findings []modules.Finding

	// Test 1: PKCE code_challenge_method=plain (weak)
	p := cloneValues(params)
	p.Set("code_challenge", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	p.Set("code_challenge_method", "plain")
	testURL := endpoint + "?" + p.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err == nil {
		if resp, err := m.client.Do(req); err == nil {
			client.DrainClose(resp)
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				findings = append(findings, modules.Finding{
					Module:   "oauth",
					Severity: modules.Medium,
					URL:      endpoint,
					Param:    "code_challenge_method",
					Payload:  "plain",
					Evidence: fmt.Sprintf("PKCE 'plain' method accepted → HTTP %d — code verifier is trivially guessable from challenge", resp.StatusCode),
					Detail:   "PKCE downgrade to 'plain' method: the authorization server accepts code_challenge_method=plain, which provides no protection since the code_verifier equals the code_challenge. Only S256 provides meaningful PKCE security.",
					CWE:         "CWE-327",
					CVSS:        5.9,
					CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
					Confidence:  modules.Potential,
					Remediation: "Reject code_challenge_method=plain; require S256 exclusively; validate that the code_verifier matches the stored code_challenge using SHA-256",
					Tags:        []string{"oauth", "pkce", "downgrade"},
				})
			}
		}
	}

	// Test 2: PKCE bypass — send code without challenge
	p2 := cloneValues(params)
	p2.Del("code_challenge")
	p2.Del("code_challenge_method")
	testURL2 := endpoint + "?" + p2.Encode()
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL2, nil)
	if err == nil {
		if resp2, err := m.client.Do(req2); err == nil {
			client.DrainClose(resp2)
			if resp2.StatusCode >= 200 && resp2.StatusCode < 400 {
				findings = append(findings, modules.Finding{
					Module:   "oauth",
					Severity: modules.High,
					URL:      endpoint,
					Param:    "code_challenge",
					Payload:  "(omitted)",
					Evidence: fmt.Sprintf("Authorization code flow accepted without PKCE code_challenge → HTTP %d", resp2.StatusCode),
					Detail:   "PKCE not enforced: the authorization server allows authorization code requests without a PKCE code_challenge. Authorization codes are susceptible to interception attacks (mobile apps, public clients). RFC 9700 requires PKCE for all public clients.",
					CWE:         "CWE-287",
					CVSS:        7.4,
					CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
					Confidence:  modules.Confirmed,
					Remediation: "Enforce PKCE for all public clients (RFC 9700); reject authorization code requests without code_challenge; store and verify the challenge at the token exchange step",
					Tags:        []string{"oauth", "pkce-bypass", "auth-code"},
				})
			}
		}
	}

	return findings
}

func (m *Module) checkTokenLeakage(page crawler.Page) []modules.Finding {
	var findings []modules.Finding

	u, err := url.Parse(page.URL)
	if err != nil {
		return nil
	}

	// Token in URL query
	q := u.Query()
	if token := q.Get("access_token"); token != "" {
		findings = append(findings, modules.Finding{
			Module:   "oauth",
			Severity: modules.Critical,
			URL:      page.URL,
			Param:    "access_token",
			Evidence: fmt.Sprintf("OAuth access_token exposed in URL query string: %s…", truncate(token, 30)),
			Detail:   "OAuth access token transmitted in URL query string — tokens in URLs are logged by web servers, proxy servers, and browser history. They may leak via Referer header when the page links to third-party resources.",
			CWE:         "CWE-598",
			CVSS:        8.0,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Never include access tokens in URL query strings; use Authorization header with Bearer scheme; set short token TTLs and revoke on logout",
			Tags:        []string{"oauth", "token-leakage", "url-exposure"},
		})
	}

	// Token in URL fragment (access_token=#... for implicit flow)
	if strings.Contains(page.URL, "#access_token=") || strings.Contains(page.URL, "access_token=") {
		if strings.Contains(page.URL, "#") {
			findings = append(findings, modules.Finding{
				Module:   "oauth",
				Severity: modules.High,
				URL:      page.URL,
				Param:    "fragment",
				Evidence: "OAuth access_token in URL fragment — JavaScript-accessible, logged in browser history",
				Detail:   "OAuth implicit flow: access token delivered in URL fragment. Fragment tokens are accessible to JavaScript on the page and recorded in browser history. Prefer authorization code flow with PKCE.",
				CWE:         "CWE-598",
				CVSS:        7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Migrate from implicit flow to authorization code flow with PKCE; never use the implicit grant type for new applications (deprecated in OAuth 2.1)",
				Tags:        []string{"oauth", "implicit-flow", "token-in-fragment"},
			})
		}
	}

	return findings
}

func isOAuthURL(rawURL string) bool {
	low := strings.ToLower(rawURL)
	return strings.Contains(low, "oauth") || strings.Contains(low, "authorize") ||
		strings.Contains(low, "client_id") || strings.Contains(low, "response_type")
}

func isOAuthRedirectAccepted(resp *http.Response, attackerDomain string) bool {
	if resp == nil {
		return false
	}
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, attackerDomain) {
		return true
	}
	if resp.StatusCode == 302 || resp.StatusCode == 301 || resp.StatusCode == 303 {
		if strings.Contains(loc, "code=") || strings.Contains(loc, "token=") {
			if strings.Contains(loc, attackerDomain) {
				return true
			}
		}
	}
	return false
}

func extractOAuthParams(endpoint, body string, headers http.Header) url.Values {
	params := make(url.Values)

	// From URL itself
	if u, err := url.Parse(endpoint); err == nil {
		for k, vs := range u.Query() {
			if len(vs) > 0 {
				params.Set(k, vs[0])
			}
		}
	}

	// From body: look for hidden inputs or JS assignments
	for _, field := range []string{"client_id", "response_type", "redirect_uri", "scope", "state", "nonce"} {
		if val := extractHTMLHidden(body, field); val != "" {
			params.Set(field, val)
		}
	}

	return params
}

func extractHTMLHidden(body, name string) string {
	needle := `name="` + name + `"`
	idx := strings.Index(body, needle)
	if idx < 0 {
		needle = `name='` + name + `'`
		idx = strings.Index(body, needle)
	}
	if idx < 0 {
		return ""
	}
	chunk := body[idx:]
	vi := strings.Index(chunk, `value="`)
	if vi < 0 {
		vi = strings.Index(chunk, `value='`)
		if vi < 0 {
			return ""
		}
		end := strings.Index(chunk[vi+7:], "'")
		if end < 0 {
			return ""
		}
		return chunk[vi+7 : vi+7+end]
	}
	end := strings.Index(chunk[vi+7:], `"`)
	if end < 0 {
		return ""
	}
	return chunk[vi+7 : vi+7+end]
}

func extractJSONString(body, key string) string {
	needle := `"` + key + `"`
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(needle):]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	end := strings.Index(rest[1:], `"`)
	if end < 0 {
		return ""
	}
	return rest[1 : end+1]
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

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
