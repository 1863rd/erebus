package httpmethods

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
func (m *Module) Name() string     { return "httpmethods" }

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

	// Cross-Site Tracing (XST) via TRACE
	if f := m.testTrace(ctx, page.URL); f != nil {
		findings = append(findings, *f)
	}
	if ctx.Err() != nil {
		return findings, nil
	}

	// Enumerate via OPTIONS
	allowed := m.optionsAllow(ctx, page.URL)
	if allowed != "" {
		for _, method := range []string{"PUT", "DELETE", "CONNECT", "PATCH"} {
			if !strings.Contains(strings.ToUpper(allowed), method) {
				continue
			}
			sev, detail, cwe, cvssVec, remediation, cvss, tags := riskOf(method)
			if detail == "" {
				continue
			}
			findings = append(findings, modules.Finding{
				Module:      "httpmethods",
				Severity:    sev,
				URL:         page.URL,
				Param:       "HTTP method",
				Payload:     method,
				Evidence:    fmt.Sprintf("OPTIONS → Allow: %s", allowed),
				Detail:      detail,
				CWE:         cwe,
				CVSS:        cvss,
				CVSSVector:  cvssVec,
				Confidence:  modules.Confirmed,
				Remediation: remediation,
				Tags:        tags,
			})
		}
	}

	return findings, nil
}

func (m *Module) testTrace(ctx context.Context, pageURL string) *modules.Finding {
	const canaryHeader = "X-Erebus-Trace"
	const canaryVal = "erebus_xst_9a3f"

	req, err := http.NewRequestWithContext(ctx, "TRACE", pageURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set(canaryHeader, canaryVal)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.Contains(string(body), canaryVal) {
		return &modules.Finding{
			Module:      "httpmethods",
			Severity:    modules.Medium,
			URL:         pageURL,
			Param:       "TRACE method",
			Payload:     "TRACE / HTTP/1.1",
			Evidence:    fmt.Sprintf("HTTP %d — TRACE reflected injected header %q (XST confirmed)", resp.StatusCode, canaryHeader),
			Detail:      "HTTP TRACE enabled — Cross-Site Tracing (XST) allows an attacker to read HTTP headers (including Authorization/Cookie) sent by the victim's browser when TRACE is combined with XSS",
			CWE:         "CWE-16",
			CVSS:        5.4,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Disable TRACE method in the web server configuration (Apache: TraceEnable Off; nginx: limit_except; IIS: custom verb restriction)",
			Tags:        []string{"httpmethods", "trace", "xst", "header-exposure"},
		}
	}
	return nil
}

func (m *Module) optionsAllow(ctx context.Context, pageURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, pageURL, nil)
	if err != nil {
		return ""
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return ""
	}
	client.DrainClose(resp)
	return resp.Header.Get("Allow")
}

func riskOf(method string) (sev modules.Severity, detail, cwe, cvssVec, remediation string, cvss float64, tags []string) {
	switch method {
	case "PUT":
		return modules.High,
			"HTTP PUT enabled — arbitrary file upload/overwrite may be possible on this endpoint",
			"CWE-650",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			"Disable the PUT method unless explicitly required; enforce authentication and path restrictions before accepting PUT requests",
			7.5,
			[]string{"httpmethods", "put", "file-upload", "broken-access-control"}
	case "DELETE":
		return modules.High,
			"HTTP DELETE enabled — resource deletion by unauthenticated or low-privileged clients",
			"CWE-650",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
			"Disable the DELETE method unless required; enforce strict authorization before accepting DELETE requests",
			8.2,
			[]string{"httpmethods", "delete", "broken-access-control"}
	case "CONNECT":
		return modules.Medium,
			"HTTP CONNECT enabled — server may be usable as an HTTP tunnel or proxy to reach internal hosts",
			"CWE-918",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
			"Disable the CONNECT method on application servers; restrict proxy functionality to dedicated systems",
			6.1,
			[]string{"httpmethods", "connect", "ssrf", "proxy-abuse"}
	case "PATCH":
		return modules.Low,
			"HTTP PATCH enabled — partial resource modification is allowed; verify authorization controls are enforced",
			"CWE-284",
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
			"Ensure PATCH requests are subject to the same authorization checks as PUT; validate partial update payloads",
			4.3,
			[]string{"httpmethods", "patch", "broken-access-control"}
	}
	return modules.Info, "", "", "", "", 0, nil
}
