package deserialization

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

// Java ObjectOutputStream magic bytes: 0xaced 0x0005 → base64 "rO0AB"
// .NET BinaryFormatter magic: 0x00 0x01 0x00 0x00 0x00 → base64 "AAEAAAD"
// PHP serialize format: O:<len>:"<classname>":...
// Python pickle protocol 2+: \x80\x02 → base64 starts with "gASV"

var (
	reJavaSerial  = regexp.MustCompile(`rO0AB[A-Za-z0-9+/=]{20,}`)
	reDotNetSerial = regexp.MustCompile(`AAEAAAD[A-Za-z0-9+/=]{20,}`)
	rePHPSerial   = regexp.MustCompile(`O:\d{1,5}:"[a-zA-Z_\\][a-zA-Z0-9_\\]*":\d+:\{`)
	rePickle      = regexp.MustCompile(`gASV[A-Za-z0-9+/=]{10,}`) // pickle protocol 4 base64

	// Java serialization error messages
	reJavaError = regexp.MustCompile(`(?i)(ClassNotFoundException|InvalidClassException|NotSerializableException|ObjectStreamException|serialVersionUID|readObject\(\)|deserializ|java\.io\.Serializ)`)
	rePHPError  = regexp.MustCompile(`(?i)(unserialize\(\)|__wakeup|__destruct|O:\d+:|PHP Warning.*unserialize)`)
	reDotNetErr = regexp.MustCompile(`(?i)(BinaryFormatter|NetDataContractSerializer|ObjectStateFormatter|LosFormatter|TypeFilterLevel|deserializ)`)
)

// Benign malformed payloads that trigger deserialization errors without executing gadgets
var probePayloads = []struct {
	name    string
	payload string
	ctype   string
}{
	{
		"java-serial-truncated",
		base64.StdEncoding.EncodeToString([]byte{0xac, 0xed, 0x00, 0x05, 0x73, 0x72, 0x00, 0x00}),
		"application/x-java-serialized-object",
	},
	{
		"php-serial-truncated",
		`O:8:"stdClass":1:{s:4:"test";s:5:"probe";}`,
		"application/x-www-form-urlencoded",
	},
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "deserialization" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	findings = append(findings, m.scanPassive(page)...)
	if ctx.Err() == nil {
		findings = append(findings, m.probeEndpoints(ctx, page)...)
	}
	return findings, nil
}

// scanPassive looks for serialized object signatures in response body, cookies, and headers.
func (m *Module) scanPassive(page crawler.Page) []modules.Finding {
	var findings []modules.Finding
	body := string(page.Body)

	type sig struct {
		name    string
		re      *regexp.Regexp
		detail  string
		cwe     string
		cvss    float64
		vector  string
		tags    []string
	}

	sigs := []sig{
		{
			"Java serialized object",
			reJavaSerial,
			"Java serialized object (base64) detected in response — if this value is deserialized server-side without type restriction, it enables Remote Code Execution via gadget chains (e.g. CommonsCollections, Spring, Groovy)",
			"CWE-502", 9.8,
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			[]string{"deserialization", "java", "rce-risk"},
		},
		{
			".NET BinaryFormatter object",
			reDotNetSerial,
			".NET BinaryFormatter/NetDataContractSerializer serialized object detected — these serializers are known-unsafe and enable RCE via type confusion gadget chains",
			"CWE-502", 9.8,
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			[]string{"deserialization", "dotnet", "rce-risk"},
		},
		{
			"PHP serialized object",
			rePHPSerial,
			"PHP serialize() format detected in response — if deserialized with user input, attackers can trigger __wakeup/__destruct gadget chains for RCE or object injection",
			"CWE-502", 8.8,
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			[]string{"deserialization", "php", "rce-risk"},
		},
		{
			"Python pickle object",
			rePickle,
			"Python pickle data (base64) detected — pickle.loads() executes arbitrary code; if user-supplied data is pickled/unpickled, it enables direct RCE",
			"CWE-502", 9.8,
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			[]string{"deserialization", "python", "pickle", "rce-risk"},
		},
	}

	for _, s := range sigs {
		match := s.re.FindString(body)
		if match == "" {
			// Also scan cookie values
			for _, setCookie := range page.Headers["Set-Cookie"] {
				if m2 := s.re.FindString(setCookie); m2 != "" {
					match = m2
					break
				}
			}
		}
		if match == "" {
			continue
		}
		extracted := match
		if len(extracted) > 100 {
			extracted = extracted[:100] + "..."
		}
		findings = append(findings, modules.Finding{
			Module:      "deserialization",
			Severity:    modules.Critical,
			URL:         page.URL,
			Param:       "response body / cookie",
			Payload:     "",
			Evidence:    fmt.Sprintf("%s signature found: %q", s.name, extracted),
			Detail:      s.detail,
			CWE:         s.cwe,
			CVSS:        s.cvss,
			CVSSVector:  s.vector,
			Confidence:  modules.Confirmed,
			Remediation: "Replace unsafe serializers with safe alternatives (JSON, protobuf, MessagePack); if serialization is required, use allow-lists for permitted types and sign/encrypt serialized data",
			Tags:        s.tags,
			Extracted:   extracted,
		})
	}

	// Check for deserialization error messages in response
	for _, errRe := range []*regexp.Regexp{reJavaError, rePHPError, reDotNetErr} {
		if m2 := errRe.FindString(body); m2 != "" {
			findings = append(findings, modules.Finding{
				Module:     "deserialization",
				Severity:   modules.Medium,
				URL:        page.URL,
				Param:      "response body",
				Evidence:   fmt.Sprintf("Deserialization framework keyword in response: %q", m2),
				Detail:     "Deserialization-related error or class name exposed in response — server may be deserializing user-controlled data",
				CWE:         "CWE-502",
				CVSS:        5.3,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				Confidence:  modules.Potential,
				Remediation: "Catch and suppress deserialization exceptions; return generic error messages to clients; log full details server-side only",
				Tags:        []string{"deserialization", "info-disclosure"},
			})
			break
		}
	}

	return findings
}

// probeEndpoints injects malformed serialized objects into parameters to trigger error messages.
func (m *Module) probeEndpoints(ctx context.Context, page crawler.Page) []modules.Finding {
	var findings []modules.Finding

	u, err := url.Parse(page.URL)
	if err != nil {
		return nil
	}

	for _, probe := range probePayloads {
		if ctx.Err() != nil {
			break
		}

		// Inject into all query parameters
		for k := range u.Query() {
			if ctx.Err() != nil {
				break
			}
			q := u.Query()
			q.Set(k, probe.payload)
			cu := *u
			cu.RawQuery = q.Encode()

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
			bodyStr := string(body)

			for _, errRe := range []*regexp.Regexp{reJavaError, rePHPError, reDotNetErr} {
				if match := errRe.FindString(bodyStr); match != "" {
					findings = append(findings, modules.Finding{
						Module:      "deserialization",
						Severity:    modules.High,
						URL:         cu.String(),
						Param:       k,
						Payload:     probe.name + " probe",
						Evidence:    fmt.Sprintf("Deserialization error triggered: %q in response after injecting %s", match, probe.name),
						Detail:      fmt.Sprintf("Insecure deserialization: parameter %q is deserialized server-side — injecting a malformed %s object triggers a deserialization exception, confirming the code path", k, probe.name),
						CWE:         "CWE-502",
						CVSS:        9.8,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Confidence:  modules.Likely,
						Remediation: "Replace unsafe serializers; validate and sign serialized data; use deserialization firewalls (e.g. SerialKiller for Java)",
						Tags:        []string{"deserialization", probe.name, "active-probe"},
					})
					goto nextParam
				}
			}
		nextParam:
		}

		// Also inject into cookies
		for _, ck := range page.Headers["Set-Cookie"] {
			if ctx.Err() != nil {
				break
			}
			cookieName := extractCookieName(ck)
			if cookieName == "" {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, page.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Cookie", cookieName+"="+probe.payload)
			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}
			body, err := client.ReadBody(resp)
			if err != nil {
				continue
			}
			bodyStr := string(body)

			for _, errRe := range []*regexp.Regexp{reJavaError, rePHPError, reDotNetErr} {
				if match := errRe.FindString(bodyStr); match != "" {
					findings = append(findings, modules.Finding{
						Module:      "deserialization",
						Severity:    modules.High,
						URL:         page.URL,
						Param:       "cookie:" + cookieName,
						Payload:     probe.name,
						Evidence:    fmt.Sprintf("Deserialization error %q after injecting %s into cookie %s", match, probe.name, cookieName),
						Detail:      fmt.Sprintf("Insecure deserialization via cookie %q — server deserializes cookie value without validation", cookieName),
						CWE:         "CWE-502",
						CVSS:        9.8,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Confidence:  modules.Likely,
						Remediation: "Replace unsafe serializers with safe alternatives (JSON, protobuf); sign/encrypt serialized cookies; implement a deserialization firewall to restrict allowed types",
						Tags:        []string{"deserialization", "cookie", probe.name},
					})
					break
				}
			}
		}

		// POST body probe for JSON APIs
		if len(page.JSONParams) > 0 {
			reqBody := `{"data":"` + probe.payload + `"}`
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, page.URL, bytes.NewBufferString(reqBody))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}
			body, err := client.ReadBody(resp)
			if err != nil {
				continue
			}
			bodyStr := string(body)
			for _, errRe := range []*regexp.Regexp{reJavaError, rePHPError, reDotNetErr} {
				if match := errRe.FindString(bodyStr); match != "" {
					findings = append(findings, modules.Finding{
						Module:     "deserialization",
						Severity:   modules.High,
						URL:        page.URL,
						Param:      "json-body:data",
						Payload:    probe.name,
						Evidence:   fmt.Sprintf("Deserialization error %q after JSON body probe", match),
						Detail:     "Insecure deserialization in JSON API endpoint",
						CWE:         "CWE-502",
						CVSS:        9.8,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Confidence:  modules.Likely,
						Remediation: "Replace unsafe deserializers with safe alternatives (JSON schema validation); never deserialize user-supplied data with Java ObjectInputStream, PHP unserialize, or pickle",
						Tags:        []string{"deserialization", "json", probe.name},
					})
					break
				}
			}
		}
	}
	return findings
}

func extractCookieName(setCookie string) string {
	if idx := strings.Index(setCookie, "="); idx > 0 {
		name := strings.TrimSpace(setCookie[:idx])
		if strings.ContainsAny(name, " \t\r\n") {
			return ""
		}
		return name
	}
	return ""
}
