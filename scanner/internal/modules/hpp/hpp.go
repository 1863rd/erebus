// Package hpp detects HTTP Parameter Pollution vulnerabilities.
// Sends duplicate parameters in query strings and POST bodies to test
// whether the server picks the first, last, or concatenated value — and
// whether duplicate injection bypasses WAF rules or access controls.
package hpp

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

// xssPayload is a simple XSS payload used to detect if a duplicate parameter
// bypasses input filtering.
const xssPayload = `<script>alert(1)</script>`

// sqliPayload used to detect SQLi filter bypass via HPP.
const sqliPayload = `' OR '1'='1`

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "hpp" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Test query parameters
	u, err := url.Parse(page.URL)
	if err == nil && len(u.Query()) > 0 {
		findings = append(findings, m.testQueryHPP(ctx, page.URL, u)...)
	}

	// Test form parameters
	for _, form := range page.Forms {
		if ctx.Err() != nil {
			break
		}
		findings = append(findings, m.testFormHPP(ctx, form, page.Body)...)
	}

	return findings, nil
}

func (m *Module) testQueryHPP(ctx context.Context, rawURL string, u *url.URL) []modules.Finding {
	var findings []modules.Finding
	orig := u.Query()

	for k, vs := range orig {
		if ctx.Err() != nil {
			break
		}
		origVal := ""
		if len(vs) > 0 {
			origVal = vs[0]
		}

		// Build a raw query with the parameter duplicated:
		// param=original&param=payload — tests "last wins" servers
		for _, payload := range []string{xssPayload, sqliPayload} {
			if ctx.Err() != nil {
				break
			}
			duplicated := buildDuplicatedQuery(orig, k, origVal, payload)
			cu := *u
			cu.RawQuery = duplicated

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, cu.String(), nil)
			if err != nil {
				continue
			}
			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}
			body, _ := client.ReadBody(resp)
			bodyStr := string(body)

			if !strings.Contains(bodyStr, payload) {
				continue
			}

			findings = append(findings, modules.Finding{
				Module:   "hpp",
				Severity: modules.High,
				URL:      rawURL,
				Param:    k,
				Payload:  fmt.Sprintf("%s=%s&%s=%s", k, origVal, k, payload),
				Evidence: fmt.Sprintf("Duplicate parameter %q: injected value %q reflected in response", k, payload),
				Detail: fmt.Sprintf("HTTP Parameter Pollution in %q: server processes the second (duplicate) parameter value. "+
					"WAF bypass possible — the filter may only inspect one occurrence while the backend uses another.", k),
				CWE:         "CWE-235",
				CVSS:        7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Reject requests with duplicate parameter names; explicitly use only the first or last occurrence consistently; validate at the WAF level",
				Tags:        []string{"hpp", "waf-bypass", "parameter-pollution"},
			})
			break
		}

		// Also test: param=payload&param=original — tests "first wins" servers
		for _, payload := range []string{xssPayload, sqliPayload} {
			if ctx.Err() != nil {
				break
			}
			duplicated := buildDuplicatedQuery(orig, k, payload, origVal)
			cu := *u
			cu.RawQuery = duplicated

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, cu.String(), nil)
			if err != nil {
				continue
			}
			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}
			body, _ := client.ReadBody(resp)
			bodyStr := string(body)

			if !strings.Contains(bodyStr, payload) {
				continue
			}

			findings = append(findings, modules.Finding{
				Module:   "hpp",
				Severity: modules.High,
				URL:      rawURL,
				Param:    k,
				Payload:  fmt.Sprintf("%s=%s&%s=%s", k, payload, k, origVal),
				Evidence: fmt.Sprintf("Duplicate parameter %q (first wins): injected value %q reflected", k, payload),
				Detail: fmt.Sprintf("HTTP Parameter Pollution in %q: server uses the first occurrence. "+
					"Prefix injection bypasses WAF rules inspecting the last value.", k),
				CWE:         "CWE-235",
				CVSS:        7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Enforce single-value parameters; handle duplicates explicitly",
				Tags:        []string{"hpp", "waf-bypass", "parameter-pollution"},
			})
			break
		}
	}
	return findings
}

func (m *Module) testFormHPP(ctx context.Context, form crawler.Form, baseline []byte) []modules.Finding {
	var findings []modules.Finding
	baselineLen := len(baseline)

	for _, field := range form.Fields {
		if field.Type == "hidden" || field.Type == "submit" || field.Type == "button" {
			continue
		}
		if ctx.Err() != nil {
			break
		}

		origVal := field.Value
		if origVal == "" {
			origVal = "test"
		}

		for _, payload := range []string{xssPayload, sqliPayload} {
			if ctx.Err() != nil {
				break
			}

			// Build form body with duplicated parameter: field=original&field=payload
			var parts []string
			for _, f := range form.Fields {
				if f.Type == "submit" || f.Type == "button" {
					continue
				}
				if f.Name == field.Name {
					parts = append(parts, url.QueryEscape(f.Name)+"="+url.QueryEscape(origVal))
					parts = append(parts, url.QueryEscape(f.Name)+"="+url.QueryEscape(payload))
				} else {
					v := f.Value
					if v == "" {
						v = "test"
					}
					parts = append(parts, url.QueryEscape(f.Name)+"="+url.QueryEscape(v))
				}
			}
			body := strings.Join(parts, "&")

			req, err := http.NewRequestWithContext(ctx, form.Method, form.Action, strings.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}
			respBody, _ := client.ReadBody(resp)
			respStr := string(respBody)

			reflected := strings.Contains(respStr, payload)
			sizeChange := len(respBody) > baselineLen+500

			if !reflected && !sizeChange {
				continue
			}

			evidence := ""
			if reflected {
				evidence = fmt.Sprintf("Payload %q reflected in response (POST HPP)", payload)
			} else {
				evidence = fmt.Sprintf("Response size delta +%d bytes on duplicate POST param (possible HPP bypass)", len(respBody)-baselineLen)
			}

			findings = append(findings, modules.Finding{
				Module:   "hpp",
				Severity: modules.Medium,
				URL:      form.Action,
				Param:    field.Name,
				Payload:  fmt.Sprintf("%s=%s&%s=%s", field.Name, origVal, field.Name, payload),
				Evidence: evidence,
				Detail: fmt.Sprintf("HTTP Parameter Pollution in POST form field %q: duplicate parameter accepted. "+
					"Server may use the last or concatenated value — WAF rules inspecting single occurrence can be bypassed.", field.Name),
				CWE:         "CWE-235",
				CVSS:        6.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  modules.Likely,
				Remediation: "Reject duplicate POST parameters; normalize input before validation",
				Tags:        []string{"hpp", "waf-bypass", "parameter-pollution", "post"},
			})
			break
		}
	}
	return findings
}

// buildDuplicatedQuery constructs a raw query string with the target key appearing twice:
// once with firstVal and once with secondVal, all other params preserved.
func buildDuplicatedQuery(orig url.Values, key, firstVal, secondVal string) string {
	var parts []string
	// Add all other params first (preserving order is best-effort)
	for k, vs := range orig {
		if k == key {
			continue
		}
		for _, v := range vs {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(firstVal))
	parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(secondVal))
	return strings.Join(parts, "&")
}
