// Package logic detects business logic flaws through numeric parameter manipulation:
// negative values, zero prices, integer overflow, boundary bypass, and discount abuse.
package logic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

var numericFieldPatterns = []string{
	"price", "amount", "quantity", "count", "balance", "total", "cost",
	"age", "limit", "offset", "size", "score", "rate", "fee", "tax",
	"discount", "weight", "height", "width", "duration", "credit", "debit",
	"transfer", "withdraw", "deposit", "budget", "salary", "income",
	"points", "reward", "cashback", "refund", "tip",
}

type probe struct {
	value   string
	label   string
	severity modules.Severity
}

var probes = []probe{
	{"-1", "negative value", modules.High},
	{"-0.01", "negative decimal", modules.High},
	{"-9999999", "large negative value", modules.High},
	{"0", "zero value", modules.Medium},
	{"0.00", "zero decimal", modules.Medium},
	{"2147483648", "integer overflow (INT32_MAX+1)", modules.Medium},
	{"9999999999", "extreme large value", modules.Medium},
	{"1e308", "float overflow", modules.Medium},
	{"0.001", "sub-penny decimal", modules.Low},
	{"0.0000001", "sub-cent rounding abuse", modules.Low},
}

type Module struct {
	client    *client.Client
	seenPaths sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "logic" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Test form fields
	for _, form := range page.Forms {
		if form.Method != "POST" && form.Method != "PUT" && form.Method != "PATCH" {
			continue
		}
		for _, field := range form.Fields {
			if !isNumericField(field.Name) {
				continue
			}
			key := "form|" + form.Action + "|" + field.Name
			if _, loaded := m.seenPaths.LoadOrStore(key, struct{}{}); loaded {
				continue
			}
			findings = append(findings, m.testFormField(ctx, form, field)...)
		}
	}

	// Test JSON parameters
	for _, jp := range page.JSONParams {
		if !isNumericField(jp.Key) {
			continue
		}
		// Must be a mutation endpoint
		if jp.Method == "GET" {
			continue
		}
		key := "json|" + jp.Endpoint + "|" + jp.Key
		if _, loaded := m.seenPaths.LoadOrStore(key, struct{}{}); loaded {
			continue
		}
		findings = append(findings, m.testJSONParam(ctx, jp)...)
	}

	// Test URL query parameters
	u, err := url.Parse(page.URL)
	if err == nil {
		for paramName, vs := range u.Query() {
			if !isNumericField(paramName) {
				continue
			}
			orig := ""
			if len(vs) > 0 {
				orig = vs[0]
			}
			if !isNumericValue(orig) {
				continue
			}
			key := "query|" + u.Host + u.Path + "|" + paramName
			if _, loaded := m.seenPaths.LoadOrStore(key, struct{}{}); loaded {
				continue
			}
			findings = append(findings, m.testQueryParam(ctx, page.URL, u, paramName)...)
		}
	}

	return findings, nil
}

func (m *Module) testFormField(ctx context.Context, form crawler.Form, field crawler.Field) []modules.Finding {
	var findings []modules.Finding

	// Baseline request
	baseline := m.formRequest(ctx, form, field.Name, field.Value)
	if baseline == nil || (baseline.status < 200 || baseline.status >= 300) {
		return nil
	}

	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		result := m.formRequest(ctx, form, field.Name, p.value)
		if result == nil {
			continue
		}
		if f := detectAnomaly(form.Action, field.Name, "form", p, baseline, result); f != nil {
			findings = append(findings, *f)
			break
		}
	}
	return findings
}

func (m *Module) testJSONParam(ctx context.Context, jp crawler.JSONParam) []modules.Finding {
	var findings []modules.Finding

	baseline := m.jsonRequest(ctx, jp, jp.Value)
	if baseline == nil || (baseline.status < 200 || baseline.status >= 300) {
		return nil
	}

	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		result := m.jsonRequest(ctx, jp, p.value)
		if result == nil {
			continue
		}
		if f := detectAnomaly(jp.Endpoint, jp.Key, "json", p, baseline, result); f != nil {
			findings = append(findings, *f)
			break
		}
	}
	return findings
}

func (m *Module) testQueryParam(ctx context.Context, rawURL string, parsed *url.URL, paramName string) []modules.Finding {
	var findings []modules.Finding

	baseline := m.queryRequest(ctx, parsed, paramName, parsed.Query().Get(paramName))
	if baseline == nil || (baseline.status < 200 || baseline.status >= 300) {
		return nil
	}

	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		result := m.queryRequest(ctx, parsed, paramName, p.value)
		if result == nil {
			continue
		}
		if f := detectAnomaly(rawURL, paramName, "query", p, baseline, result); f != nil {
			findings = append(findings, *f)
			break
		}
	}
	return findings
}

type reqResult struct {
	status int
	body   string
}

func (m *Module) formRequest(ctx context.Context, form crawler.Form, targetField, value string) *reqResult {
	vals := make(url.Values)
	for _, f := range form.Fields {
		if f.Name == targetField {
			vals.Set(f.Name, value)
		} else if f.Value != "" {
			vals.Set(f.Name, f.Value)
		} else {
			vals.Set(f.Name, "test")
		}
	}
	req, err := http.NewRequestWithContext(ctx, form.Method, form.Action, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := client.ReadBody(resp)
	n := len(b)
	if n > 300 {
		n = 300
	}
	return &reqResult{status: resp.StatusCode, body: string(b[:n])}
}

func (m *Module) jsonRequest(ctx context.Context, jp crawler.JSONParam, value interface{}) *reqResult {
	body := deepCopyJSON(jp.FullBody)
	if len(jp.Path) > 0 {
		setJSON(body, jp.Path, value)
	} else {
		body[jp.Key] = value
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, jp.Method, jp.Endpoint, strings.NewReader(string(encoded)))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := client.ReadBody(resp)
	n := len(b)
	if n > 300 {
		n = 300
	}
	return &reqResult{status: resp.StatusCode, body: string(b[:n])}
}

func (m *Module) queryRequest(ctx context.Context, parsed *url.URL, paramName, value string) *reqResult {
	q := parsed.Query()
	q.Set(paramName, value)
	cu := *parsed
	cu.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cu.String(), nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := client.ReadBody(resp)
	n := len(b)
	if n > 300 {
		n = 300
	}
	return &reqResult{status: resp.StatusCode, body: string(b[:n])}
}

func detectAnomaly(endpoint, param, loc string, p probe, baseline, result *reqResult) *modules.Finding {
	if result.status < 200 || result.status >= 300 {
		return nil
	}
	// If accepted (2xx): this is suspicious for negative/overflow values
	if strings.HasPrefix(p.value, "-") || p.value == "0" || p.value == "0.00" {
		bodyLow := strings.ToLower(result.body)
		// Extra signals: look for money/balance words in response
		hasMoneySignal := strings.Contains(bodyLow, "total") ||
			strings.Contains(bodyLow, "balance") ||
			strings.Contains(bodyLow, "amount") ||
			strings.Contains(bodyLow, "price") ||
			strings.Contains(bodyLow, "credit") ||
			strings.Contains(bodyLow, "success") ||
			strings.Contains(bodyLow, "order") ||
			strings.Contains(bodyLow, "payment")

		if !hasMoneySignal && result.status == baseline.status {
			return nil
		}

		sev := p.severity
		detail := fmt.Sprintf(
			"Business logic flaw — %s accepted for '%s' parameter: the endpoint returned HTTP %d "+
				"(same as baseline %d) without rejecting the invalid value. "+
				"This may allow negative-price purchases, balance inflation, quantity abuse, or free upgrades.",
			p.label, param, result.status, baseline.status,
		)
		if strings.HasPrefix(p.value, "-") {
			sev = modules.High
		}

		return &modules.Finding{
			Module:  "logic",
			Severity: sev,
			URL:     endpoint,
			Param:   param + " (" + loc + ")",
			Payload: p.value,
			Evidence: fmt.Sprintf(
				"HTTP %d returned for %s=%s (expected rejection) — baseline HTTP %d. Response: %s",
				result.status, param, p.value, baseline.status, result.body,
			),
			Detail:      detail,
			CWE:         "CWE-840",
			CVSS:        logicCVSS(sev),
			Confidence:  modules.Likely,
			Remediation: "Validate all numeric inputs server-side: reject negative values where not permitted, enforce min/max bounds, use integer-safe arithmetic, validate business constraints (price>0, quantity≥1) before processing",
			Tags:        []string{"business-logic", "numeric-abuse", "parameter-manipulation"},
		}
	}

	// Overflow: if server accepted 2147483648 and response changed, possible overflow
	if p.value == "2147483648" || p.value == "9999999999" {
		if result.status != baseline.status {
			return &modules.Finding{
				Module:   "logic",
				Severity: modules.Medium,
				URL:      endpoint,
				Param:    param + " (" + loc + ")",
				Payload:  p.value,
				Evidence: fmt.Sprintf("Integer boundary accepted (%s) — HTTP %d vs baseline %d, possible overflow/truncation", p.value, result.status, baseline.status),
				Detail:   "Integer overflow/truncation: the endpoint accepted a value exceeding INT32_MAX without rejection. Server-side integer overflow may produce unexpected behavior, negative values after wrap-around, or logic bypasses.",
				CWE:      "CWE-190",
				CVSS:     5.3,
				Confidence: modules.Potential,
				Tags:     []string{"business-logic", "integer-overflow"},
			}
		}
	}

	return nil
}

func isNumericField(name string) bool {
	low := strings.ToLower(name)
	for _, pat := range numericFieldPatterns {
		if strings.Contains(low, pat) {
			return true
		}
	}
	return false
}

func isNumericValue(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func deepCopyJSON(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if nested, ok := v.(map[string]interface{}); ok {
			out[k] = deepCopyJSON(nested)
		} else {
			out[k] = v
		}
	}
	return out
}

func setJSON(m map[string]interface{}, path []string, val interface{}) {
	if len(path) == 0 {
		return
	}
	if len(path) == 1 {
		m[path[0]] = val
		return
	}
	child, ok := m[path[0]].(map[string]interface{})
	if !ok {
		child = make(map[string]interface{})
	}
	setJSON(child, path[1:], val)
	m[path[0]] = child
}

func logicCVSS(sev modules.Severity) float64 {
	switch sev {
	case modules.High:
		return 7.5
	case modules.Medium:
		return 5.3
	default:
		return 3.7
	}
}
