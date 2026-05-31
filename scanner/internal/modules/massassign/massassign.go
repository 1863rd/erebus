// Package massassign detects mass assignment vulnerabilities in REST APIs.
// It injects extra privileged fields into POST/PUT/PATCH request bodies and
// observes whether the server silently accepts them (OWASP API3:2023).
package massassign

import (
	"bytes"
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

// privileged fields to inject — each has a value that, if accepted, indicates
// that the server merged user input into a privileged object without filtering.
var privilegedFields = []struct {
	key   string
	value interface{}
}{
	{"is_admin", true},
	{"isAdmin", true},
	{"admin", true},
	{"role", "admin"},
	{"roles", []string{"admin"}},
	{"user_role", "administrator"},
	{"group", "admin"},
	{"permission", "write"},
	{"permissions", []string{"admin:read", "admin:write"}},
	{"verified", true},
	{"email_verified", true},
	{"active", true},
	{"enabled", true},
	{"banned", false},
	{"premium", true},
	{"subscription", "enterprise"},
	{"plan", "premium"},
	{"price", 0},
	{"discount", 100},
	{"balance", 99999},
	{"credit", 99999},
	{"internal_id", 1},
	{"_id", 1},
	{"id", 1},
	{"user_id", 1},
	{"account_id", 1},
}

// form field overrides for application/x-www-form-urlencoded
var formPrivilegedFields = []struct {
	key   string
	value string
}{
	{"is_admin", "1"},
	{"isAdmin", "true"},
	{"admin", "true"},
	{"role", "admin"},
	{"verified", "true"},
	{"active", "true"},
	{"premium", "true"},
	{"price", "0"},
	{"discount", "100"},
	{"balance", "99999"},
	{"banned", "0"},
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "massassign" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	// JSON API endpoints
	findings = append(findings, m.testJSONEndpoints(ctx, page)...)

	// HTML form POST endpoints
	if ctx.Err() == nil {
		findings = append(findings, m.testFormEndpoints(ctx, page)...)
	}

	return findings, nil
}

func (m *Module) testJSONEndpoints(ctx context.Context, page crawler.Page) []modules.Finding {
	var findings []modules.Finding

	if len(page.JSONParams) == 0 {
		return nil
	}

	// Group JSON params by endpoint+method
	type endpointKey struct {
		endpoint string
		method   string
	}
	endpoints := make(map[endpointKey]map[string]interface{})
	for _, jp := range page.JSONParams {
		key := endpointKey{jp.Endpoint, jp.Method}
		if endpoints[key] == nil {
			endpoints[key] = make(map[string]interface{})
		}
		endpoints[key][jp.Key] = jp.Value
	}

	for ek, baseBody := range endpoints {
		if ctx.Err() != nil {
			break
		}
		if ek.method == http.MethodGet || ek.method == http.MethodDelete {
			continue
		}

		// Baseline request to get original response size/content
		baseResp, err := m.jsonRequest(ctx, ek.endpoint, ek.method, baseBody)
		if err != nil || baseResp == nil {
			continue
		}
		baseBody2, _ := client.ReadBody(baseResp)
		baseStatus := baseResp.StatusCode

		// Inject privileged fields alongside the legitimate body
		augmented := make(map[string]interface{})
		for k, v := range baseBody {
			augmented[k] = v
		}
		for _, f := range privilegedFields {
			augmented[f.key] = f.value
		}

		injResp, err := m.jsonRequest(ctx, ek.endpoint, ek.method, augmented)
		if err != nil || injResp == nil {
			continue
		}
		injBody, _ := client.ReadBody(injResp)

		// Check for signs of acceptance:
		// 1. Server returns 200/201 (not 400 "unknown field" validation error)
		// 2. Response echoes back one of the injected field values
		// 3. Response is meaningfully different from base (extra data accepted)
		acceptedFields := detectAcceptedFields(string(injBody))

		if len(acceptedFields) > 0 && injResp.StatusCode < 400 {
			findings = append(findings, modules.Finding{
				Module:      "massassign",
				Severity:    modules.High,
				URL:         ek.endpoint,
				Param:       strings.Join(acceptedFields, ", "),
				Payload:     fmt.Sprintf("%s %s + privileged fields: %s", ek.method, ek.endpoint, strings.Join(acceptedFields, ",")),
				Evidence:    fmt.Sprintf("Injected privileged fields accepted (HTTP %d); response reflects: %s", injResp.StatusCode, strings.Join(acceptedFields, ", ")),
				Detail:      "Mass assignment: the API merges request body fields directly into a model without filtering sensitive properties. Injecting privileged fields (is_admin, role, verified, price) was accepted by the server.",
				CWE:         "CWE-915",
				CVSS:        8.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Use an explicit allow-list (DTO/schema) for which fields can be set by users; never bind request bodies directly to ORM models",
				Tags:        []string{"mass-assignment", "api3", "owasp-api", "privilege-escalation"},
			})
		} else if injResp.StatusCode < 400 && baseStatus < 400 {
			// No reflected fields but server accepted — check for 0-diff (all fields ignored) vs diff
			if len(injBody) != len(baseBody2) {
				findings = append(findings, modules.Finding{
					Module:     "massassign",
					Severity:   modules.Medium,
					URL:        ek.endpoint,
					Param:      "JSON body (privileged fields)",
					Payload:    fmt.Sprintf("%s with %d extra privileged fields", ek.method, len(privilegedFields)),
					Evidence:   fmt.Sprintf("Response size changed %d→%d bytes after injecting privileged fields (HTTP %d) — possible acceptance", len(baseBody2), len(injBody), injResp.StatusCode),
					Detail:     "Possible mass assignment: the API accepted extra privileged fields in the request body without returning a validation error. Verify manually whether is_admin/role/verified fields were persisted.",
					CWE:         "CWE-915",
					CVSS:        6.5,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
					Confidence:  modules.Potential,
					Remediation: "Use an explicit allow-list (DTO/schema) for which fields can be set by users; verify whether injected fields were persisted",
					Tags:        []string{"mass-assignment", "api3", "owasp-api"},
				})
			}
		}
	}
	return findings
}

func (m *Module) testFormEndpoints(ctx context.Context, page crawler.Page) []modules.Finding {
	var findings []modules.Finding

	for _, form := range page.Forms {
		if ctx.Err() != nil {
			break
		}
		if strings.ToUpper(form.Method) != "POST" {
			continue
		}

		// Baseline form submission
		baseData := make(url.Values)
		for _, f := range form.Fields {
			if f.Value != "" {
				baseData.Set(f.Name, f.Value)
			} else if f.Type != "hidden" && f.Type != "submit" && f.Type != "button" {
				baseData.Set(f.Name, "test")
			}
		}

		baseResp, err := m.formRequest(ctx, form.Action, baseData)
		if err != nil || baseResp == nil {
			continue
		}
		client.DrainClose(baseResp)

		// Inject extra privileged fields
		augData := make(url.Values)
		for k, vs := range baseData {
			augData[k] = vs
		}
		for _, f := range formPrivilegedFields {
			augData.Set(f.key, f.value)
		}

		injResp, err := m.formRequest(ctx, form.Action, augData)
		if err != nil || injResp == nil {
			continue
		}
		injBody, _ := client.ReadBody(injResp)

		if accepted := detectAcceptedFields(string(injBody)); injResp.StatusCode < 400 && accepted != nil {
			findings = append(findings, modules.Finding{
				Module:      "massassign",
				Severity:    modules.High,
				URL:         form.Action,
				Param:       strings.Join(accepted, ", "),
				Payload:     "POST form + is_admin=1&role=admin&verified=true&...",
				Evidence:    fmt.Sprintf("Form accepted privileged fields (HTTP %d): %s", injResp.StatusCode, strings.Join(accepted, ", ")),
				Detail:      "Mass assignment via HTML form: extra privileged fields (is_admin, role, etc.) appended to a POST form submission were accepted by the server",
				CWE:         "CWE-915",
				CVSS:        8.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "Use an explicit field allow-list; never bind POST body directly to user model without filtering",
				Tags:        []string{"mass-assignment", "api3", "form", "owasp-api"},
			})
		}
	}
	return findings
}

func (m *Module) jsonRequest(ctx context.Context, endpoint, method string, body map[string]interface{}) (*http.Response, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return m.client.Do(req)
}

func (m *Module) formRequest(ctx context.Context, action string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return m.client.Do(req)
}

// detectAcceptedFields checks whether any of the injected privileged field values
// appear verbatim in the response body (reflected back by the API).
func detectAcceptedFields(body string) []string {
	var found []string
	bodyLow := strings.ToLower(body)
	for _, f := range privilegedFields {
		switch v := f.value.(type) {
		case bool:
			if v && (strings.Contains(bodyLow, `"`+f.key+`":true`) || strings.Contains(bodyLow, f.key+`=true`)) {
				found = append(found, f.key)
			}
		case string:
			if strings.Contains(bodyLow, strings.ToLower(`"`+f.key+`":"`+v+`"`)) {
				found = append(found, f.key)
			}
		case int:
			if v == 0 && strings.Contains(bodyLow, `"`+f.key+`":0`) {
				found = append(found, f.key)
			}
		}
	}
	return found
}
