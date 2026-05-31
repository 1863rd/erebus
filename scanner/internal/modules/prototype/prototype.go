package prototype

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

const ppCanary = "erebus_pp_7x4q2"

// Pollution vectors as (query key, value) pairs for URL-based injection
var queryVectors = []struct {
	key   string
	value string
}{
	{"__proto__[erebus_pp]", ppCanary},
	{"__proto__.erebus_pp", ppCanary},
	{"constructor[prototype][erebus_pp]", ppCanary},
	{"constructor.prototype.erebus_pp", ppCanary},
	{"__proto__[toString]", ppCanary},
	{"__proto__[valueOf]", ppCanary},
}

// JSON body vectors
var jsonVectors = []map[string]interface{}{
	{"__proto__": map[string]interface{}{"erebus_pp": ppCanary}},
	{"constructor": map[string]interface{}{"prototype": map[string]interface{}{"erebus_pp": ppCanary}}},
	{"__proto__": map[string]interface{}{"isAdmin": true, "role": "admin", "erebus_pp": ppCanary}},
	{"__proto__": map[string]interface{}{"toString": ppCanary}},
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "prototype" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	findings = append(findings, m.testQueryPollution(ctx, page)...)
	if ctx.Err() == nil {
		findings = append(findings, m.testJSONPollution(ctx, page)...)
	}
	return findings, nil
}

func (m *Module) testQueryPollution(ctx context.Context, page crawler.Page) []modules.Finding {
	var findings []modules.Finding
	baseStr := strings.ToLower(string(page.Body))

	u, err := url.Parse(page.URL)
	if err != nil {
		return nil
	}

	for _, vec := range queryVectors {
		if ctx.Err() != nil {
			break
		}
		q := u.Query()
		q.Set(vec.key, vec.value)
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
		bodyLow := strings.ToLower(string(body))

		if strings.Contains(bodyLow, ppCanary) && !strings.Contains(baseStr, ppCanary) {
			findings = append(findings, modules.Finding{
				Module:      "prototype",
				Severity:    modules.High,
				URL:         cu.String(),
				Param:       vec.key,
				Payload:     vec.value,
				Evidence:    fmt.Sprintf("Canary %q reflected in response body — query-based prototype pollution", ppCanary),
				Detail:      "Prototype pollution via URL query parameters: injecting into __proto__ or constructor.prototype is reflected in the response, indicating the application merges query parameters into objects without key filtering",
				CWE:         "CWE-1321",
				CVSS:        7.3,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
				Confidence:  modules.Confirmed,
				Remediation: "Sanitize object keys before merging user input; use Object.create(null) or Map for user-supplied data; use a library like deepmerge with prototype pollution protection",
				Tags:        []string{"prototype-pollution", "client-side", "injection"},
			})
			break
		}

		// Behavior change heuristic: response significantly different in size
		origLen := len(page.Body)
		altLen := len(body)
		if origLen > 100 && resp.StatusCode == 200 {
			diff := altLen - origLen
			if diff < 0 {
				diff = -diff
			}
			if float64(diff)/float64(origLen) > 0.30 {
				findings = append(findings, modules.Finding{
					Module:      "prototype",
					Severity:    modules.Medium,
					URL:         cu.String(),
					Param:       vec.key,
					Payload:     vec.value,
					Evidence:    fmt.Sprintf("Response size changed by %.0f%% with prototype pollution payload (%d→%d bytes)", float64(diff)/float64(origLen)*100, origLen, altLen),
					Detail:      "Possible prototype pollution: response size significantly different when injecting __proto__/__constructor keys — application may be merging query params into objects",
					CWE:         "CWE-1321",
					CVSS:        5.3,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
					Confidence:  modules.Potential,
					Remediation: "Sanitize object keys before merging user input; use Object.create(null) or Map for user-supplied data; use a library like deepmerge with prototype pollution protection",
					Tags:        []string{"prototype-pollution", "client-side"},
				})
				break
			}
		}
	}
	return findings
}

func (m *Module) testJSONPollution(ctx context.Context, page crawler.Page) []modules.Finding {
	var findings []modules.Finding

	// Only test pages with JSON API parameters
	if len(page.JSONParams) == 0 && !strings.Contains(page.URL, "/api/") {
		return nil
	}

	baseStr := strings.ToLower(string(page.Body))

	for i, vec := range jsonVectors {
		if ctx.Err() != nil {
			break
		}
		payload, err := json.Marshal(vec)
		if err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, page.URL, bytes.NewReader(payload))
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
		bodyLow := strings.ToLower(string(body))

		if strings.Contains(bodyLow, ppCanary) && !strings.Contains(baseStr, ppCanary) {
			findings = append(findings, modules.Finding{
				Module:      "prototype",
				Severity:    modules.High,
				URL:         page.URL,
				Param:       fmt.Sprintf("JSON body (vector %d)", i+1),
				Payload:     string(payload),
				Evidence:    fmt.Sprintf("Canary %q reflected after JSON body prototype pollution", ppCanary),
				Detail:      "Server-side prototype pollution via JSON body: the application merges JSON request body fields including __proto__ keys into server-side objects, potentially allowing privilege escalation or RCE via gadget chains",
				CWE:         "CWE-1321",
				CVSS:        8.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Validate and sanitize all incoming JSON keys; use JSON schema validation; avoid unsafe recursive object merging (lodash.merge, jQuery.extend without 'deep' guard)",
				Tags:        []string{"prototype-pollution", "server-side", "sspp", "injection"},
			})
			break
		}
	}
	return findings
}
