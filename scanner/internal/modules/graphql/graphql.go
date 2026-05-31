package graphql

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

var graphqlPaths = []string{
	"/graphql", "/graphql/v1", "/graphql/v2",
	"/api/graphql", "/v1/graphql", "/v2/graphql", "/v3/graphql",
	"/query", "/gql", "/graphiql", "/playground",
	"/api/query", "/api/v1/graphql", "/api/v2/graphql",
}

const introspectionQuery = `{
  "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } } } } }"
}`

const depthQuery = `{
  "query": "{ a { a { a { a { a { a { a { a { a { a { a { __typename } } } } } } } } } } } }"
}`

const batchQuery = `[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]`

// Fragment-based introspection bypass for servers that block direct __schema
const fragmentIntrospection = `{
  "query": "fragment f on __Schema { queryType { name } types { name kind } } { __schema { ...f } }"
}`

type Module struct {
	client    *client.Client
	seenHosts sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "graphql" }

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

	for _, path := range graphqlPaths {
		if ctx.Err() != nil {
			break
		}
		endpoint := host + path
		fs := m.probeEndpoint(ctx, endpoint)
		findings = append(findings, fs...)
		if len(fs) > 0 {
			break
		}
	}

	if isGraphQLURL(page.URL) {
		findings = append(findings, m.probeEndpoint(ctx, page.URL)...)
	}
	return findings, nil
}

func (m *Module) probeEndpoint(ctx context.Context, endpoint string) []modules.Finding {
	if !m.isGraphQL(ctx, endpoint) {
		return nil
	}

	var findings []modules.Finding

	var schema *graphqlSchema

	if f, s := m.testIntrospection(ctx, endpoint); f != nil {
		findings = append(findings, *f)
		schema = s
	}

	// If direct introspection is blocked, try fragment bypass
	if schema == nil {
		if f, s := m.testFragmentIntrospection(ctx, endpoint); f != nil {
			findings = append(findings, *f)
			schema = s
		}
	}

	if f := m.testBatching(ctx, endpoint); f != nil {
		findings = append(findings, *f)
	}

	if f := m.testFieldSuggestion(ctx, endpoint); f != nil {
		findings = append(findings, *f)
	}

	if f := m.testGETQuery(ctx, endpoint); f != nil {
		findings = append(findings, *f)
	}

	if f := m.testDepthAttack(ctx, endpoint); f != nil {
		findings = append(findings, *f)
	}

	// Mutation-based tests (only if we have schema info)
	if schema != nil && ctx.Err() == nil {
		findings = append(findings, m.testMutations(ctx, endpoint, schema)...)
	}

	if f := m.testAliasDoS(ctx, endpoint); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

type graphqlSchema struct {
	Types     []gqlType
	MutationType string
}

type gqlType struct {
	Name   string
	Kind   string
	Fields []gqlField
}

type gqlField struct {
	Name string
	Args []gqlArg
}

type gqlArg struct {
	Name string
}

func (m *Module) isGraphQL(ctx context.Context, endpoint string) bool {
	body, err := m.post(ctx, endpoint, `{"query":"{__typename}"}`)
	if err != nil {
		return false
	}
	s := strings.ToLower(string(body))
	return strings.Contains(s, `"data"`) || strings.Contains(s, `"errors"`) ||
		strings.Contains(s, "graphql") || strings.Contains(s, "__typename")
}

func (m *Module) testIntrospection(ctx context.Context, endpoint string) (*modules.Finding, *graphqlSchema) {
	body, err := m.post(ctx, endpoint, introspectionQuery)
	if err != nil {
		return nil, nil
	}
	s := string(body)
	if !strings.Contains(s, `"__schema"`) && !strings.Contains(s, `"queryType"`) {
		return nil, nil
	}

	var resp struct {
		Data struct {
			Schema struct {
				MutationType struct {
					Name string `json:"name"`
				} `json:"mutationType"`
				Types []struct {
					Name   string `json:"name"`
					Kind   string `json:"kind"`
					Fields []struct {
						Name string `json:"name"`
						Args []struct {
							Name string `json:"name"`
						} `json:"args"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	json.Unmarshal(body, &resp)

	schema := &graphqlSchema{
		MutationType: resp.Data.Schema.MutationType.Name,
	}
	var typeNames []string
	for _, t := range resp.Data.Schema.Types {
		if strings.HasPrefix(t.Name, "__") {
			continue
		}
		if t.Kind == "OBJECT" {
			typeNames = append(typeNames, t.Name)
			gt := gqlType{Name: t.Name, Kind: t.Kind}
			for _, f := range t.Fields {
				ga := gqlField{Name: f.Name}
				for _, arg := range f.Args {
					ga.Args = append(ga.Args, gqlArg{Name: arg.Name})
				}
				gt.Fields = append(gt.Fields, ga)
			}
			schema.Types = append(schema.Types, gt)
		}
	}

	extracted := fmt.Sprintf("Types: %s", strings.Join(typeNames, ", "))
	if schema.MutationType != "" {
		extracted += fmt.Sprintf(" | Mutation type: %s", schema.MutationType)
	}

	return &modules.Finding{
		Module:      "graphql",
		Severity:    modules.Medium,
		URL:         endpoint,
		Param:       "POST body",
		Payload:     introspectionQuery,
		Evidence:    fmt.Sprintf("__schema returned %d types — full schema exposed", len(typeNames)),
		Detail:      "GraphQL introspection enabled — attacker can enumerate the full API schema including all types, fields, and mutations",
		CWE:         "CWE-200",
		CVSS:        5.3,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Confidence:  modules.Confirmed,
		Remediation: "Disable introspection in production; use query depth limiting and field allow-lists",
		Tags:        []string{"graphql", "introspection", "info-disclosure"},
		Extracted:   extracted,
	}, schema
}

func (m *Module) testFragmentIntrospection(ctx context.Context, endpoint string) (*modules.Finding, *graphqlSchema) {
	body, err := m.post(ctx, endpoint, fragmentIntrospection)
	if err != nil {
		return nil, nil
	}
	s := string(body)
	if !strings.Contains(s, `"__schema"`) && !strings.Contains(s, `"types"`) {
		return nil, nil
	}

	schema := &graphqlSchema{}
	return &modules.Finding{
		Module:     "graphql",
		Severity:   modules.Medium,
		URL:        endpoint,
		Param:      "POST body",
		Payload:    fragmentIntrospection,
		Evidence:   "Fragment-based introspection returned schema data — introspection block bypassed via inline fragments",
		Detail:     "GraphQL introspection block bypass via fragments: the server blocks direct `__schema` queries but responds to fragment-spread introspection, leaking schema information",
		CWE:         "CWE-200",
		CVSS:        5.3,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Confidence:  modules.Confirmed,
		Remediation: "Use an allowlist approach that blocks all introspection paths including fragment-based; apply query depth limits and field-level access control",
		Tags:        []string{"graphql", "introspection-bypass", "info-disclosure"},
	}, schema
}

func (m *Module) testBatching(ctx context.Context, endpoint string) *modules.Finding {
	body, err := m.post(ctx, endpoint, batchQuery)
	if err != nil {
		return nil
	}
	s := string(body)
	if !strings.HasPrefix(strings.TrimSpace(s), "[") {
		return nil
	}
	var arr []interface{}
	if json.Unmarshal(body, &arr) != nil || len(arr) < 5 {
		return nil
	}
	return &modules.Finding{
		Module:      "graphql",
		Severity:    modules.Low,
		URL:         endpoint,
		Param:       "POST body",
		Payload:     batchQuery,
		Evidence:    fmt.Sprintf("Batch of %d queries accepted in one request — batching enabled", len(arr)),
		Detail:      "GraphQL query batching enabled — can bypass per-request rate limiting by sending many queries in one HTTP request (brute-force, enumeration)",
		CWE:         "CWE-799",
		CVSS:        5.3,
		Confidence:  modules.Confirmed,
		Remediation: "Disable batching or enforce per-operation rate limits",
		Tags:        []string{"graphql", "batching", "rate-limit-bypass"},
	}
}

func (m *Module) testFieldSuggestion(ctx context.Context, endpoint string) *modules.Finding {
	body, err := m.post(ctx, endpoint, `{"query":"{usersXXX{idXXX}}"}`)
	if err != nil {
		return nil
	}
	s := strings.ToLower(string(body))
	if !strings.Contains(s, "did you mean") && !strings.Contains(s, "suggestion") {
		return nil
	}
	return &modules.Finding{
		Module:     "graphql",
		Severity:   modules.Low,
		URL:        endpoint,
		Param:      "POST body",
		Payload:    `{"query":"{usersXXX{idXXX}}"}`,
		Evidence:   "Server returned field name suggestion in error response",
		Detail:     "GraphQL field suggestion leaks valid field/type names even when introspection is disabled",
		CWE:         "CWE-200",
		CVSS:        3.7,
		CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Confidence:  modules.Confirmed,
		Remediation: "Disable field suggestions in production GraphQL configuration (e.g. disableSuggestions option in graphql-js / Apollo Server)",
		Tags:        []string{"graphql", "field-suggestion", "info-disclosure"},
	}
}

func (m *Module) testGETQuery(ctx context.Context, endpoint string) *modules.Finding {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil
	}
	q := u.Query()
	q.Set("query", "{__typename}")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := client.ReadBody(resp)
	s := strings.ToLower(string(body))
	if !strings.Contains(s, "__typename") && !strings.Contains(s, `"data"`) {
		return nil
	}
	return &modules.Finding{
		Module:     "graphql",
		Severity:   modules.Medium,
		URL:        u.String(),
		Param:      "query param",
		Payload:    "?query={__typename}",
		Evidence:   "GraphQL responded to GET request",
		Detail:     "GraphQL accepts GET queries — enables CSRF attacks against state-changing mutations",
		CWE:         "CWE-352",
		CVSS:        6.5,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
		Confidence:  modules.Confirmed,
		Remediation: "Disable GET query support for mutations; enforce POST-only for state-changing GraphQL operations; add CSRF tokens or require custom request headers",
		Tags:        []string{"graphql", "csrf", "get-query"},
	}
}

func (m *Module) testDepthAttack(ctx context.Context, endpoint string) *modules.Finding {
	body, err := m.post(ctx, endpoint, depthQuery)
	if err != nil {
		return nil
	}
	s := strings.ToLower(string(body))
	// If the server responded with data rather than an error, depth limiting is absent
	if strings.Contains(s, `"data"`) && !strings.Contains(s, "too deep") && !strings.Contains(s, "max depth") {
		return &modules.Finding{
			Module:     "graphql",
			Severity:   modules.Medium,
			URL:        endpoint,
			Param:      "POST body",
			Payload:    depthQuery,
			Evidence:   "11-level nested query returned data without depth limit rejection",
			Detail:     "GraphQL has no query depth limiting — deeply nested queries can exhaust server resources (DoS)",
			CWE:         "CWE-400",
			CVSS:        5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			Confidence:  modules.Likely,
			Remediation: "Implement query depth limiting (max 10–15 levels); use query complexity analysis; reject queries exceeding the depth threshold before execution",
			Tags:        []string{"graphql", "depth-limit", "dos"},
		}
	}
	return nil
}

// testAliasDoS sends a query with many aliases of the same expensive field.
// This bypasses per-query rate limiting since it's a single request.
func (m *Module) testAliasDoS(ctx context.Context, endpoint string) *modules.Finding {
	aliases := make([]string, 100)
	for i := range aliases {
		aliases[i] = fmt.Sprintf("a%d:__typename", i)
	}
	query := fmt.Sprintf(`{"query":"{ %s }"}`, strings.Join(aliases, " "))
	body, err := m.post(ctx, endpoint, query)
	if err != nil {
		return nil
	}
	s := string(body)
	// Count how many aliases were resolved
	count := strings.Count(s, "__typename")
	if count >= 50 {
		return &modules.Finding{
			Module:     "graphql",
			Severity:   modules.Low,
			URL:        endpoint,
			Param:      "POST body",
			Payload:    fmt.Sprintf("{100 aliased __typename fields}"),
			Evidence:   fmt.Sprintf("Server resolved %d aliased fields in one request — no alias limit", count),
			Detail:     "GraphQL alias-based resource exhaustion: using many field aliases in a single query bypasses per-field rate limits and amplifies query cost, enabling DoS",
			CWE:        "CWE-400",
			CVSS:       5.3,
			Confidence: modules.Confirmed,
			Remediation: "Implement query cost analysis / complexity limits; limit alias count per query",
			Tags:       []string{"graphql", "alias-dos", "rate-limit-bypass"},
		}
	}
	return nil
}

// testMutations probes discovered mutation fields for authorization issues.
func (m *Module) testMutations(ctx context.Context, endpoint string, schema *graphqlSchema) []modules.Finding {
	var findings []modules.Finding

	// Find the mutation type
	var mutType *gqlType
	for i := range schema.Types {
		if schema.MutationType != "" && schema.Types[i].Name == schema.MutationType {
			mutType = &schema.Types[i]
			break
		}
		if strings.EqualFold(schema.Types[i].Name, "Mutation") {
			mutType = &schema.Types[i]
			break
		}
	}
	if mutType == nil {
		return nil
	}

	// Dangerous mutation name patterns
	dangerous := []string{
		"delete", "remove", "destroy", "drop",
		"update", "modify", "change", "set",
		"create", "add", "insert", "register",
		"assign", "grant", "promote", "elevate",
		"password", "email", "role", "admin",
	}

	for _, field := range mutType.Fields {
		if ctx.Err() != nil {
			break
		}
		fname := strings.ToLower(field.Name)
		isDangerous := false
		for _, d := range dangerous {
			if strings.Contains(fname, d) {
				isDangerous = true
				break
			}
		}
		if !isDangerous {
			continue
		}

		// Build a probe mutation with dummy args
		argList := ""
		if len(field.Args) > 0 {
			args := make([]string, len(field.Args))
			for i, a := range field.Args {
				args[i] = fmt.Sprintf(`%s: "erebus_test"`, a.Name)
			}
			argList = "(" + strings.Join(args, ", ") + ")"
		}
		query := fmt.Sprintf(`{"query":"mutation { %s%s { __typename } }"}`, field.Name, argList)

		body, err := m.post(ctx, endpoint, query)
		if err != nil {
			continue
		}
		s := strings.ToLower(string(body))

		// If no errors about authorization / authentication → potentially accessible
		hasAuthError := strings.Contains(s, "unauthorized") || strings.Contains(s, "forbidden") ||
			strings.Contains(s, "authentication") || strings.Contains(s, "not allowed") ||
			strings.Contains(s, "permission") || strings.Contains(s, "access denied")

		hasData := strings.Contains(s, `"data"`) && !strings.Contains(s, `"data":null`)

		if !hasAuthError && (hasData || !strings.Contains(s, "errors")) {
			findings = append(findings, modules.Finding{
				Module:     "graphql",
				Severity:   modules.High,
				URL:        endpoint,
				Param:      "mutation:" + field.Name,
				Payload:    query,
				Evidence:   fmt.Sprintf("Mutation %q executed without authorization error", field.Name),
				Detail:     fmt.Sprintf("GraphQL mutation %q appears accessible without proper authorization — sensitive operations may be performable by unauthenticated or low-privileged users", field.Name),
				CWE:         "CWE-862",
				CVSS:        8.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
				Confidence:  modules.Likely,
				Remediation: "Add authorization middleware to all GraphQL mutations; verify ownership and role on every resolver; use per-field or per-type permission rules",
				Tags:        []string{"graphql", "mutation", "auth-bypass", "bola"},
			})
		}
	}
	return findings
}

func (m *Module) post(ctx context.Context, endpoint, body string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	return client.ReadBody(resp)
}

func isGraphQLURL(rawURL string) bool {
	low := strings.ToLower(rawURL)
	for _, p := range []string{"graphql", "/gql", "/query", "graphiql", "playground"} {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}
