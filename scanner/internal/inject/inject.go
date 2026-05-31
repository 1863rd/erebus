// Package inject provides a unified parameter injection abstraction.
// All attack modules use this package so that injection automatically covers
// URL query parameters, HTML form fields, JSON request bodies, HTTP headers,
// cookies, and URL path segments — with no per-module duplication.
package inject

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
)

// Location identifies where a parameter lives. Values are bit flags (1 << iota).
type Location uint8

const (
	LocQuery  Location = 1 << iota // 1: ?param=value
	LocForm                        // 2: POST form field (application/x-www-form-urlencoded)
	LocJSON                        // 4: JSON body field (application/json)
	LocHeader                      // 8: HTTP request header
	LocCookie                      // 16: Cookie header value
	LocPath                        // 32: URL path segment
)

// Target is one injectable parameter at one location.
type Target struct {
	URL   string
	Name  string
	Value string
	Loc   Location

	// LocForm internals
	form     *crawler.Form
	formData map[string]string

	// LocJSON internals
	jsonMethod string
	jsonBody   map[string]interface{}
	jsonPath   []string

	// LocPath internals
	pathIdx int
	parsed  *url.URL
}

// Inject sends the request with `value` substituted for this parameter.
// Returns (responseBody, rawRequestDump, error).
func (t Target) Inject(ctx context.Context, c *client.Client, value string) ([]byte, string, error) {
	switch t.Loc {
	case LocQuery:
		return t.injectQuery(ctx, c, value)
	case LocForm:
		return t.injectForm(ctx, c, value)
	case LocJSON:
		return t.injectJSON(ctx, c, value)
	case LocHeader:
		return t.injectHeader(ctx, c, value)
	case LocCookie:
		return t.injectCookie(ctx, c, value)
	case LocPath:
		return t.injectPath(ctx, c, value)
	}
	return nil, "", fmt.Errorf("unknown location %d", t.Loc)
}

// InjectRaw is like Inject but returns the raw *http.Response for callers that
// need status code or response headers (e.g. IDOR comparison).
func (t Target) InjectRaw(ctx context.Context, c *client.Client, value string) (*http.Response, string, error) {
	var req *http.Request
	var body []byte
	var err error

	switch t.Loc {
	case LocQuery:
		req, err = t.buildQueryReq(ctx, value)
	case LocForm:
		req, body, err = t.buildFormReq(ctx, value)
	case LocJSON:
		req, body, err = t.buildJSONReq(ctx, value)
	case LocHeader:
		req, err = t.buildHeaderReq(ctx, value)
	case LocCookie:
		req, err = t.buildCookieReq(ctx, value)
	case LocPath:
		req, err = t.buildPathReq(ctx, value)
	default:
		return nil, "", fmt.Errorf("unknown location")
	}
	if err != nil {
		return nil, "", err
	}

	resp, dump, err := c.DoCapture(req)
	if err != nil {
		return nil, dump, err
	}
	// Re-attach body bytes if needed after capture consumed it
	_ = body
	return resp, dump, nil
}

// Collect extracts every injectable target from a crawler page, covering all
// locations: URL params, forms, JSON body params, common headers, cookies, path segments.
func Collect(page crawler.Page) []Target {
	return CollectFiltered(page, LocQuery|LocForm|LocJSON|LocHeader|LocPath)
}

// CollectFiltered collects targets limited to the specified location bitmask.
func CollectFiltered(page crawler.Page, locs Location) []Target {
	var targets []Target

	u, urlErr := url.Parse(page.URL)

	// URL query parameters
	if locs&LocQuery != 0 && urlErr == nil {
		for k, vs := range u.Query() {
			val := ""
			if len(vs) > 0 {
				val = vs[0]
			}
			targets = append(targets, Target{URL: page.URL, Name: k, Value: val, Loc: LocQuery})
		}
	}

	// HTML form fields
	if locs&LocForm != 0 {
		for i := range page.Forms {
			form := &page.Forms[i]
			fd := make(map[string]string)
			for _, f := range form.Fields {
				if f.Value != "" {
					fd[f.Name] = f.Value
				} else {
					fd[f.Name] = "test"
				}
			}
			for _, f := range form.Fields {
				if f.Type == "hidden" || f.Type == "submit" || f.Type == "button" {
					continue
				}
				targets = append(targets, Target{
					URL:      form.Action,
					Name:     f.Name,
					Value:    f.Value,
					Loc:      LocForm,
					form:     form,
					formData: fd,
				})
			}
		}
	}

	// JSON body parameters (from API responses)
	if locs&LocJSON != 0 {
		for _, jp := range page.JSONParams {
			targets = append(targets, Target{
				URL:        jp.Endpoint,
				Name:       jp.Key,
				Value:      jp.Value,
				Loc:        LocJSON,
				jsonMethod: jp.Method,
				jsonBody:   jp.FullBody,
				jsonPath:   jp.Path,
			})
		}
	}

	// Path segments (numeric / UUID)
	if locs&LocPath != 0 && urlErr == nil {
		segs := strings.Split(u.Path, "/")
		for i, seg := range segs {
			if isIDSeg(seg) {
				targets = append(targets, Target{
					URL:     page.URL,
					Name:    fmt.Sprintf("path[%d]", i),
					Value:   seg,
					Loc:     LocPath,
					pathIdx: i,
					parsed:  u,
				})
			}
		}
	}

	return targets
}

// EndpointURL returns the URL that would be called for this injection.
func (t Target) EndpointURL() string {
	if t.Loc == LocForm && t.form != nil {
		return t.form.Action
	}
	return t.URL
}

// LocationName returns a human-readable name for the injection location.
func (t Target) LocationName() string {
	switch t.Loc {
	case LocQuery:
		return "query"
	case LocForm:
		method := "POST"
		if t.form != nil {
			method = t.form.Method
		}
		return method + "-form"
	case LocJSON:
		return "json-body[" + t.jsonMethod + "]"
	case LocHeader:
		return "header"
	case LocCookie:
		return "cookie"
	case LocPath:
		return "path"
	}
	return "unknown"
}

// ---- private injection builders ----

func (t Target) injectQuery(ctx context.Context, c *client.Client, value string) ([]byte, string, error) {
	req, err := t.buildQueryReq(ctx, value)
	if err != nil {
		return nil, "", err
	}
	resp, dump, err := c.DoCapture(req)
	if err != nil {
		return nil, dump, err
	}
	body, err := client.ReadBody(resp)
	return body, dump, err
}

func (t Target) buildQueryReq(ctx context.Context, value string) (*http.Request, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set(t.Name, value)
	u.RawQuery = q.Encode()
	return http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
}

func (t Target) injectForm(ctx context.Context, c *client.Client, value string) ([]byte, string, error) {
	req, bodyBytes, err := t.buildFormReq(ctx, value)
	if err != nil {
		return nil, "", err
	}
	resp, dump, err := c.DoCapture(req)
	if err != nil {
		return nil, dump, err
	}
	_ = bodyBytes
	body, err := client.ReadBody(resp)
	return body, dump, err
}

func (t Target) buildFormReq(ctx context.Context, value string) (*http.Request, []byte, error) {
	if t.form == nil {
		return nil, nil, fmt.Errorf("no form for LocForm target")
	}
	data := make(url.Values)
	for k, v := range t.formData {
		if k == t.Name {
			data.Set(k, value)
		} else {
			data.Set(k, v)
		}
	}
	data.Set(t.Name, value) // ensure injected value takes priority

	encoded := []byte(data.Encode())
	method := strings.ToUpper(t.form.Method)
	if method == "" {
		method = "POST"
	}

	if method == "POST" {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.form.Action,
			bytes.NewReader(encoded))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, encoded, nil
	}

	u, err := url.Parse(t.form.Action)
	if err != nil {
		return nil, nil, err
	}
	u.RawQuery = data.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	return req, nil, err
}

func (t Target) injectJSON(ctx context.Context, c *client.Client, value string) ([]byte, string, error) {
	req, bodyBytes, err := t.buildJSONReq(ctx, value)
	if err != nil {
		return nil, "", err
	}
	resp, dump, err := c.DoCapture(req)
	if err != nil {
		return nil, dump, err
	}
	_ = bodyBytes
	body, err := client.ReadBody(resp)
	return body, dump, err
}

func (t Target) buildJSONReq(ctx context.Context, value string) (*http.Request, []byte, error) {
	method := t.jsonMethod
	if method == "" {
		method = http.MethodPost
	}

	// Deep-copy the full body and inject at the target path
	mutated := deepCopyMap(t.jsonBody)
	if len(t.jsonPath) > 0 {
		setNestedJSON(mutated, t.jsonPath, value)
	} else {
		mutated[t.Name] = value
	}

	encoded, err := json.Marshal(mutated)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, t.URL, bytes.NewReader(encoded))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, encoded, nil
}

func (t Target) injectHeader(ctx context.Context, c *client.Client, value string) ([]byte, string, error) {
	req, err := t.buildHeaderReq(ctx, value)
	if err != nil {
		return nil, "", err
	}
	resp, dump, err := c.DoCapture(req)
	if err != nil {
		return nil, dump, err
	}
	body, err := client.ReadBody(resp)
	return body, dump, err
}

func (t Target) buildHeaderReq(ctx context.Context, value string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(t.Name, value)
	return req, nil
}

func (t Target) injectCookie(ctx context.Context, c *client.Client, value string) ([]byte, string, error) {
	req, err := t.buildCookieReq(ctx, value)
	if err != nil {
		return nil, "", err
	}
	resp, dump, err := c.DoCapture(req)
	if err != nil {
		return nil, dump, err
	}
	body, err := client.ReadBody(resp)
	return body, dump, err
}

func (t Target) buildCookieReq(ctx context.Context, value string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return nil, err
	}
	existing := req.Header.Get("Cookie")
	if existing == "" {
		req.Header.Set("Cookie", t.Name+"="+value)
	} else {
		req.Header.Set("Cookie", existing+"; "+t.Name+"="+value)
	}
	return req, nil
}

func (t Target) injectPath(ctx context.Context, c *client.Client, value string) ([]byte, string, error) {
	req, err := t.buildPathReq(ctx, value)
	if err != nil {
		return nil, "", err
	}
	resp, dump, err := c.DoCapture(req)
	if err != nil {
		return nil, dump, err
	}
	body, err := client.ReadBody(resp)
	return body, dump, err
}

func (t Target) buildPathReq(ctx context.Context, value string) (*http.Request, error) {
	if t.parsed == nil {
		return nil, fmt.Errorf("no parsed URL for LocPath")
	}
	segs := strings.Split(t.parsed.Path, "/")
	if t.pathIdx >= len(segs) {
		return nil, fmt.Errorf("path index out of range")
	}
	modified := make([]string, len(segs))
	copy(modified, segs)
	modified[t.pathIdx] = value
	cu := *t.parsed
	cu.Path = strings.Join(modified, "/")
	return http.NewRequestWithContext(ctx, http.MethodGet, cu.String(), nil)
}

// ---- JSON helpers ----

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if nested, ok := v.(map[string]interface{}); ok {
			out[k] = deepCopyMap(nested)
		} else {
			out[k] = v
		}
	}
	return out
}

func setNestedJSON(m map[string]interface{}, path []string, value interface{}) {
	if len(path) == 0 {
		return
	}
	if len(path) == 1 {
		m[path[0]] = value
		return
	}
	child, ok := m[path[0]].(map[string]interface{})
	if !ok {
		child = make(map[string]interface{})
	}
	setNestedJSON(child, path[1:], value)
	m[path[0]] = child
}

// ExtractJSONParams walks a JSON body and returns all leaf string/number values
// with their dotted paths.  Used by the crawler to populate page.JSONParams.
func ExtractJSONParams(endpoint, method string, body map[string]interface{}) []crawler.JSONParam {
	var params []crawler.JSONParam
	walkJSON(endpoint, method, body, body, nil, &params)
	return params
}

func walkJSON(endpoint, method string, root, node map[string]interface{}, path []string, out *[]crawler.JSONParam) {
	for k, v := range node {
		p := append(append([]string{}, path...), k)
		switch vt := v.(type) {
		case string:
			*out = append(*out, crawler.JSONParam{
				Endpoint: endpoint,
				Key:      k,
				Value:    vt,
				Method:   method,
				Path:     p,
				FullBody: root,
			})
		case float64:
			*out = append(*out, crawler.JSONParam{
				Endpoint: endpoint,
				Key:      k,
				Value:    fmt.Sprintf("%v", vt),
				Method:   method,
				Path:     p,
				FullBody: root,
			})
		case map[string]interface{}:
			walkJSON(endpoint, method, root, vt, p, out)
		case []interface{}:
			// Take the first object element of any array
			for _, item := range vt {
				if obj, ok := item.(map[string]interface{}); ok {
					walkJSON(endpoint, method, root, obj, p, out)
					break
				}
			}
		}
	}
}

func isIDSeg(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			goto notNum
		}
	}
	return true
notNum:
	if len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' {
		return true
	}
	if len(s) >= 16 {
		for _, c := range s {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}
	return false
}
