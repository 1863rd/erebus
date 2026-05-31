package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/erebus/scanner/internal/client"
	"golang.org/x/net/html"
)

type Form struct {
	Action string
	Method string
	Fields []Field
}

type Field struct {
	Name  string
	Value string
	Type  string
}

// JSONParam represents a leaf value extracted from a JSON API response body.
// Injection modules use these to test JSON body parameters without needing to
// re-discover the API structure themselves.
type JSONParam struct {
	Endpoint string
	Key      string
	Value    string
	Method   string                 // HTTP method to use when injecting (POST, PUT, PATCH)
	Path     []string               // path through nested objects: ["user", "email"]
	FullBody map[string]interface{} // the complete request body template
}

type Page struct {
	URL        string
	Forms      []Form
	Links      []string
	Body       []byte
	Headers    http.Header // response headers
	JSONParams []JSONParam // injectable params extracted from JSON API responses
	StatusCode int
}

type Crawler struct {
	client   *client.Client
	scope    *url.URL
	maxDepth int
	maxURLs  int
	workers  int
	verbose  bool
}

func New(c *client.Client, target *url.URL, maxDepth, maxURLs, workers int, verbose bool) *Crawler {
	if workers < 1 {
		workers = 24
	}
	return &Crawler{
		client:   c,
		scope:    target,
		maxDepth: maxDepth,
		maxURLs:  maxURLs,
		workers:  workers,
		verbose:  verbose,
	}
}

// jsURLPattern matches quoted relative/absolute paths in JavaScript source.
// Captures both API-style paths and generic assignment/call patterns.
var jsURLPattern = regexp.MustCompile(
	`(?:fetch|axios|XMLHttpRequest|href|src|action|url|path|endpoint|route)\s*[=(:\[]\s*["` + "`" + `']([^"` + "`" + `'\s]{4,})["` + "`" + `']` +
		`|["` + "`" + `'](/(?:api|v\d|admin|auth|user|account|static|assets|search|graphql)[a-zA-Z0-9_/.\-]*(?:\?[^"` + "`" + `'\s]*)?)["` + "`" + `']`,
)

// jsonPathPattern extracts relative URL paths from JSON response bodies.
var jsonPathPattern = regexp.MustCompile(`"(/[a-zA-Z0-9_/.\-]{2,}(?:\?[^"\s]*)?)"`)

type seenSet struct {
	mu       sync.Mutex
	patterns map[string]struct{}
	urls     map[string]struct{}
	count    int
}

func (s *seenSet) tryAdd(pattern, rawURL string, max int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.patterns[pattern]; ok {
		return false
	}
	if _, ok := s.urls[rawURL]; ok {
		return false
	}
	if s.count >= max {
		return false
	}
	s.patterns[pattern] = struct{}{}
	s.urls[rawURL] = struct{}{}
	s.count++
	return true
}

func (cr *Crawler) Run(ctx context.Context) (<-chan Page, error) {
	out := make(chan Page, 128)

	type work struct {
		rawURL string
		depth  int
	}

	queue := make(chan work, 4096)
	s := &seenSet{
		patterns: make(map[string]struct{}),
		urls:     make(map[string]struct{}),
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, cr.workers)

	enqueue := func(rawURL string, depth int) {
		wg.Add(1)
		select {
		case queue <- work{rawURL, depth}:
		default:
			wg.Done()
		}
	}

	enqueue(cr.scope.String(), 0)

	wg.Add(1)
	go func() {
		defer wg.Done()
		cr.seedExtras(ctx, enqueue)
	}()

	go func() {
		wg.Wait()
		close(queue)
	}()

	go func() {
		defer close(out)

		for item := range queue {
			item := item

			if item.depth > cr.maxDepth {
				wg.Done()
				continue
			}

			pattern := structuralPattern(item.rawURL)
			if !s.tryAdd(pattern, item.rawURL, cr.maxURLs) {
				wg.Done()
				continue
			}

			sem <- struct{}{}

			go func(w work) {
				defer wg.Done()
				defer func() { <-sem }()

				page, links := cr.fetch(ctx, w.rawURL)
				if page == nil {
					return
				}

				select {
				case out <- *page:
				case <-ctx.Done():
					return
				}

				for _, link := range links {
					if !cr.inScope(link) {
						continue
					}
					enqueue(link, w.depth+1)
				}
			}(item)
		}
	}()

	return out, nil
}

// seedExtras probes robots.txt, sitemap.xml, and common API discovery endpoints.
func (cr *Crawler) seedExtras(ctx context.Context, enqueue func(string, int)) {
	base := fmt.Sprintf("%s://%s", cr.scope.Scheme, cr.scope.Host)
	extras := []string{
		base + "/robots.txt",
		base + "/sitemap.xml",
		base + "/sitemap_index.xml",
		base + "/.well-known/openid-configuration",
		base + "/api",
		base + "/api/v1",
		base + "/api/v2",
	}
	for _, u := range extras {
		select {
		case <-ctx.Done():
			return
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := cr.client.Do(req)
		if err != nil {
			continue
		}
		body, err := client.ReadBody(resp)
		if err != nil {
			continue
		}
		for _, link := range extractTextURLs(string(body), cr.scope) {
			enqueue(link, 1)
		}
	}
}

func (cr *Crawler) fetch(ctx context.Context, rawURL string) (*Page, []string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil
	}

	resp, err := cr.client.Do(req)
	if err != nil {
		return nil, nil
	}

	ct := resp.Header.Get("Content-Type")

	// Skip binary content types that yield no parseable links
	if isBinary(ct) {
		client.DrainClose(resp)
		return nil, nil
	}

	body, err := client.ReadBody(resp)
	if err != nil {
		return nil, nil
	}

	base, _ := url.Parse(rawURL)
	var forms []Form
	var links []string

	switch {
	case isHTML(ct):
		forms, links = parseHTML(body, base)
		links = append(links, extractJSURLs(body, base)...)
	case isJSON(ct):
		links = extractJSONURLs(string(body), base)
	case isJS(ct):
		links = extractJSURLs(body, base)
	}

	var jsonParams []JSONParam
	if isJSON(ct) && isAPIPath(rawURL) {
		jsonParams = extractJSONParams(rawURL, body)
	}

	return &Page{
		URL:        rawURL,
		Forms:      forms,
		Links:      links,
		Body:       body,
		Headers:    resp.Header,
		JSONParams: jsonParams,
		StatusCode: resp.StatusCode,
	}, links
}

// extractJSONParams parses a JSON response and returns injectable leaf parameters.
// We probe the same endpoint with POST, PUT, PATCH to find the mutation surface.
func extractJSONParams(rawURL string, body []byte) []JSONParam {
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		// Try array wrapper: [{...}]
		var arr []map[string]interface{}
		if err2 := json.Unmarshal(body, &arr); err2 != nil || len(arr) == 0 {
			return nil
		}
		obj = arr[0]
	}
	if len(obj) == 0 {
		return nil
	}

	var params []JSONParam
	walkJSONObj(rawURL, "POST", obj, obj, nil, &params)
	return params
}

func walkJSONObj(endpoint, method string, root, node map[string]interface{}, path []string, out *[]JSONParam) {
	for k, v := range node {
		p := append(append([]string{}, path...), k)
		switch vt := v.(type) {
		case string:
			*out = append(*out, JSONParam{
				Endpoint: endpoint, Key: k, Value: vt,
				Method: method, Path: p, FullBody: root,
			})
		case float64:
			*out = append(*out, JSONParam{
				Endpoint: endpoint, Key: k, Value: fmt.Sprintf("%v", vt),
				Method: method, Path: p, FullBody: root,
			})
		case map[string]interface{}:
			walkJSONObj(endpoint, method, root, vt, p, out)
		case []interface{}:
			for _, item := range vt {
				if sub, ok := item.(map[string]interface{}); ok {
					walkJSONObj(endpoint, method, root, sub, p, out)
					break
				}
			}
		}
	}
}

func isAPIPath(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	for _, seg := range []string{"/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/service/", "/endpoint"} {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}

func parseHTML(body []byte, base *url.URL) ([]Form, []string) {
	var forms []Form
	var links []string

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, nil
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a", "link":
				if href := attr(n, "href"); href != "" {
					if resolved := resolveURL(base, href); resolved != "" {
						links = append(links, resolved)
					}
				}
			case "script":
				if src := attr(n, "src"); src != "" {
					if resolved := resolveURL(base, src); resolved != "" {
						links = append(links, resolved)
					}
				}
			case "form":
				forms = append(forms, parseForm(n, base))
			case "iframe", "frame":
				if src := attr(n, "src"); src != "" {
					if resolved := resolveURL(base, src); resolved != "" {
						links = append(links, resolved)
					}
				}
			}
			// Extract data-url / data-href / data-src attributes
			for _, a := range n.Attr {
				if a.Key == "data-url" || a.Key == "data-href" || a.Key == "data-src" || a.Key == "data-action" {
					if resolved := resolveURL(base, a.Val); resolved != "" {
						links = append(links, resolved)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	return forms, links
}

func parseForm(n *html.Node, base *url.URL) Form {
	action := attr(n, "action")
	if action == "" {
		action = base.String()
	} else {
		action = resolveURL(base, action)
	}
	method := strings.ToUpper(attr(n, "method"))
	if method == "" {
		method = "GET"
	}

	var fields []Field
	var walkInputs func(*html.Node)
	walkInputs = func(child *html.Node) {
		if child.Type == html.ElementNode {
			switch child.Data {
			case "input", "textarea", "select":
				name := attr(child, "name")
				if name != "" {
					fields = append(fields, Field{
						Name:  name,
						Value: attr(child, "value"),
						Type:  attr(child, "type"),
					})
				}
			}
		}
		for c := child.FirstChild; c != nil; c = c.NextSibling {
			walkInputs(c)
		}
	}
	walkInputs(n)

	return Form{Action: action, Method: method, Fields: fields}
}

func extractJSURLs(body []byte, base *url.URL) []string {
	matches := jsURLPattern.FindAllSubmatch(body, -1)
	seen := make(map[string]struct{})
	var result []string
	for _, m := range matches {
		// Group 1: assignment/call pattern; Group 2: API path pattern
		for _, g := range m[1:] {
			if len(g) == 0 {
				continue
			}
			if resolved := resolveURL(base, string(g)); resolved != "" {
				if _, ok := seen[resolved]; !ok {
					seen[resolved] = struct{}{}
					result = append(result, resolved)
				}
			}
		}
	}
	return result
}

func extractJSONURLs(text string, base *url.URL) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, m := range jsonPathPattern.FindAllStringSubmatch(text, -1) {
		if len(m) < 2 {
			continue
		}
		if resolved := resolveURL(base, m[1]); resolved != "" {
			if _, ok := seen[resolved]; !ok {
				seen[resolved] = struct{}{}
				result = append(result, resolved)
			}
		}
	}
	return result
}

var sitemapURLPattern = regexp.MustCompile(`<loc>\s*(https?://[^\s<]+)\s*</loc>`)
var robotsDisallowPattern = regexp.MustCompile(`(?i)(?:Disallow|Allow):\s*(/[^\s]*)`)

func extractTextURLs(text string, scope *url.URL) []string {
	seen := make(map[string]struct{})
	var result []string

	add := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		if u.Host == "" {
			u.Scheme = scope.Scheme
			u.Host = scope.Host
		}
		if u.Host != scope.Host {
			return
		}
		s := u.String()
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}

	for _, m := range sitemapURLPattern.FindAllStringSubmatch(text, -1) {
		add(strings.TrimSpace(m[1]))
	}
	for _, m := range robotsDisallowPattern.FindAllStringSubmatch(text, -1) {
		add(strings.TrimSpace(m[1]))
	}
	return result
}

func structuralPattern(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	segments := strings.Split(u.Path, "/")
	for i, seg := range segments {
		if isID(seg) {
			segments[i] = "{id}"
		}
	}
	u.Path = strings.Join(segments, "/")
	u.RawQuery = normalizeQuery(u.RawQuery)
	u.Fragment = ""
	return u.String()
}

var numericID = regexp.MustCompile(`^\d+$`)
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var hashRe = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)

func isID(s string) bool {
	return numericID.MatchString(s) || uuidRe.MatchString(s) || hashRe.MatchString(s)
}

func normalizeQuery(q string) string {
	if q == "" {
		return ""
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		return q
	}
	norm := make(url.Values)
	for k := range vals {
		norm[k] = []string{"x"}
	}
	return norm.Encode()
}

func resolveURL(base *url.URL, ref string) string {
	if ref == "" || strings.HasPrefix(ref, "#") ||
		strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") ||
		strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "tel:") {
		return ""
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(refURL)
	resolved.Fragment = ""
	return resolved.String()
}

func (cr *Crawler) inScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Hostname() == cr.scope.Hostname() &&
		(u.Scheme == "http" || u.Scheme == "https")
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func isHTML(ct string) bool {
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

func isJSON(ct string) bool {
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "text/json")
}

func isJS(ct string) bool {
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "text/js")
}

func isBinary(ct string) bool {
	for _, prefix := range []string{
		"image/", "video/", "audio/", "font/",
		"application/pdf", "application/zip", "application/octet-stream",
		"application/x-tar", "application/x-gzip",
	} {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}
