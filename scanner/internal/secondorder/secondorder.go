// Package secondorder detects second-order injection vulnerabilities: data planted
// via one endpoint that executes as SQL, template, or XSS payload on a different
// endpoint. Two-pass scan: plant canaries → harvest reflections/evaluations.
package secondorder

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/modules"
	"golang.org/x/net/html"
)

// Multi-purpose canary: {{7777*7777}} evaluates to 60481729 in Jinja2/Twig/FreeMarker/EL.
// Using a large product makes the result unique enough to avoid collision with page data.
const (
	sstiCanary     = "erebus2O_{{7777*7777}}_${7777*7777}"
	sstiEval       = "60481729"
	plainCanaryPfx = "erebus2Oplain_"
	sqliCanary     = "erebus2Osql'"
)

var sqlErrorPatterns = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark",
	"pg::syntaxerror",
	"org.postgresql.util.psqlexception",
	"microsoft ole db provider for sql server",
	"sqlite3.operationalerror",
	"ora-01756", "ora-00933",
	"syntax error or access violation",
	"unterminated string literal",
	"division by zero",
	"invalid column name",
	"column count doesn't match",
}

type canaryRecord struct {
	sourceURL string
	param     string
	canary    string
}

// Scan performs a two-pass second-order injection probe.
// Pass 1 — discover POST forms on each URL and inject canaries.
// Pass 2 — re-fetch all URLs and check for canary reflection, SSTI evaluation, or SQL errors.
func Scan(ctx context.Context, c *client.Client, visitedURLs []string) []modules.Finding {
	if len(visitedURLs) == 0 {
		return nil
	}

	// Deduplicate and cap
	seen := make(map[string]struct{})
	var urls []string
	for _, u := range visitedURLs {
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		urls = append(urls, u)
		if len(urls) >= 150 {
			break
		}
	}

	var (
		recordMu sync.Mutex
		records  []canaryRecord
	)

	// Pass 1: plant canaries via POST forms
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, rawURL := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pageURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			recs := plantInForms(ctx, c, pageURL)
			if len(recs) > 0 {
				recordMu.Lock()
				records = append(records, recs...)
				recordMu.Unlock()
			}
		}(rawURL)
	}
	wg.Wait()

	if len(records) == 0 || ctx.Err() != nil {
		return nil
	}

	// Brief pause — let the server persist the writes before reading back
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
		return nil
	}

	// Pass 2: re-fetch all URLs, check for canary traces
	var (
		findings []modules.Finding
		findMu   sync.Mutex
	)

	for _, rawURL := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pageURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
			if err != nil {
				return
			}
			resp, err := c.Do(req)
			if err != nil {
				return
			}
			body, err := client.ReadBody(resp)
			if err != nil {
				return
			}
			bodyStr := string(body)
			bodyLow := strings.ToLower(bodyStr)

			// Also search response headers (Location, Set-Cookie) for canary reflections
			locationHdr := resp.Header.Get("Location")
			setCookieHdr := strings.Join(resp.Header["Set-Cookie"], " ")

			recordMu.Lock()
			snap := make([]canaryRecord, len(records))
			copy(snap, records)
			recordMu.Unlock()

			for _, rec := range snap {
				var f *modules.Finding

				switch {
				case strings.Contains(rec.canary, "7777*7777") && strings.Contains(bodyStr, sstiEval):
					f = &modules.Finding{
						Module:      "secondorder",
						Severity:    modules.Critical,
						URL:         pageURL,
						Param:       rec.param,
						Payload:     rec.canary,
						Evidence:    fmt.Sprintf("Second-order SSTI: expression {{7777*7777}} injected via %s evaluated to %s on %s", rec.sourceURL, sstiEval, pageURL),
						Detail:      "Second-order template injection: a math expression injected into a storage endpoint was later evaluated by a server-side template engine on a different page. An attacker can escalate this to arbitrary code execution.",
						CWE:         "CWE-94",
						CVSS:        9.8,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
						Confidence:  modules.Confirmed,
						Remediation: "Never pass stored user data through template engines; escape/sandbox template rendering",
						Tags:        []string{"ssti", "second-order", "rce-potential", "stored"},
					}

				case strings.HasPrefix(rec.canary, sqliCanary):
					for _, pat := range sqlErrorPatterns {
						if strings.Contains(bodyLow, pat) {
							f = &modules.Finding{
								Module:      "secondorder",
								Severity:    modules.High,
								URL:         pageURL,
								Param:       rec.param,
								Payload:     rec.canary,
								Evidence:    fmt.Sprintf("Second-order SQLi: SQL error %q on %s after injecting quote via %s", pat, pageURL, rec.sourceURL),
								Detail:      "Second-order SQL injection: a single quote stored in one endpoint caused a SQL syntax error when the value was later used in a database query on a different endpoint. Use parameterized queries when re-using stored user data.",
								CWE:         "CWE-89",
								CVSS:        9.1,
								CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
								Confidence:  modules.Likely,
								Remediation: "Parameterize all SQL queries, including those that read from the database; never interpolate stored strings into SQL",
								Tags:        []string{"sqli", "second-order", "stored"},
							}
							break
						}
					}

				case strings.HasPrefix(rec.canary, plainCanaryPfx) && strings.Contains(bodyStr, rec.canary):
					if containsUnescaped(bodyStr, rec.canary) {
						f = &modules.Finding{
							Module:      "secondorder",
							Severity:    modules.High,
							URL:         pageURL,
							Param:       rec.param,
							Payload:     rec.canary,
							Evidence:    fmt.Sprintf("Stored reflection: canary %q planted at %s reflected unescaped in HTML on %s", rec.canary, rec.sourceURL, pageURL),
							Detail:      "Second-order stored XSS risk: user-supplied data injected via one endpoint is reflected unescaped in an HTML context on a different endpoint. An attacker can store a script payload for persistent XSS.",
							CWE:         "CWE-79",
							CVSS:        8.1,
							CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
							Confidence:  modules.Likely,
							Remediation: "HTML-encode all stored user content at render time; apply Content Security Policy",
							Tags:        []string{"xss", "stored-xss", "second-order"},
						}
					}

				// Canary in Location header — open redirect or account-linking hijack via stored value
				case strings.HasPrefix(rec.canary, plainCanaryPfx) &&
					(strings.Contains(locationHdr, rec.canary) || strings.Contains(setCookieHdr, rec.canary)):
					where := "Location header"
					if strings.Contains(setCookieHdr, rec.canary) {
						where = "Set-Cookie header"
					}
					f = &modules.Finding{
						Module:      "secondorder",
						Severity:    modules.High,
						URL:         pageURL,
						Param:       rec.param,
						Payload:     rec.canary,
						Evidence:    fmt.Sprintf("Stored canary %q planted at %s appeared in %s on %s", rec.canary, rec.sourceURL, where, pageURL),
						Detail:      fmt.Sprintf("Second-order header injection: a value stored via one endpoint was later reflected in a response %s on a different page. Depending on content, this could enable open redirect, cookie injection, or response splitting.", where),
						CWE:         "CWE-113",
						CVSS:        7.4,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N",
						Confidence:  modules.Likely,
						Remediation: "Sanitize stored user data before using it in HTTP response headers; validate and encode values in Location and Set-Cookie headers",
						Tags:        []string{"header-injection", "second-order", "stored", "open-redirect"},
					}
				}

				if f != nil {
					findMu.Lock()
					findings = append(findings, *f)
					findMu.Unlock()
					break
				}
			}
		}(rawURL)
	}
	wg.Wait()

	return dedupFindings(findings)
}

// plantInForms fetches a URL, extracts POST forms, and submits canaries into text fields.
func plantInForms(ctx context.Context, c *client.Client, pageURL string) []canaryRecord {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil
	}

	forms := extractForms(pageURL, body)
	var recs []canaryRecord

	for _, form := range forms {
		if strings.ToUpper(form.method) != "POST" || form.action == "" {
			continue
		}
		for _, fieldName := range form.textFields {
			for _, canary := range []string{
				sstiCanary,
				sqliCanary + fieldName,
				plainCanaryPfx + fieldName,
			} {
				data := make(url.Values)
				for _, f := range form.allFields {
					if f.name == fieldName {
						data.Set(f.name, canary)
					} else if f.value != "" {
						data.Set(f.name, f.value)
					} else {
						data.Set(f.name, "test")
					}
				}
				pReq, err := http.NewRequestWithContext(ctx, http.MethodPost, form.action,
					strings.NewReader(data.Encode()))
				if err != nil {
					continue
				}
				pReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				pResp, err := c.Do(pReq)
				if err != nil {
					continue
				}
				client.DrainClose(pResp)
				if pResp.StatusCode >= 200 && pResp.StatusCode < 400 {
					recs = append(recs, canaryRecord{
						sourceURL: pageURL,
						param:     fieldName,
						canary:    canary,
					})
				}
			}
		}
	}
	return recs
}

type formField struct{ name, value string }

type formInfo struct {
	action     string
	method     string
	allFields  []formField
	textFields []string
}

func extractForms(pageURL string, body []byte) []formInfo {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	base, _ := url.Parse(pageURL)
	var forms []formInfo

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			var fi formInfo
			fi.method = "GET"
			for _, a := range n.Attr {
				switch strings.ToLower(a.Key) {
				case "action":
					if ref, err2 := url.Parse(a.Val); err2 == nil {
						fi.action = base.ResolveReference(ref).String()
					}
				case "method":
					fi.method = strings.ToUpper(a.Val)
				}
			}
			if fi.action == "" {
				fi.action = pageURL
			}
			var collectInputs func(*html.Node)
			collectInputs = func(nn *html.Node) {
				if nn.Type == html.ElementNode && (nn.Data == "input" || nn.Data == "textarea") {
					var name, value, typ string
					for _, a := range nn.Attr {
						switch strings.ToLower(a.Key) {
						case "name":
							name = a.Val
						case "value":
							value = a.Val
						case "type":
							typ = strings.ToLower(a.Val)
						}
					}
					if name != "" {
						fi.allFields = append(fi.allFields, formField{name, value})
						if typ == "" || typ == "text" || typ == "email" || typ == "search" || typ == "url" || nn.Data == "textarea" {
							fi.textFields = append(fi.textFields, name)
						}
					}
				}
				for child := nn.FirstChild; child != nil; child = child.NextSibling {
					collectInputs(child)
				}
			}
			collectInputs(n)
			forms = append(forms, fi)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return forms
}

// containsUnescaped returns true if needle appears in body not preceded by HTML entity encoding.
func containsUnescaped(body, needle string) bool {
	idx := strings.Index(body, needle)
	if idx < 0 {
		return false
	}
	start := idx - 30
	if start < 0 {
		start = 0
	}
	before := body[start:idx]
	return !strings.Contains(before, "&amp;") && !strings.Contains(before, "&#")
}

func dedupFindings(findings []modules.Finding) []modules.Finding {
	seen := make(map[string]struct{})
	var out []modules.Finding
	for _, f := range findings {
		key := f.URL + "|" + f.Param + "|" + f.Module
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}
