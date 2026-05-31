package engine

import (
	"context"
	"net/url"
	"strings"
	"sync"

	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
	"github.com/erebus/scanner/internal/waf"
)

type Engine struct {
	crawler    *crawler.Crawler
	mods       []modules.Module
	workers    int
	wafResult  *waf.Result
}

func (e *Engine) SetWAF(r *waf.Result) { e.wafResult = r }

func New(cr *crawler.Crawler, mods []modules.Module, workers int) *Engine {
	return &Engine{crawler: cr, mods: mods, workers: workers}
}

func (e *Engine) Run(ctx context.Context) (<-chan modules.Finding, <-chan string, error) {
	return e.RunWithExtra(ctx, nil)
}

// RunWithExtra is like Run but also dispatches modules over extra pre-built pages
// (e.g. from OpenAPI spec discovery or headless browser crawl) in addition to the
// pages produced by the crawler. Extra pages are fed into the pipeline before the
// crawler finishes so they are processed concurrently.
func (e *Engine) RunWithExtra(ctx context.Context, extra []crawler.Page) (<-chan modules.Finding, <-chan string, error) {
	// Inject WAF result into context so all modules can access bypass payloads
	if e.wafResult != nil {
		ctx = waf.WithContext(ctx, e.wafResult)
	}

	pages, err := e.crawler.Run(ctx)
	if err != nil {
		return nil, nil, err
	}

	findings := make(chan modules.Finding, 512)
	visited := make(chan string, 512)

	sem := make(chan struct{}, e.workers)
	dedup := &dedupSet{}
	pageDedup := &dedupSet{}
	var wg sync.WaitGroup

	dispatch := func(page crawler.Page) {
		select {
		case visited <- page.URL:
		default:
		}

		for _, mod := range e.mods {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(m modules.Module, p crawler.Page) {
				defer wg.Done()
				defer func() { <-sem }()

				if isInjectionModule(m.Name()) && !pageDedup.markPage(m.Name(), p.URL) {
					return
				}

				results, err := m.Run(ctx, p)
				if err != nil || len(results) == 0 {
					return
				}

				for _, f := range results {
					key := f.Module + "|" + f.URL + "|" + f.Param + "|" + f.Payload
					if !dedup.add(key) {
						continue
					}
					select {
					case findings <- f:
					case <-ctx.Done():
						return
					}
				}
			}(mod, page)
		}
	}

	go func() {
		defer close(findings)
		defer close(visited)

		// Dispatch extra pages first (spec/browser discovery results)
		for _, page := range extra {
			select {
			case <-ctx.Done():
				goto drain
			default:
			}
			dispatch(page)
		}

		// Then process crawler pages
		for page := range pages {
			select {
			case <-ctx.Done():
				goto drain
			default:
			}
			dispatch(page)
		}

	drain:
		wg.Wait()
	}()

	return findings, visited, nil
}

// isInjectionModule returns true for modules that probe URL/form parameters
// or perform per-page active testing (eligible for structural deduplication).
func isInjectionModule(name string) bool {
	switch name {
	case "sqli", "xss", "ssti", "rce", "lfi", "ssrf", "xxe", "openredirect", "csrf", "idor", "jwt",
		"prototype", "deserialization", "cache", "massassign", "ratelimit",
		"crlf", "race", "logic", "bypass403", "nosql",
		"enumeration", "paraminer", "hpp", "hostheader", "bfla":
		return true
	}
	return false
}

type dedupSet struct {
	mu   sync.Mutex
	keys map[string]struct{}
}

func (d *dedupSet) add(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.keys == nil {
		d.keys = make(map[string]struct{})
	}
	if _, ok := d.keys[key]; ok {
		return false
	}
	d.keys[key] = struct{}{}
	return true
}

// markPage returns true the first time (module, host+structuralPath) is seen.
func (d *dedupSet) markPage(moduleName, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	key := moduleName + "|" + u.Host + "|" + structuralPath(u.Path)
	return d.add(key)
}

func structuralPath(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if isIDSegment(seg) {
			segments[i] = "{id}"
		}
	}
	return strings.Join(segments, "/")
}

func isIDSegment(s string) bool {
	if len(s) == 0 {
		return false
	}
	allDigit := true
	for _, c := range s {
		if c < '0' || c > '9' {
			allDigit = false
			break
		}
	}
	if allDigit {
		return true
	}
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
