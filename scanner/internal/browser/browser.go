// Package browser provides headless Chrome-based SPA discovery.
// It intercepts XHR/fetch network requests made by JavaScript-heavy
// applications and returns them as synthetic crawler pages for injection testing.
package browser

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/erebus/scanner/internal/crawler"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// Discover launches a headless browser, navigates to targetURL, interacts
// with the page to trigger JavaScript, and returns all discovered API endpoints
// as synthetic crawler pages. noVerify skips TLS certificate verification.
func Discover(ctx context.Context, targetURL string, noVerify bool) ([]crawler.Page, error) {
	scope, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	launch := launcher.New().
		Headless(true).
		NoSandbox(true).
		Set("disable-web-security", "").
		Set("ignore-certificate-errors", "")

	if noVerify {
		launch = launch.Set("ignore-certificate-errors", "true")
	}

	controlURL, err := launch.Launch()
	if err != nil {
		return nil, err
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		return nil, err
	}
	defer browser.Close()

	var mu sync.Mutex
	seen := make(map[string]struct{})
	var pages []crawler.Page

	addPage := func(rawURL string) {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host != scope.Host {
			return
		}
		// Strip fragment
		u.Fragment = ""
		clean := u.String()

		mu.Lock()
		defer mu.Unlock()
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}

		page := crawler.Page{URL: clean}
		pages = append(pages, page)
	}

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, err
	}

	// Intercept all network requests to capture API calls
	router := page.HijackRequests()
	router.MustAdd("*", func(ctx *rod.Hijack) {
		req := ctx.Request
		reqURL := req.URL().String()

		// Only capture in-scope XHR/fetch/API calls
		if isAPIRequest(reqURL, string(req.Type()), scope.Host) {
			addPage(reqURL)
		}
		ctx.ContinueRequest(&proto.FetchContinueRequest{})
	})
	go router.Run()
	defer router.Stop()

	// Navigate to target
	pageCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := page.Context(pageCtx).Navigate(targetURL); err != nil {
		return pages, nil
	}
	_ = page.WaitLoad()

	// Interact: scroll, click common interactive elements to trigger JS
	interact(page, pageCtx)

	// Also extract hrefs and SPA route links from the DOM
	extractDOMLinks(page, scope, addPage)

	return pages, nil
}

// interact scrolls the page and triggers common JS interactions to surface more endpoints.
func interact(page *rod.Page, ctx context.Context) {
	// Scroll down in steps to trigger lazy-load content
	for i := 0; i < 5; i++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
		page.MustEval(`window.scrollBy(0, window.innerHeight)`)
	}

	// Click buttons and links that might trigger navigation or AJAX
	elements, err := page.Elements("button, [role='button'], [data-action], a[href^='/'], nav a")
	if err != nil {
		return
	}
	for i, el := range elements {
		if i >= 10 {
			break
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = el.Click(proto.InputMouseButtonLeft, 1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
		// Navigate back if we left the page
		_ = page.MustEval(`window.history.back()`)
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// extractDOMLinks walks the current DOM for anchor hrefs and data-* URL attributes.
func extractDOMLinks(page *rod.Page, scope *url.URL, add func(string)) {
	result, err := page.Eval(`
		(function() {
			var urls = [];
			document.querySelectorAll('a[href], [data-url], [data-href], [data-src]').forEach(function(el) {
				var u = el.href || el.getAttribute('data-url') || el.getAttribute('data-href') || el.getAttribute('data-src');
				if (u) urls.push(u);
			});
			return urls;
		})()
	`)
	if err != nil {
		return
	}

	links := result.Value.Arr()
	for _, l := range links {
		rawURL := l.String()
		if strings.HasPrefix(rawURL, "http") || strings.HasPrefix(rawURL, "/") {
			if strings.HasPrefix(rawURL, "/") {
				rawURL = scope.Scheme + "://" + scope.Host + rawURL
			}
			add(rawURL)
		}
	}
}

func isAPIRequest(rawURL, reqType, host string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host != host {
		return false
	}

	// Always capture XHR/Fetch
	if reqType == "XHR" || reqType == "Fetch" {
		return true
	}

	// Capture document navigations that look like API paths
	path := strings.ToLower(u.Path)
	for _, prefix := range []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/service/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
