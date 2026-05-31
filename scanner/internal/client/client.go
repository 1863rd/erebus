package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
}

type Options struct {
	Timeout   time.Duration
	RateLimit float64
	Proxy     string
	NoVerify  bool
	Cookie    string
	Bearer    string
	BasicAuth string   // "user:password"
	Workers   int
	Headers   []string // "Key: Value" pairs injected on every request
}

type Client struct {
	http    *http.Client
	limiter *rate.Limiter
	uaIdx   atomic.Uint64
	opts    Options
}

func New(opts Options) (*Client, error) {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.NoVerify},
		MaxIdleConns:        opts.Workers * 2,
		MaxIdleConnsPerHost: opts.Workers,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true, // negotiate HTTP/2 when TLS is used
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	var limiter *rate.Limiter
	if opts.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(opts.RateLimit), int(opts.RateLimit)+1)
	} else {
		limiter = rate.NewLimiter(rate.Inf, 0)
	}

	return &Client{
		http: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		limiter: limiter,
		opts:    opts,
	}, nil
}

// DoNoAuth sends req without injecting authentication headers (Cookie, Authorization,
// BasicAuth). UA rotation and rate-limiting still apply. Used by IDOR/auth-bypass tests.
func (c *Client) DoNoAuth(req *http.Request) (*http.Response, error) {
	if err := c.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	idx := c.uaIdx.Add(1) % uint64(len(userAgents))
	req.Header.Set("User-Agent", userAgents[idx])
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
	return c.http.Do(req)
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	c.applyHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}

	// Single retry on rate-limiting / temporary unavailability (safe methods only)
	if (resp.StatusCode == 429 || resp.StatusCode == 503) &&
		(req.Method == http.MethodGet || req.Method == http.MethodHead) {
		DrainClose(resp)
		delay := retryAfterDelay(resp.Header.Get("Retry-After"), 2*time.Second)
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
		}
		retry, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), nil)
		if err != nil {
			return nil, err
		}
		retry.Header = req.Header.Clone()
		resp, err = c.http.Do(retry)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (c *Client) Get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) PostForm(ctx context.Context, rawURL string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.Do(req)
}

// applyHeaders sets per-request headers: UA rotation, Accept, auth, custom headers.
// Custom headers (opts.Headers) can override any of these by setting the same key.
func (c *Client) applyHeaders(req *http.Request) {
	idx := c.uaIdx.Add(1) % uint64(len(userAgents))
	req.Header.Set("User-Agent", userAgents[idx])
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	}
	if c.opts.Cookie != "" && req.Header.Get("Cookie") == "" {
		req.Header.Set("Cookie", c.opts.Cookie)
	}
	if c.opts.Bearer != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+c.opts.Bearer)
	}
	if c.opts.BasicAuth != "" && req.Header.Get("Authorization") == "" {
		parts := strings.SplitN(c.opts.BasicAuth, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}
	// User-supplied headers override everything set above
	for _, h := range c.opts.Headers {
		if colon := strings.Index(h, ":"); colon > 0 {
			key := strings.TrimSpace(h[:colon])
			val := strings.TrimSpace(h[colon+1:])
			req.Header.Set(key, val)
		}
	}
}

// DoCapture sends the request and returns the response together with the raw
// HTTP request dump — ready to paste into Burp or curl for immediate replay.
func (c *Client) DoCapture(req *http.Request) (*http.Response, string, error) {
	// Dump before sending: body may be consumed by http.Client
	var reqDump string
	if raw, err := httputil.DumpRequestOut(req, true); err == nil {
		reqDump = string(raw)
	}
	resp, err := c.Do(req)
	return resp, reqDump, err
}

// ReadBodyCapture reads up to 5 MB and returns both the bytes and a truncated
// string suitable for embedding in a Finding.Response field.
func ReadBodyCapture(resp *http.Response, maxDisplay int) ([]byte, string, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, "", err
	}
	display := string(body)
	if len(display) > maxDisplay {
		display = display[:maxDisplay] + "\n[… truncated]"
	}
	return body, display, nil
}

// RebuildRequest creates a fresh copy of req with a new body reader so it can
// be sent again after DumpRequestOut has consumed the original body.
func RebuildRequest(req *http.Request, body []byte) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if len(body) > 0 {
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.ContentLength = int64(len(body))
	}
	return clone, nil
}

func ReadBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
}

func DrainClose(resp *http.Response) {
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func retryAfterDelay(header string, fallback time.Duration) time.Duration {
	if header == "" {
		return fallback
	}
	if secs, err := strconv.ParseFloat(header, 64); err == nil && secs > 0 {
		return time.Duration(secs * float64(time.Second))
	}
	return fallback
}
