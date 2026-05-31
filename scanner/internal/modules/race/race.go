// Package race detects race condition / TOCTOU vulnerabilities on transactional endpoints.
// Gate-synchronized goroutines fire simultaneously to expose double-spend, coupon reuse,
// concurrent limit bypass, and other time-of-check/time-of-use flaws.
package race

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

const raceN = 20

var transactionalKeywords = []string{
	"redeem", "coupon", "voucher", "promo", "discount", "apply",
	"transfer", "withdraw", "refund", "purchase", "checkout", "order",
	"pay", "payment", "buy", "subscribe", "upgrade", "claim", "use",
	"vote", "like", "follow", "invite", "register", "reward", "bonus",
	"gift", "credit", "debit", "limit", "quota", "consume",
}

type Module struct {
	client    *client.Client
	seenPaths sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "race" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	for _, form := range page.Forms {
		if form.Method != "POST" && form.Method != "PUT" && form.Method != "PATCH" {
			continue
		}
		if !isTransactional(form.Action) && !hasTransactionalField(form.Fields) {
			continue
		}
		key := "form|" + normKey(form.Action, form.Method)
		if _, loaded := m.seenPaths.LoadOrStore(key, struct{}{}); loaded {
			continue
		}
		data := buildFormData(form.Fields)
		if f := m.probe(ctx, form.Method, form.Action, "application/x-www-form-urlencoded", []byte(data)); f != nil {
			findings = append(findings, *f)
		}
	}

	u, err := url.Parse(page.URL)
	if err == nil && isTransactional(u.Path) {
		key := "url|" + normKey(page.URL, "GET")
		if _, loaded := m.seenPaths.LoadOrStore(key, struct{}{}); !loaded {
			if f := m.probe(ctx, "GET", page.URL, "", nil); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, nil
}

type raceResult struct {
	status int
	body   []byte
}

func (m *Module) probe(ctx context.Context, method, rawURL, contentType string, body []byte) *modules.Finding {
	baseline := m.single(ctx, method, rawURL, contentType, body)
	if baseline < 200 || baseline >= 300 {
		return nil
	}

	gate := make(chan struct{})
	results := make([]raceResult, raceN)
	var wg sync.WaitGroup

	for i := 0; i < raceN; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var bodyReader io.Reader
			if body != nil {
				bodyReader = bytes.NewReader(body)
			}
			req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
			if err != nil {
				return
			}
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			<-gate
			resp, err := m.client.Do(req)
			if err != nil {
				return
			}
			b, _ := client.ReadBody(resp)
			results[idx] = raceResult{status: resp.StatusCode, body: b}
		}(i)
	}

	time.Sleep(60 * time.Millisecond)
	close(gate)
	wg.Wait()

	var successes, errors int32
	var sampleBody string
	for _, r := range results {
		if r.status >= 200 && r.status < 300 {
			atomic.AddInt32(&successes, 1)
			if sampleBody == "" && len(r.body) > 0 {
				n := len(r.body)
				if n > 150 {
					n = 150
				}
				sampleBody = string(r.body[:n])
			}
		} else if r.status >= 400 {
			atomic.AddInt32(&errors, 1)
		}
	}

	if successes >= int32(raceN/4) && errors > 0 {
		return &modules.Finding{
			Module:  "race",
			Severity: modules.High,
			URL:     rawURL,
			Param:   "concurrent requests",
			Payload: fmt.Sprintf("%d simultaneous %s requests (gate-synchronized)", raceN, method),
			Evidence: fmt.Sprintf(
				"%d/%d requests returned 2xx simultaneously (%d returned 4xx) — indicates TOCTOU on transactional endpoint. Sample: %s",
				successes, raceN, errors, sampleBody,
			),
			Detail: "Race condition / TOCTOU: multiple concurrent requests all received a success response on a one-shot " +
				"transactional endpoint. Exploitable for double-spending, coupon reuse, duplicate votes, bypassing usage limits, " +
				"or multiple simultaneous account operations that should be serialized.",
			CWE:         "CWE-362",
			CVSS:        7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
			Confidence:  modules.Likely,
			Remediation: "Use atomic DB operations / SELECT FOR UPDATE; implement idempotency keys; apply optimistic locking; use SERIALIZABLE transaction isolation on balance/counter updates",
			Tags:        []string{"race-condition", "toctou", "business-logic", "double-spend"},
		}
	}
	return nil
}

func (m *Module) single(ctx context.Context, method, rawURL, contentType string, body []byte) int {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return 0
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0
	}
	client.DrainClose(resp)
	return resp.StatusCode
}

func isTransactional(s string) bool {
	low := strings.ToLower(s)
	for _, kw := range transactionalKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func hasTransactionalField(fields []crawler.Field) bool {
	for _, f := range fields {
		if isTransactional(f.Name) || isTransactional(f.Value) {
			return true
		}
	}
	return false
}

func buildFormData(fields []crawler.Field) string {
	vals := make(url.Values)
	for _, f := range fields {
		if f.Value != "" {
			vals.Set(f.Name, f.Value)
		} else {
			vals.Set(f.Name, "test")
		}
	}
	return vals.Encode()
}

func normKey(rawURL, method string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return method + "|" + rawURL
	}
	return method + "|" + u.Host + "|" + u.Path
}
