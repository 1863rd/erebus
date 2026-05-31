// Package storedxss implements a two-pass stored XSS scanner.
// Pass 1: inject canary strings into all POST form fields.
// Pass 2: re-crawl pages looking for stored canaries.
package storedxss

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

type canaryRecord struct {
	ID         string
	InjectURL  string // URL where the canary was injected
	Param      string
	FoundAt    string // URL where the canary was found (populated in pass 2)
}

type Scanner struct {
	client  *client.Client
	canaries sync.Map // canaryID → *canaryRecord
}

func New(c *client.Client) *Scanner { return &Scanner{client: c} }

// InjectPass injects unique canaries into every POST form field across all pages.
// The canary format is: EREBUS_SXSS_<8-hex> — visible in HTML without executing as JS.
// Returns the set of canary IDs for the detection pass.
func (s *Scanner) InjectPass(ctx context.Context, pages []crawler.Page) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, page := range pages {
		for _, form := range page.Forms {
			if strings.ToUpper(form.Method) != "POST" {
				continue
			}
			for _, field := range form.Fields {
				if field.Type == "hidden" || field.Type == "submit" || field.Type == "button" {
					continue
				}
				if ctx.Err() != nil {
					return
				}

				wg.Add(1)
				sem <- struct{}{}
				go func(f crawler.Form, fieldName string) {
					defer wg.Done()
					defer func() { <-sem }()

					id := newCanaryID()
					canary := "EREBUS_SXSS_" + id
					rec := &canaryRecord{
						ID:        id,
						InjectURL: f.Action,
						Param:     fieldName,
					}
					s.canaries.Store(id, rec)
					s.injectForm(ctx, f, fieldName, canary)
				}(form, field.Name)
			}
		}
	}
	wg.Wait()
}

// DetectPass re-fetches all known pages and looks for stored canaries.
// Returns findings for every canary found.
func (s *Scanner) DetectPass(ctx context.Context, pages []crawler.Page) []modules.Finding {
	// Build set of canary IDs to search for
	var ids []string
	s.canaries.Range(func(k, v interface{}) bool {
		ids = append(ids, k.(string))
		return true
	})
	if len(ids) == 0 {
		return nil
	}

	var mu sync.Mutex
	var findings []modules.Finding
	seen := make(map[string]struct{})

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, page := range pages {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p crawler.Page) {
			defer wg.Done()
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
			if err != nil {
				return
			}
			resp, err := s.client.Do(req)
			if err != nil {
				return
			}
			body, err := client.ReadBody(resp)
			if err != nil {
				return
			}
			bodyStr := string(body)

			for _, id := range ids {
				canary := "EREBUS_SXSS_" + id
				if !strings.Contains(bodyStr, canary) {
					continue
				}

				recI, ok := s.canaries.Load(id)
				if !ok {
					continue
				}
				rec := recI.(*canaryRecord)

				// Avoid duplicate findings for same canary at same URL
				dedupKey := id + "|" + p.URL
				mu.Lock()
				if _, dup := seen[dedupKey]; dup {
					mu.Unlock()
					continue
				}
				seen[dedupKey] = struct{}{}
				mu.Unlock()

				severity := modules.High
				detail := fmt.Sprintf("Stored XSS canary %q injected at %s param=%s found at %s", canary, rec.InjectURL, rec.Param, p.URL)
				if rec.InjectURL == p.URL {
					severity = modules.Medium
					detail += " (same page — may be reflected, verify persistence)"
				}

				finding := modules.Finding{
					Module:      "stored-xss",
					Severity:    severity,
					URL:         p.URL,
					Param:       rec.Param,
					Payload:     canary,
					Evidence:    fmt.Sprintf("Canary %q found at %s after injection at %s", canary, p.URL, rec.InjectURL),
					Detail:      detail,
					CWE:         "CWE-79",
					CVSS:        8.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
					Confidence:  modules.Confirmed,
					Remediation: "HTML-encode all output; use Content-Security-Policy; sanitize user-supplied HTML with an allow-list",
					Tags:        []string{"xss", "stored-xss", "persistent"},
				}
				mu.Lock()
				findings = append(findings, finding)
				mu.Unlock()
			}
		}(page)
	}
	wg.Wait()
	return findings
}

// Scan is a convenience wrapper: runs InjectPass, then DetectPass on the same pages.
func Scan(ctx context.Context, c *client.Client, pages []crawler.Page) []modules.Finding {
	s := New(c)
	s.InjectPass(ctx, pages)
	if ctx.Err() != nil {
		return nil
	}
	return s.DetectPass(ctx, pages)
}

func (s *Scanner) injectForm(ctx context.Context, form crawler.Form, targetField, value string) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, form.Action,
		strings.NewReader(data.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	client.DrainClose(resp)
}

func newCanaryID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}
