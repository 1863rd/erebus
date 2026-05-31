package csrf

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

// Known CSRF token field names (case-insensitive)
var tokenFields = []string{
	"csrf", "csrftoken", "csrf_token", "_csrf", "_token", "token",
	"authenticity_token", "nonce", "xsrf", "xsrf_token",
	"__requestverificationtoken", "form_key", "security_token",
	"anti_forgery_token", "verify_token", "req_token", "form_nonce",
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "csrf" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding
	for _, form := range page.Forms {
		if ctx.Err() != nil {
			break
		}
		if strings.ToUpper(form.Method) != "POST" {
			continue
		}
		if hasCSRFField(form.Fields) {
			continue
		}
		if f := m.testForm(ctx, form, page.URL); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

func (m *Module) testForm(ctx context.Context, form crawler.Form, originPage string) *modules.Finding {
	data := make(url.Values)
	for _, f := range form.Fields {
		if f.Type == "submit" || f.Type == "button" {
			continue
		}
		if f.Value != "" {
			data.Set(f.Name, f.Value)
		} else {
			data.Set(f.Name, "test")
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, form.Action,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Deliberately omit Origin / Referer to simulate a cross-origin forged request
	req.Header.Del("Origin")
	req.Header.Del("Referer")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	client.DrainClose(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil
	}

	sev := modules.High
	if resp.StatusCode >= 300 {
		sev = modules.Medium
	}
	cvss := 8.8
	if sev == modules.Medium {
		cvss = 5.4
	}
	return &modules.Finding{
		Module:      "csrf",
		Severity:    sev,
		URL:         form.Action,
		Param:       "POST " + form.Action,
		Payload:     "cross-origin POST without Origin/Referer",
		Evidence:    fmt.Sprintf("HTTP %d — form accepted without anti-CSRF token and without Origin header", resp.StatusCode),
		Detail:      fmt.Sprintf("CSRF: state-changing form at %s has no anti-CSRF token — a malicious page can forge authenticated POST requests on behalf of a victim", form.Action),
		CWE:         "CWE-352",
		CVSS:        cvss,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
		Confidence:  modules.Likely,
		Remediation: "Add a per-session, per-form anti-CSRF token (SameSite=Strict cookies alone are insufficient for cross-site form submissions); validate Origin/Referer headers as a secondary defense",
		Tags:        []string{"csrf", "state-change", "form"},
	}
}

func hasCSRFField(fields []crawler.Field) bool {
	for _, f := range fields {
		lower := strings.ToLower(f.Name)
		for _, t := range tokenFields {
			if lower == t || strings.Contains(lower, t) {
				return true
			}
		}
	}
	return false
}
