// Package enumeration detects user enumeration vulnerabilities on authentication endpoints.
// It identifies when an application leaks whether a user/email exists via different
// response sizes, status codes, error messages, or response timing.
package enumeration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

var authPaths = []string{
	"/login", "/signin", "/auth/login", "/api/login", "/api/auth/login",
	"/api/signin", "/rest/user/login", "/user/login", "/account/login",
	"/auth", "/api/v1/login", "/api/v2/login",
}

var resetPaths = []string{
	"/forgot-password", "/password-reset", "/reset-password",
	"/api/password-reset", "/api/forgot-password", "/auth/reset",
	"/user/forgot", "/users/password",
}

// existenceSignals — phrases that appear when a user EXISTS (wrong password)
var existenceSignals = []string{
	"password incorrect", "wrong password", "invalid password",
	"password does not match", "bad credentials", "incorrect password",
	"the password you entered", "your password is wrong",
}

// nonExistenceSignals — phrases that appear when a user does NOT exist
var nonExistenceSignals = []string{
	"user not found", "no account found", "email not found",
	"no user found", "account does not exist", "email address not registered",
	"we couldn't find", "unknown email", "invalid email or password",
}

type Module struct {
	client    *client.Client
	seenPaths sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "enumeration" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}
	host := u.Scheme + "://" + u.Host
	if _, loaded := m.seenPaths.LoadOrStore(host, struct{}{}); loaded {
		return nil, nil
	}

	var findings []modules.Finding

	// Test login endpoints for username/email enumeration
	for _, path := range authPaths {
		if ctx.Err() != nil {
			break
		}
		findings = append(findings, m.testLoginEnumeration(ctx, host+path)...)
	}

	// Test password reset endpoints for email enumeration
	for _, path := range resetPaths {
		if ctx.Err() != nil {
			break
		}
		if f := m.testResetEnumeration(ctx, host+path); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// testLoginEnumeration probes a login endpoint with valid-looking vs invalid credentials.
func (m *Module) testLoginEnumeration(ctx context.Context, testURL string) []modules.Finding {
	// Baseline: confirm endpoint exists and accepts POST
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodPost, testURL,
		strings.NewReader("email=nonexistent_erebus_test@nowhere.invalid&password=erebusTestPass1!"))
	if err != nil {
		return nil
	}
	baseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	baseResp, err := m.client.Do(baseReq)
	if err != nil {
		return nil
	}
	baseBody, _ := client.ReadBody(baseResp)
	if baseResp.StatusCode == 404 || baseResp.StatusCode == 405 || baseResp.StatusCode >= 500 {
		return nil
	}
	if isHTMLSPA(baseResp.Header.Get("Content-Type"), baseBody) {
		return nil
	}

	baseStr := strings.ToLower(string(baseBody))

	// Test with a plausible existing email (admin@<host>)
	hostPart := extractHost(testURL)
	existEmail := "admin@" + hostPart

	existReq, err := http.NewRequestWithContext(ctx, http.MethodPost, testURL,
		strings.NewReader("email="+url.QueryEscape(existEmail)+"&password=erebusTestPass1!"))
	if err != nil {
		return nil
	}
	existReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	existResp, err := m.client.Do(existReq)
	if err != nil {
		return nil
	}
	existBody, _ := client.ReadBody(existResp)
	existStr := strings.ToLower(string(existBody))

	var findings []modules.Finding

	// Check 1: error message distinguishes existing vs non-existing user
	nonExistMsg := findSignal(baseStr, nonExistenceSignals)
	existMsg := findSignal(existStr, existenceSignals)
	if nonExistMsg != "" && existMsg != "" && nonExistMsg != existMsg {
		findings = append(findings, modules.Finding{
			Module:  "enumeration",
			Severity: modules.Medium,
			URL:      testURL,
			Param:    "email",
			Payload:  fmt.Sprintf("non-exist: %s | exist: %s", "nonexistent_erebus_test@nowhere.invalid", existEmail),
			Evidence: fmt.Sprintf("Non-existent user: %q — Existing user: %q — different error messages reveal account existence",
				nonExistMsg, existMsg),
			Detail:      "Username/email enumeration via distinct error messages: the application returns different responses for existing vs non-existing accounts, allowing an attacker to enumerate valid usernames or email addresses",
			CWE:         "CWE-204",
			CVSS:        5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Always return the same error message regardless of whether the account exists (e.g., 'Invalid credentials')",
			Tags:        []string{"enumeration", "user-enum", "information-disclosure", "auth"},
		})
	}

	// Check 2: response size differs significantly (>10% for same status code)
	if baseResp.StatusCode == existResp.StatusCode {
		baseLen := len(baseBody)
		existLen := len(existBody)
		if baseLen > 0 {
			diff := existLen - baseLen
			if diff < 0 {
				diff = -diff
			}
			ratio := float64(diff) / float64(baseLen)
			if ratio > 0.10 && diff > 20 {
				findings = append(findings, modules.Finding{
					Module:   "enumeration",
					Severity: modules.Low,
					URL:      testURL,
					Param:    "email",
					Payload:  fmt.Sprintf("non-exist: %d bytes | exist: %d bytes", baseLen, existLen),
					Evidence: fmt.Sprintf("Response size difference: %d vs %d bytes (%.0f%%) for same status %d — may indicate account existence",
						baseLen, existLen, ratio*100, baseResp.StatusCode),
					Detail:      "Potential username enumeration via response size: a size difference in otherwise identical responses may allow distinguishing existing from non-existing accounts",
					CWE:         "CWE-204",
					CVSS:        3.7,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
					Confidence:  modules.Potential,
					Remediation: "Return identical response bodies (and sizes) regardless of account existence; use a fixed-length error response template",
					Tags:        []string{"enumeration", "user-enum", "timing"},
				})
			}
		}
	}

	// Check 3: timing-based enumeration (repeat requests to measure latency)
	timingFinding := m.testTiming(ctx, testURL, "nonexistent_erebus_test@nowhere.invalid", existEmail)
	if timingFinding != nil {
		findings = append(findings, *timingFinding)
	}

	return findings
}

// testTiming measures response time difference between existing and non-existing accounts.
func (m *Module) testTiming(ctx context.Context, testURL, nonExistEmail, existEmail string) *modules.Finding {
	measure := func(email string) time.Duration {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, testURL,
			strings.NewReader("email="+url.QueryEscape(email)+"&password=erebusTestTimingPass1!"))
		if err != nil {
			return 0
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := m.client.Do(req)
		if err != nil {
			return 0
		}
		client.DrainClose(resp)
		return time.Since(start)
	}

	// Take 3 samples each and compare medians
	var nonExistTimes, existTimes []time.Duration
	for i := 0; i < 3; i++ {
		if ctx.Err() != nil {
			return nil
		}
		nonExistTimes = append(nonExistTimes, measure(nonExistEmail))
		existTimes = append(existTimes, measure(existEmail))
	}

	nonExistMed := median(nonExistTimes)
	existMed := median(existTimes)
	if nonExistMed == 0 || existMed == 0 {
		return nil
	}

	diff := existMed - nonExistMed
	if diff < 0 {
		diff = -diff
	}
	// Report only if consistently >150ms difference (password hashing for existing users)
	if diff > 150*time.Millisecond && float64(diff)/float64(nonExistMed+1) > 0.30 {
		return &modules.Finding{
			Module:   "enumeration",
			Severity: modules.Low,
			URL:      testURL,
			Param:    "email",
			Payload:  fmt.Sprintf("timing: non-exist avg=%v, exist avg=%v", nonExistMed, existMed),
			Evidence: fmt.Sprintf("Timing difference: ~%v for non-existing account vs ~%v for existing account — %v gap suggests password hashing only runs for valid users",
				nonExistMed.Round(time.Millisecond), existMed.Round(time.Millisecond), diff.Round(time.Millisecond)),
			Detail:      "Timing-based user enumeration: the application takes significantly longer to respond for existing accounts (likely because it only runs the password hash comparison for valid users), allowing enumeration via response timing",
			CWE:         "CWE-208",
			CVSS:        3.7,
			CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Confidence:  modules.Potential,
			Remediation: "Always perform password hashing regardless of whether the account exists; use constant-time comparison; add random jitter to auth responses",
			Tags:        []string{"enumeration", "timing", "user-enum", "auth"},
		}
	}
	return nil
}

// testResetEnumeration checks if a password reset endpoint reveals account existence.
func (m *Module) testResetEnumeration(ctx context.Context, testURL string) *modules.Finding {
	// Non-existent email baseline
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodPost, testURL,
		strings.NewReader("email=nonexistent_erebus_test@nowhere.invalid"))
	if err != nil {
		return nil
	}
	baseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	baseResp, err := m.client.Do(baseReq)
	if err != nil {
		return nil
	}
	baseBody, _ := client.ReadBody(baseResp)
	if baseResp.StatusCode == 404 || baseResp.StatusCode == 405 || baseResp.StatusCode >= 500 {
		return nil
	}
	if isHTMLSPA(baseResp.Header.Get("Content-Type"), baseBody) {
		return nil
	}
	baseStr := strings.ToLower(string(baseBody))

	// Existing email probe
	hostPart := extractHost(testURL)
	existEmail := "admin@" + hostPart
	existReq, err := http.NewRequestWithContext(ctx, http.MethodPost, testURL,
		strings.NewReader("email="+url.QueryEscape(existEmail)))
	if err != nil {
		return nil
	}
	existReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	existResp, err := m.client.Do(existReq)
	if err != nil {
		return nil
	}
	existBody, _ := client.ReadBody(existResp)
	existStr := strings.ToLower(string(existBody))

	// Status code leak
	if baseResp.StatusCode != existResp.StatusCode {
		return &modules.Finding{
			Module:   "enumeration",
			Severity: modules.Medium,
			URL:      testURL,
			Param:    "email",
			Payload:  fmt.Sprintf("non-exist: HTTP %d | exist: HTTP %d", baseResp.StatusCode, existResp.StatusCode),
			Evidence: fmt.Sprintf("Password reset returns HTTP %d for non-existing email vs HTTP %d for existing email",
				baseResp.StatusCode, existResp.StatusCode),
			Detail:      "Email enumeration via password reset: different HTTP status codes reveal whether an email address is registered, enabling targeted phishing and credential stuffing",
			CWE:         "CWE-204",
			CVSS:        5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Always return HTTP 200 and the same message regardless of whether the email exists",
			Tags:        []string{"enumeration", "email-enum", "password-reset", "auth"},
		}
	}

	// Message leak
	nonExistMsg := findSignal(baseStr, nonExistenceSignals)
	existMsg := findSignal(existStr, existenceSignals)
	if nonExistMsg != "" || existMsg != "" {
		return &modules.Finding{
			Module:   "enumeration",
			Severity: modules.Medium,
			URL:      testURL,
			Param:    "email",
			Payload:  fmt.Sprintf("non-exist signal: %q / exist signal: %q", nonExistMsg, existMsg),
			Evidence: fmt.Sprintf("Reset endpoint leaks email existence: %q for non-existing vs %q for existing",
				nonExistMsg, existMsg),
			Detail:      "Email enumeration via password reset error message: the application reveals whether an email is registered, enabling account discovery",
			CWE:         "CWE-204",
			CVSS:        5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Return the same response body for all reset requests regardless of email existence (e.g., 'If this email is registered, you will receive a link')",
			Tags:        []string{"enumeration", "email-enum", "password-reset", "auth"},
		}
	}
	return nil
}

func findSignal(body string, signals []string) string {
	for _, s := range signals {
		if strings.Contains(body, s) {
			return s
		}
	}
	return ""
}

func isHTMLSPA(ct string, body []byte) bool {
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return true
	}
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

func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "example.com"
	}
	h := u.Hostname()
	if h == "" {
		return "example.com"
	}
	// Strip port
	parts := strings.Split(h, ":")
	return parts[0]
}

func median(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	// Simple sort for small slice
	for i := 0; i < len(ds); i++ {
		for j := i + 1; j < len(ds); j++ {
			if ds[j] < ds[i] {
				ds[i], ds[j] = ds[j], ds[i]
			}
		}
	}
	return ds[len(ds)/2]
}
