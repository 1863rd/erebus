package idor

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

var numRe = regexp.MustCompile(`^\d{1,12}$`)
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "idor" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}

	var findings []modules.Finding

	// Numeric path segments
	segments := strings.Split(u.Path, "/")
	for i, seg := range segments {
		if ctx.Err() != nil {
			break
		}
		if !numRe.MatchString(seg) {
			continue
		}
		n, _ := strconv.ParseInt(seg, 10, 64)
		if n < 1 {
			continue
		}

		// Test neighboring IDs — deep mode uses wider delta range
		deltas := []int64{1, -1, 99}
		if modules.GetMode(ctx) == modules.ModeDeep {
			deltas = []int64{1, -1, 2, -2, 5, 10, -10, 100, -100, 999, 9999}
		}
		for _, delta := range deltas {
			alt := n + delta
			if alt < 1 {
				continue
			}
			modified := make([]string, len(segments))
			copy(modified, segments)
			modified[i] = strconv.FormatInt(alt, 10)
			cu := *u
			cu.Path = strings.Join(modified, "/")
			if f := m.compare(ctx, page, cu.String(), "path:"+seg, strconv.FormatInt(alt, 10)); f != nil {
				findings = append(findings, *f)
				break
			}
		}

		// Auth bypass test: access the original resource without authentication
		if f := m.testNoAuth(ctx, page, "path:"+seg); f != nil {
			findings = append(findings, *f)
		}
	}

	// Numeric / UUID query parameters
	for k, vs := range u.Query() {
		if ctx.Err() != nil {
			break
		}
		if len(vs) == 0 {
			continue
		}
		v := vs[0]

		if numRe.MatchString(v) {
			n, _ := strconv.ParseInt(v, 10, 64)
			if n < 1 {
				continue
			}
			qDeltas := []int64{1, -1, 99}
			if modules.GetMode(ctx) == modules.ModeDeep {
				qDeltas = []int64{1, -1, 2, -2, 5, 10, -10, 100, -100, 999, 9999}
			}
			for _, delta := range qDeltas {
				alt := n + delta
				if alt < 1 {
					continue
				}
				q := u.Query()
				q.Set(k, strconv.FormatInt(alt, 10))
				cu := *u
				cu.RawQuery = q.Encode()
				if f := m.compare(ctx, page, cu.String(), k, strconv.FormatInt(alt, 10)); f != nil {
					findings = append(findings, *f)
					break
				}
			}

			if f := m.testNoAuth(ctx, page, k); f != nil {
				findings = append(findings, *f)
			}
			if f := m.testInvalidToken(ctx, page, k); f != nil {
				findings = append(findings, *f)
			}

		} else if uuidRe.MatchString(strings.ToLower(v)) {
			altUUID := "00000000-0000-0000-0000-000000000001"
			if strings.ToLower(v) == altUUID {
				altUUID = "00000000-0000-0000-0000-000000000002"
			}
			q := u.Query()
			q.Set(k, altUUID)
			cu := *u
			cu.RawQuery = q.Encode()
			if f := m.compare(ctx, page, cu.String(), k, altUUID); f != nil {
				findings = append(findings, *f)
			}
			if f := m.testNoAuth(ctx, page, k); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	// Deep mode: test hash-based and base64-encoded ID variants
	if modules.GetMode(ctx) == modules.ModeDeep {
		findings = append(findings, m.testDeepIDVariants(ctx, page)...)
	}

	return findings, nil
}

// testDeepIDVariants checks for predictable hash-based and base64-encoded IDs.
func (m *Module) testDeepIDVariants(ctx context.Context, page crawler.Page) []modules.Finding {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil
	}
	var findings []modules.Finding

	for k, vs := range u.Query() {
		if ctx.Err() != nil {
			break
		}
		if len(vs) == 0 {
			continue
		}
		v := vs[0]

		// Base64-encoded numeric IDs: decode → increment → re-encode
		if decoded, err := base64.StdEncoding.DecodeString(v); err == nil && len(decoded) >= 4 {
			orig := int64(binary.BigEndian.Uint32(decoded[:4]))
			for _, delta := range []int64{1, -1, 2} {
				alt := orig + delta
				if alt < 0 {
					continue
				}
				var buf [4]byte
				binary.BigEndian.PutUint32(buf[:], uint32(alt))
				encoded := base64.StdEncoding.EncodeToString(buf[:])
				q := u.Query()
				q.Set(k, encoded)
				cu := *u
				cu.RawQuery = q.Encode()
				if f := m.compare(ctx, page, cu.String(), k, encoded); f != nil {
					f.Detail = "[deep/base64-id] " + f.Detail
					f.Tags = append(f.Tags, "base64-id")
					findings = append(findings, *f)
					break
				}
			}
		}

		// MD5-like IDs: if value looks like a 32-char hex, try MD5("1"), MD5("2"), MD5("3")
		if len(v) == 32 && isHex(v) {
			for _, seed := range []string{"1", "2", "3", "admin", "0"} {
				altHash := fmt.Sprintf("%x", md5.Sum([]byte(seed)))
				if altHash == v {
					continue
				}
				q := u.Query()
				q.Set(k, altHash)
				cu := *u
				cu.RawQuery = q.Encode()
				if f := m.compare(ctx, page, cu.String(), k, altHash); f != nil {
					f.Detail = fmt.Sprintf("[deep/md5-id] Predictable MD5 hash (MD5(%q)): %s", seed, f.Detail)
					f.Tags = append(f.Tags, "hash-id", "predictable-id")
					findings = append(findings, *f)
					break
				}
			}
		}
	}
	return findings
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// compare checks if an alternate ID returns a valid, distinct resource.
func (m *Module) compare(ctx context.Context, page crawler.Page, testURL, param, altVal string) *modules.Finding {
	if isHTMLBody(page.Body) {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusOK || len(body) < 200 {
		return nil
	}
	if isHTMLBody(body) {
		return nil
	}
	if string(body) == string(page.Body) {
		return nil
	}
	origLen := len(page.Body)
	altLen := len(body)
	if origLen > 0 {
		diff := altLen - origLen
		if diff < 0 {
			diff = -diff
		}
		if float64(diff)/float64(origLen) > 0.60 {
			return nil
		}
	}

	return &modules.Finding{
		Module:      "idor",
		Severity:    modules.High,
		URL:         testURL,
		Param:       param,
		Payload:     altVal,
		Evidence:    fmt.Sprintf("HTTP 200, %d bytes (original %d bytes) — distinct object accessible with modified ID", altLen, origLen),
		Detail:      fmt.Sprintf("IDOR/BOLA: %q with value %s returns a valid, different resource", param, altVal),
		CWE:         "CWE-639",
		CVSS:        8.1,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		Confidence:  modules.Likely,
		Remediation: "Implement object-level authorization checks on every resource access; use indirect reference maps instead of exposing raw IDs",
		Tags:        []string{"idor", "bola", "auth-bypass"},
	}
}

// testNoAuth sends the same request without any authentication headers.
// A 200 response with similar content means unauthenticated access is possible.
func (m *Module) testNoAuth(ctx context.Context, page crawler.Page, param string) *modules.Finding {
	if isHTMLBody(page.Body) {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, page.URL, nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.DoNoAuth(req)
	if err != nil {
		return nil
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusOK || len(body) < 200 {
		return nil
	}
	if isHTMLBody(body) {
		return nil
	}
	if string(body) == string(page.Body) {
		// Identical responses — unauthenticated access returns same content as authenticated
		return &modules.Finding{
			Module:      "idor",
			Severity:    modules.Critical,
			URL:         page.URL,
			Param:       param,
			Payload:     "(no auth headers)",
			Evidence:    fmt.Sprintf("HTTP 200 (%d bytes) without auth headers — identical to authenticated response", len(body)),
			Detail:      "Broken object-level authorization: resource is accessible without any authentication credentials, identical content returned",
			CWE:         "CWE-639",
			CVSS:        9.1,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Enforce authentication on every resource endpoint; return 401/403 for unauthenticated requests",
			Tags:        []string{"idor", "auth-bypass", "unauthenticated-access", "bola"},
		}
	}

	origLen := len(page.Body)
	altLen := len(body)
	if origLen > 0 {
		diff := altLen - origLen
		if diff < 0 {
			diff = -diff
		}
		// Similar size but different content (stripped auth, still 200)
		if float64(diff)/float64(origLen) < 0.20 {
			return &modules.Finding{
				Module:      "idor",
				Severity:    modules.High,
				URL:         page.URL,
				Param:       param,
				Payload:     "(no auth headers)",
				Evidence:    fmt.Sprintf("HTTP 200 (%d bytes) without auth headers — similar size to authenticated response (%d bytes)", altLen, origLen),
				Detail:      "Possible broken authentication: resource returns similar content without authentication credentials",
				CWE:         "CWE-306",
				CVSS:        8.2,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
				Confidence:  modules.Likely,
				Remediation: "Enforce authentication on every resource endpoint; return 401/403 for unauthenticated requests",
				Tags:        []string{"idor", "auth-bypass", "missing-authentication"},
			}
		}
	}
	return nil
}

// testInvalidToken sends the request with a clearly invalid/expired token.
// If the response is still 200 with similar content, authentication is not enforced.
func (m *Module) testInvalidToken(ctx context.Context, page crawler.Page, param string) *modules.Finding {
	if isHTMLBody(page.Body) {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, page.URL, nil)
	if err != nil {
		return nil
	}
	// Deliberately invalid JWT (all zeroes in signature)
	const invalidToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIwIiwiaWF0IjoxfQ."
	req.Header.Set("Authorization", "Bearer "+invalidToken)
	req.Header.Set("Cookie", "session=invalid_erebus_token_00000000")

	resp, err := m.client.DoNoAuth(req)
	if err != nil {
		return nil
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusOK || len(body) < 200 {
		return nil
	}
	if isHTMLBody(body) {
		return nil
	}

	origLen := len(page.Body)
	altLen := len(body)
	diff := altLen - origLen
	if diff < 0 {
		diff = -diff
	}

	if origLen > 0 && float64(diff)/float64(origLen) < 0.15 {
		return &modules.Finding{
			Module:      "idor",
			Severity:    modules.Critical,
			URL:         page.URL,
			Param:       param,
			Payload:     "Bearer " + invalidToken,
			Evidence:    fmt.Sprintf("HTTP 200 (%d bytes) with invalid/expired token — authentication not properly enforced", altLen),
			Detail:      "Authentication bypass: sending a clearly invalid JWT returns similar content as a valid authenticated request — token validation is not enforced",
			CWE:         "CWE-287",
			CVSS:        9.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Confidence:  modules.Likely,
			Remediation: "Validate JWT signatures on every request; reject expired, malformed, or alg:none tokens with 401",
			Tags:        []string{"idor", "auth-bypass", "invalid-token", "broken-auth"},
		}
	}
	return nil
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
