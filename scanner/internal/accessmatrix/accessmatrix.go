// Package accessmatrix builds a comparative access control matrix across scan identities.
// For each discovered endpoint, every identity (anonymous, user, admin, …) is probed
// independently. The resulting matrix is analyzed to detect IDOR, BFLA, missing
// authentication, and privilege escalation automatically.
package accessmatrix

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/modules"
)

// PrivLevel orders identities from least to most privileged.
const (
	LevelAnonymous = 0
	LevelUser      = 1
	LevelAdmin     = 2
)

// Identity pairs a session name with its HTTP client and inferred privilege level.
type Identity struct {
	Name   string
	Client *client.Client
	Level  int
}

// InferLevel maps a session name string to a privilege level.
func InferLevel(name string) int {
	lower := strings.ToLower(name)
	if lower == "" || lower == "anonymous" || lower == "anon" || lower == "guest" || lower == "public" {
		return LevelAnonymous
	}
	for _, kw := range []string{"admin", "root", "superuser", "super", "manager", "staff", "operator", "sysadmin"} {
		if strings.Contains(lower, kw) {
			return LevelAdmin
		}
	}
	return LevelUser
}

type probeResult struct {
	status int
	size   int
	sig    string
	isHTML bool
	err    bool
}

type matrixEntry struct {
	url     string
	results map[string]*probeResult // identity name → result
}

// Build probes every URL in allURLs with every identity and returns access control findings.
// allURLs should be the union of URLs visited across all identity scans.
// A maximum of maxProbe structural paths are tested to limit request volume.
func Build(ctx context.Context, allURLs []string, identities []Identity, maxProbe int) []modules.Finding {
	if len(identities) < 2 || len(allURLs) == 0 {
		return nil
	}
	if maxProbe <= 0 {
		maxProbe = 300
	}

	unique := deduplicateStructural(allURLs, maxProbe)
	matrix := probeAll(ctx, unique, identities)
	return analyze(matrix, identities)
}

// deduplicateStructural keeps one representative URL per structural path pattern.
// /api/users/123 and /api/users/456 map to the same pattern → keep the first seen.
func deduplicateStructural(urls []string, limit int) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		key := u.Host + "|" + structuralPath(u.Path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, raw)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func structuralPath(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if isIDSegment(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
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
	if allDigit && len(s) >= 1 {
		return true
	}
	if len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' {
		return true
	}
	if len(s) >= 16 {
		hex := true
		for _, c := range s {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				hex = false
				break
			}
		}
		if hex {
			return true
		}
	}
	return false
}

// probeAll fires each (url, identity) pair concurrently and returns the matrix.
func probeAll(ctx context.Context, urls []string, identities []Identity) []*matrixEntry {
	entries := make([]*matrixEntry, len(urls))
	for i, u := range urls {
		entries[i] = &matrixEntry{url: u, results: make(map[string]*probeResult)}
	}

	sem := make(chan struct{}, 20) // max 20 concurrent matrix probes
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := range entries {
		for _, id := range identities {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(e *matrixEntry, identity Identity) {
				defer wg.Done()
				defer func() { <-sem }()
				r := probe(ctx, e.url, identity)
				mu.Lock()
				e.results[identity.Name] = r
				mu.Unlock()
			}(entries[i], id)
		}
	}
	wg.Wait()
	return entries
}

func probe(ctx context.Context, rawURL string, id Identity) *probeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return &probeResult{err: true}
	}
	resp, err := id.Client.Do(req)
	if err != nil {
		return &probeResult{err: true}
	}
	body, _ := client.ReadBody(resp)
	return &probeResult{
		status: resp.StatusCode,
		size:   len(body),
		sig:    bodySignature(body),
		isHTML: isHTMLBody(resp.Header.Get("Content-Type"), body),
	}
}

// isHTMLBody returns true when the response is an HTML document (SPA catch-all or static page).
func isHTMLBody(ct string, body []byte) bool {
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

// normalizers strip per-session tokens so body comparison is meaningful
var (
	reJWT  = regexp.MustCompile(`eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{5,}`)
	reUUID = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reTS   = regexp.MustCompile(`\b1[0-9]{9,12}\b`) // unix timestamps
	reTok  = regexp.MustCompile(`[a-zA-Z0-9]{40,}`) // long opaque tokens
)

func bodySignature(body []byte) string {
	if len(body) > 4000 {
		body = body[:4000]
	}
	b := reJWT.ReplaceAll(body, []byte("<JWT>"))
	b = reUUID.ReplaceAll(b, []byte("<UUID>"))
	b = reTS.ReplaceAll(b, []byte("<TS>"))
	b = reTok.ReplaceAll(b, []byte("<TOK>"))
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:8])
}

func analyze(entries []*matrixEntry, identities []Identity) []modules.Finding {
	var findings []modules.Finding

	for _, entry := range entries {
		if len(entry.results) < 2 {
			continue
		}
		if f := detectViolation(entry, identities); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

type namedCell struct {
	id  Identity
	res *probeResult
}

func detectViolation(entry *matrixEntry, identities []Identity) *modules.Finding {
	var cells []namedCell
	for _, id := range identities {
		res, ok := entry.results[id.Name]
		if !ok || res == nil || res.err {
			continue
		}
		cells = append(cells, namedCell{id, res})
	}
	if len(cells) < 2 {
		return nil
	}

	// Sort by level asc for analysis
	sort.Slice(cells, func(i, j int) bool {
		return cells[i].id.Level < cells[j].id.Level
	})

	// Partition by status class
	var ok2xx, blocked4xx, other []namedCell
	for _, c := range cells {
		switch {
		case c.res.status >= 200 && c.res.status < 300:
			ok2xx = append(ok2xx, c)
		case c.res.status >= 400 && c.res.status < 600:
			blocked4xx = append(blocked4xx, c)
		default:
			other = append(other, c)
		}
	}
	_ = other

	matrixRow := buildMatrixRow(cells)
	urlLow := strings.ToLower(entry.url)

	// No access control violations if everyone is blocked
	if len(ok2xx) == 0 {
		return nil
	}

	// ── Rule 1: Unauthenticated access ─────────────────────────────────────
	// Anonymous gets 2xx while at least one authenticated identity exists
	var anonOK, anonBlocked bool
	for _, c := range cells {
		if c.id.Level == LevelAnonymous {
			if c.res.status >= 200 && c.res.status < 300 {
				anonOK = true
			} else {
				anonBlocked = true
			}
		}
	}
	_ = anonBlocked

	hasHigherPrivIdentity := false
	for _, c := range cells {
		if c.id.Level > LevelAnonymous {
			hasHigherPrivIdentity = true
			break
		}
	}

	if anonOK && hasHigherPrivIdentity && len(ok2xx) > 0 {
		// SPA catch-all: if all accessible responses are HTML, they are not real API access.
		allHTML := true
		for _, c := range ok2xx {
			if !c.res.isHTML {
				allHTML = false
				break
			}
		}
		if allHTML {
			return nil
		}

		allOK := len(blocked4xx) == 0
		if allOK {
			// No access control at all — flag only if URL looks sensitive
			if isSensitiveURL(urlLow) {
				return &modules.Finding{
					Module:         "access-matrix",
					Severity:       modules.Medium,
					URL:            entry.url,
					Method:         "GET",
					AttackCategory: "A01:Broken Access Control",
					Evidence:       formatMatrix(cells) + " — no authentication on sensitive endpoint",
					Detail:         fmt.Sprintf("Missing authentication: %q accessible without any credentials", entry.url),
					CWE:            "CWE-306",
					CVSS:           6.5,
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					Confidence:     modules.Confirmed,
					Remediation:    "Require authentication on this endpoint; add appropriate authorization checks",
					RemPriority:    "high",
					Tags:           []string{"access-control", "missing-auth", "a01"},
					MatrixRow:      matrixRow,
					ChainSteps: []string{
						fmt.Sprintf("1. GET %s with no credentials", entry.url),
						"2. Server returns 200 with content — no authentication enforced",
					},
				}
			}
			return nil
		}

		// Some identities are blocked but anonymous isn't → authentication bypass
		return &modules.Finding{
			Module:         "access-matrix",
			Severity:       modules.Critical,
			URL:            entry.url,
			Method:         "GET",
			AttackCategory: "A07:Identification and Authentication Failures",
			Evidence:       formatMatrix(cells) + " — unauthenticated access",
			Detail:         fmt.Sprintf("Authentication bypass: anonymous identity accesses %q while other identities are blocked", entry.url),
			CWE:            "CWE-287",
			CVSS:           9.1,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			Confidence:     modules.Confirmed,
			Remediation:    "Enforce authentication on this endpoint for all request origins",
			RemPriority:    "immediate",
			Tags:           []string{"access-control", "auth-bypass", "unauthenticated", "a07"},
			MatrixRow:      matrixRow,
			ChainSteps: []string{
				fmt.Sprintf("1. GET %s without any session cookie / auth header", entry.url),
				"2. Server returns 200 — authentication check missing or bypassable",
				"3. Attacker reads sensitive data without authenticating",
			},
		}
	}

	// ── Rule 2: BFLA — non-admin accessing admin functionality ─────────────
	if isAdminURL(urlLow) {
		for _, c := range ok2xx {
			if c.id.Level < LevelAdmin && !c.res.isHTML {
				// Find admin response size for comparison
				var adminSig string
				var adminSize int
				for _, a := range cells {
					if a.id.Level == LevelAdmin && a.res.status >= 200 && a.res.status < 300 {
						adminSig = a.res.sig
						adminSize = a.res.size
						break
					}
				}
				conf := modules.Likely
				detail := fmt.Sprintf("BFLA: identity %q (level %d) accesses admin endpoint %q", c.id.Name, c.id.Level, entry.url)
				steps := []string{
					fmt.Sprintf("1. Log in as %q (non-admin)", c.id.Name),
					fmt.Sprintf("2. GET %s", entry.url),
					fmt.Sprintf("3. Server returns %d (%d bytes) — admin function accessible to lower-privilege user", c.res.status, c.res.size),
				}
				if adminSig != "" && adminSig == c.res.sig {
					conf = modules.Confirmed
					detail += fmt.Sprintf(" — response identical to admin (%d bytes)", adminSize)
					steps = append(steps, "4. Response body identical to admin response — full admin data exposed to non-admin identity")
				} else if adminSize > 0 && similarSize(c.res.size, adminSize) {
					conf = modules.Confirmed
					detail += fmt.Sprintf(" — response size similar to admin (%d vs %d bytes)", c.res.size, adminSize)
				}
				return &modules.Finding{
					Module:         "access-matrix",
					Severity:       modules.Critical,
					URL:            entry.url,
					Method:         "GET",
					Param:          "session identity",
					AttackCategory: "A01:Broken Access Control",
					Evidence:       formatMatrix(cells),
					Detail:         detail,
					CWE:            "CWE-285",
					CVSS:           8.8,
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
					Confidence:     conf,
					Remediation:    "Enforce function-level authorization; verify role before serving admin endpoints",
					RemPriority:    "immediate",
					Tags:           []string{"access-control", "bfla", "privilege-escalation", "a01"},
					MatrixRow:      matrixRow,
					ChainSteps:     steps,
					Session:        c.id.Name,
				}
			}
		}
	}

	// ── Rule 3: IDOR — multiple user-level identities access same object ────
	if hasIDInURL(entry.url) && len(ok2xx) >= 2 {
		// Filter to non-anonymous, non-HTML responses only.
		// HTML responses indicate a SPA catch-all, not real object access.
		var userOK []namedCell
		for _, c := range ok2xx {
			if c.id.Level >= LevelUser && !c.res.isHTML && c.res.size > 50 {
				userOK = append(userOK, c)
			}
		}
		if len(userOK) >= 2 {
			meaningful := len(userOK)
			if meaningful >= 2 {
				// Check body signature equality → confirmed vs likely
				sigs := make(map[string]int)
				for _, c := range userOK {
					sigs[c.res.sig]++
				}
				conf := modules.Likely
				idorDetail := fmt.Sprintf("IDOR: %d identities access same object at %q", len(userOK), entry.url)
				steps := []string{
					fmt.Sprintf("1. As identity %q, request GET %s", userOK[0].id.Name, entry.url),
					fmt.Sprintf("2. Server returns 200 (%d bytes)", userOK[0].res.size),
					fmt.Sprintf("3. As identity %q (different user), same request returns 200 (%d bytes)", userOK[1].id.Name, userOK[1].res.size),
				}
				for _, count := range sigs {
					if count >= 2 {
						conf = modules.Confirmed
						idorDetail += " — identical response body across identities (same object data exposed)"
						steps = append(steps, "4. Response body identical — both users receive the same object data (confirmed cross-user exposure)")
						break
					}
				}
				if conf == modules.Likely {
					steps = append(steps, "4. Different body content but both users can access the resource — server may return filtered data per user, manual confirmation needed")
				}
				sev := modules.High
				if conf == modules.Confirmed {
					sev = modules.Critical
				}
				return &modules.Finding{
					Module:         "access-matrix",
					Severity:       sev,
					URL:            entry.url,
					Method:         "GET",
					Param:          extractIDParam(entry.url),
					AttackCategory: "A01:Broken Access Control",
					Evidence:       formatMatrix(cells),
					Detail:         idorDetail,
					CWE:            "CWE-639",
					CVSS:           8.1,
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
					Confidence:     conf,
					Remediation:    "Verify object ownership on every request; enforce that authenticated user owns the requested resource ID",
					RemPriority:    "immediate",
					Tags:           []string{"access-control", "idor", "bola", "a01"},
					MatrixRow:      matrixRow,
					ChainSteps:     steps,
				}
			}
		}
	}

	// ── Rule 4: Vertical privilege escalation ──────────────────────────────
	// Lower-privilege user gets 2xx on endpoint where access control exists (some blocked)
	// AND their response is similar in size to the highest-privilege response
	if len(blocked4xx) > 0 && len(ok2xx) >= 2 {
		// Find the highest-privilege identity that got 2xx
		var highestOK namedCell
		for _, c := range ok2xx {
			if c.id.Level > highestOK.id.Level {
				highestOK = c
			}
		}
		// Find a lower-privilege identity that also got 2xx with similar non-HTML response
		for _, c := range ok2xx {
			if c.id.Level >= highestOK.id.Level {
				continue
			}
			if c.res.size < 50 || c.res.isHTML || highestOK.res.isHTML {
				continue
			}
			if similarSize(c.res.size, highestOK.res.size) {
				return &modules.Finding{
					Module:         "access-matrix",
					Severity:       modules.High,
					URL:            entry.url,
					Method:         "GET",
					Param:          "session identity",
					AttackCategory: "A01:Broken Access Control",
					Evidence:       formatMatrix(cells),
					Detail: fmt.Sprintf("Vertical privilege escalation: identity %q (level %d) receives same response as %q (level %d) — access control may be incomplete",
						c.id.Name, c.id.Level, highestOK.id.Name, highestOK.id.Level),
					CWE:         "CWE-269",
					CVSS:        7.5,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
					Confidence:  modules.Likely,
					Remediation: "Implement role-based access control; filter response data based on caller's privilege level",
					RemPriority: "high",
					Tags:        []string{"access-control", "privilege-escalation", "a01"},
					MatrixRow:   matrixRow,
					ChainSteps: []string{
						fmt.Sprintf("1. As %q (lower-privilege), GET %s", c.id.Name, entry.url),
						fmt.Sprintf("2. Response: %d (%d bytes)", c.res.status, c.res.size),
						fmt.Sprintf("3. As %q (higher-privilege), same endpoint returns %d (%d bytes)", highestOK.id.Name, highestOK.res.status, highestOK.res.size),
						"4. Similar response size — lower-privilege identity may be receiving full privileged data",
					},
					Session: c.id.Name,
				}
			}
		}
	}

	return nil
}

// PrintMatrix prints a human-readable access control matrix to stdout.
func PrintMatrix(findings []modules.Finding, identities []Identity) {
	if len(findings) == 0 {
		return
	}
	// Already reported individually via PrintFinding — no extra table needed.
	// The MatrixRow on each Finding carries the data for HTML/JSON reports.
}

// FormatMatrixTable returns a compact text table for a set of findings.
func FormatMatrixTable(findings []modules.Finding) string {
	if len(findings) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n  Access Control Matrix Summary\n")
	sb.WriteString("  " + strings.Repeat("─", 80) + "\n")

	// Collect all identity names
	allNames := make(map[string]struct{})
	for _, f := range findings {
		for name := range f.MatrixRow {
			allNames[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(allNames))
	for n := range allNames {
		names = append(names, n)
	}
	sort.Strings(names)

	// Header
	sb.WriteString(fmt.Sprintf("  %-50s", "Endpoint"))
	for _, n := range names {
		sb.WriteString(fmt.Sprintf("  %-12s", n))
	}
	sb.WriteString("\n  " + strings.Repeat("─", 80) + "\n")

	// Rows
	for _, f := range findings {
		endpoint := f.URL
		if len(endpoint) > 48 {
			endpoint = "..." + endpoint[len(endpoint)-45:]
		}
		sb.WriteString(fmt.Sprintf("  %-50s", endpoint))
		for _, n := range names {
			if cell, ok := f.MatrixRow[n]; ok {
				sb.WriteString(fmt.Sprintf("  %-12s", statusLabel(cell.Status, cell.Size)))
			} else {
				sb.WriteString(fmt.Sprintf("  %-12s", "?"))
			}
		}
		sb.WriteString(fmt.Sprintf("  → %s\n", f.Detail[:min(len(f.Detail), 40)]))
	}
	sb.WriteString("  " + strings.Repeat("─", 80) + "\n")
	return sb.String()
}

func statusLabel(status, size int) string {
	switch {
	case status == 0:
		return "ERR"
	case status >= 200 && status < 300:
		return fmt.Sprintf("%d(%dB)", status, size)
	default:
		return fmt.Sprintf("%d", status)
	}
}

func buildMatrixRow(cells []namedCell) map[string]modules.AccessCell {
	row := make(map[string]modules.AccessCell, len(cells))
	for _, c := range cells {
		row[c.id.Name] = modules.AccessCell{
			Status: c.res.status,
			Size:   c.res.size,
			Sig:    c.res.sig,
		}
	}
	return row
}

func formatMatrix(cells []namedCell) string {
	parts := make([]string, 0, len(cells))
	for _, c := range cells {
		parts = append(parts, fmt.Sprintf("%s→%s", c.id.Name, statusLabel(c.res.status, c.res.size)))
	}
	return strings.Join(parts, "  ")
}

func isAdminURL(u string) bool {
	for _, kw := range []string{"/admin", "/manage", "/management", "/config", "/configuration",
		"/settings", "/superuser", "/backend", "/internal", "/system", "/dashboard/admin",
		"/api/admin", "/api/manage", "/operator", "/staff", "/sysadmin"} {
		if strings.Contains(u, kw) {
			return true
		}
	}
	return false
}

func isSensitiveURL(u string) bool {
	for _, kw := range []string{
		"/api/", "/user", "/account", "/profile", "/order", "/payment", "/invoice",
		"/admin", "/manage", "/config", "/secret", "/private", "/internal", "/auth",
		"/token", "/session", "/key", "/credential", "/password", "/reset",
	} {
		if strings.Contains(u, kw) {
			return true
		}
	}
	return false
}

func hasIDInURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if isIDSegment(seg) {
			return true
		}
	}
	for _, vs := range u.Query() {
		for _, v := range vs {
			if isIDSegment(v) {
				return true
			}
		}
	}
	return false
}

func extractIDParam(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "id"
	}
	segs := strings.Split(u.Path, "/")
	for i, seg := range segs {
		if isIDSegment(seg) && i > 0 {
			return segs[i-1] + " ID"
		}
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			if isIDSegment(v) {
				return k
			}
		}
	}
	return "id"
}

func similarSize(a, b int) bool {
	if b == 0 {
		return a == 0
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(b) < 0.25
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
