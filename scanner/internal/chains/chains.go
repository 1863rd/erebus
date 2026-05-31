// Package chains performs post-exploitation chain analysis on collected findings.
// It looks for combinations of confirmed vulnerabilities that create escalation paths
// and generates synthetic chain findings with elevated severity.
package chains

import (
	"fmt"
	"strings"

	"github.com/erebus/scanner/internal/modules"
)

// Analyze takes all findings from a completed scan and returns additional
// chain findings representing multi-step exploit scenarios.
func Analyze(findings []modules.Finding) []modules.Finding {
	var chains []modules.Finding
	chains = append(chains, lfiToRCE(findings)...)
	chains = append(chains, ssrfToCredentials(findings)...)
	chains = append(chains, sqliToAuthBypass(findings)...)
	chains = append(chains, idorEscalation(findings)...)
	chains = append(chains, jwtToAdmin(findings)...)
	chains = append(chains, xxeToSSRF(findings)...)
	chains = append(chains, sstiToRCE(findings)...)
	chains = append(chains, nosqlAuthBypass(findings)...)
	chains = append(chains, uploadToRCE(findings)...)
	chains = append(chains, corsWithAuth(findings)...)
	chains = append(chains, openRedirectOAuth(findings)...)
	return chains
}

// lfiToRCE detects the LFI → log poisoning → RCE chain.
// If we have a confirmed LFI reading a web server log, and there is also
// an RCE finding (or the log file read succeeds), flag the potential chain.
func lfiToRCE(findings []modules.Finding) []modules.Finding {
	var lfiFindings, rceFindings []modules.Finding
	for _, f := range findings {
		switch f.Module {
		case "lfi":
			if f.Confidence == modules.Confirmed {
				lfiFindings = append(lfiFindings, f)
			}
		case "rce":
			rceFindings = append(rceFindings, f)
		}
	}

	if len(lfiFindings) == 0 {
		return nil
	}

	var chains []modules.Finding
	for _, lfi := range lfiFindings {
		// Check if LFI is reading an access log (log poisoning precondition)
		logRead := strings.Contains(lfi.Payload, "access.log") ||
			strings.Contains(lfi.Payload, "error.log") ||
			strings.Contains(lfi.Payload, "apache") ||
			strings.Contains(lfi.Payload, "nginx")

		if logRead {
			detail := fmt.Sprintf("LFI→RCE chain: log poisoning via %s — inject PHP payload into User-Agent, then read log", lfi.Payload)
			chains = append(chains, modules.Finding{
				Module:     "chain",
				Severity:   modules.Critical,
				URL:        lfi.URL,
				Param:      lfi.Param,
				Payload:    "User-Agent: <?php system($_GET['cmd']); ?> → " + lfi.Payload,
				Evidence:   "LFI reading web server log — poison log with PHP payload then trigger via LFI",
				Detail:     detail,
				CWE:        "CWE-78",
				CVSS:       9.8,
				CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence: modules.Likely,
				Remediation: "Fix LFI first; additionally disable PHP execution in log directories",
				Tags:       []string{"chain", "lfi", "rce", "log-poisoning"},
				ChainOf:    lfi.URL,
				Session:    lfi.Session,
			})
		}

		// If we already have confirmed RCE on the same host, mark the full chain
		for _, rce := range rceFindings {
			if sameHost(lfi.URL, rce.URL) {
				chains = append(chains, modules.Finding{
					Module:     "chain",
					Severity:   modules.Critical,
					URL:        lfi.URL,
					Param:      lfi.Param,
					Payload:    lfi.Payload + " + " + rce.Payload,
					Evidence:   fmt.Sprintf("Confirmed LFI (%s) + confirmed RCE (%s) on same host", lfi.Param, rce.Param),
					Detail:     "LFI + RCE confirmed on same host — full compromise likely achievable",
					CWE:        "CWE-78",
					CVSS:       9.8,
					CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Confidence: modules.Confirmed,
					Remediation: "Fix both LFI and RCE vulnerabilities immediately",
					Tags:       []string{"chain", "lfi", "rce", "critical-chain"},
					ChainOf:    lfi.URL,
					Session:    lfi.Session,
				})
				break
			}
		}
	}
	return dedup(chains)
}

// ssrfToCredentials flags when SSRF successfully reaches cloud metadata endpoints
// containing credentials — escalating SSRF to account compromise.
func ssrfToCredentials(findings []modules.Finding) []modules.Finding {
	var chains []modules.Finding
	for _, f := range findings {
		if f.Module != "ssrf" || f.Confidence != modules.Confirmed {
			continue
		}
		if strings.Contains(f.Evidence, "IAM credentials") ||
			strings.Contains(f.Evidence, "AccessKeyId") ||
			strings.Contains(f.Evidence, "SecretAccessKey") ||
			strings.Contains(f.Extracted, "AccessKeyId") ||
			strings.Contains(f.Extracted, "SecretAccessKey") {
			chains = append(chains, modules.Finding{
				Module:     "chain",
				Severity:   modules.Critical,
				URL:        f.URL,
				Param:      f.Param,
				Payload:    f.Payload,
				Evidence:   "SSRF reached cloud IAM credentials — AWS/GCP/Azure account may be compromised",
				Detail:     "SSRF→credential theft: cloud metadata endpoint leaked IAM credentials; use them to escalate to cloud account",
				CWE:        "CWE-918",
				CVSS:       9.8,
				CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				Confidence: modules.Confirmed,
				Remediation: "Fix SSRF; enforce IMDSv2 (AWS); block 169.254.169.254 at egress; rotate exposed credentials immediately",
				Tags:       []string{"chain", "ssrf", "cloud-credentials", "lateral-movement"},
				ChainOf:    f.URL,
				Extracted:  f.Extracted,
				Session:    f.Session,
			})
		}
	}
	return chains
}

// sqliToAuthBypass detects SQLi on login/auth endpoints — direct auth bypass.
func sqliToAuthBypass(findings []modules.Finding) []modules.Finding {
	var chains []modules.Finding
	for _, f := range findings {
		if f.Module != "sqli" {
			continue
		}
		urlLow := strings.ToLower(f.URL)
		paramLow := strings.ToLower(f.Param)
		if isAuthEndpoint(urlLow) || isAuthParam(paramLow) {
			chains = append(chains, modules.Finding{
				Module:     "chain",
				Severity:   modules.Critical,
				URL:        f.URL,
				Param:      f.Param,
				Payload:    "' OR '1'='1'-- (auth bypass variant)",
				Evidence:   fmt.Sprintf("SQLi on auth endpoint %s — authentication bypass likely", f.URL),
				Detail:     "SQLi→auth bypass: injection on login/authentication endpoint allows bypassing access controls",
				CWE:        "CWE-89",
				CVSS:       9.8,
				CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence: modules.Likely,
				Remediation: "Parameterize queries; enforce authentication server-side; do not rely on SQL query result for auth decision",
				Tags:       []string{"chain", "sqli", "auth-bypass", "authentication"},
				ChainOf:    f.URL,
				Session:    f.Session,
			})
		}
	}
	return dedup(chains)
}

// idorEscalation detects IDOR findings across multiple sessions — horizontal/vertical privilege.
func idorEscalation(findings []modules.Finding) []modules.Finding {
	type sessionURL struct {
		session string
		url     string
	}
	seen := make(map[string][]string) // url → sessions that found IDOR

	for _, f := range findings {
		if f.Module != "idor" {
			continue
		}
		seen[f.URL] = append(seen[f.URL], f.Session)
	}

	var chains []modules.Finding
	for u, sessions := range seen {
		if len(sessions) >= 2 {
			chains = append(chains, modules.Finding{
				Module:     "chain",
				Severity:   modules.Critical,
				URL:        u,
				Param:      "object ID",
				Payload:    "Cross-session IDOR",
				Evidence:   fmt.Sprintf("IDOR confirmed from sessions: %s — object accessible across identities", strings.Join(sessions, ", ")),
				Detail:     "Privilege escalation: IDOR confirmed across multiple sessions — horizontal or vertical access control bypass",
				CWE:        "CWE-639",
				CVSS:       8.8,
				CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
				Confidence: modules.Confirmed,
				Remediation: "Enforce object-level authorization server-side; validate ownership on every request",
				Tags:       []string{"chain", "idor", "privilege-escalation", "access-control"},
				ChainOf:    u,
			})
		}
	}
	return chains
}

// jwtToAdmin detects weak JWT key + admin/privileged claims — direct privilege escalation.
func jwtToAdmin(findings []modules.Finding) []modules.Finding {
	var chains []modules.Finding
	for _, f := range findings {
		if f.Module != "jwt" {
			continue
		}
		hasWeakKey := strings.Contains(f.Evidence, "HMAC signing key cracked") ||
			strings.Contains(f.Evidence, "cracked")
		hasAdminClaim := strings.Contains(strings.ToLower(f.Extracted), "admin") ||
			strings.Contains(strings.ToLower(f.Extracted), "role") ||
			strings.Contains(strings.ToLower(f.Extracted), "superuser") ||
			strings.Contains(strings.ToLower(f.Extracted), "is_staff")
		isAlgNone := strings.Contains(f.Evidence, "alg:none") || strings.Contains(f.Payload, "alg\":\"none\"")

		if (hasWeakKey || isAlgNone) && hasAdminClaim {
			chains = append(chains, modules.Finding{
				Module:     "chain",
				Severity:   modules.Critical,
				URL:        f.URL,
				Param:      f.Param,
				Payload:    f.Payload,
				Evidence:   "JWT weak key/alg:none + privileged claims — forge token with elevated role",
				Detail:     "JWT→privilege escalation: forge token with admin/privileged claims using cracked key or alg:none bypass",
				CWE:        "CWE-347",
				CVSS:       9.8,
				CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence: modules.Likely,
				Remediation: "Use strong random keys (256-bit+); reject alg:none; validate claims server-side",
				Tags:       []string{"chain", "jwt", "privilege-escalation", "authentication"},
				ChainOf:    f.URL,
				Extracted:  f.Extracted,
				Session:    f.Session,
			})
		}
	}
	return chains
}

// xxeToSSRF detects XXE on endpoints that also have SSRF-accessible internal services.
func xxeToSSRF(findings []modules.Finding) []modules.Finding {
	var xxeFindings, ssrfFindings []modules.Finding
	for _, f := range findings {
		switch f.Module {
		case "xxe":
			if f.Confidence == modules.Confirmed {
				xxeFindings = append(xxeFindings, f)
			}
		case "ssrf":
			ssrfFindings = append(ssrfFindings, f)
		}
	}

	if len(xxeFindings) == 0 || len(ssrfFindings) == 0 {
		return nil
	}

	var chains []modules.Finding
	for _, xxe := range xxeFindings {
		for _, ssrf := range ssrfFindings {
			if sameHost(xxe.URL, ssrf.URL) {
				chains = append(chains, modules.Finding{
					Module:     "chain",
					Severity:   modules.Critical,
					URL:        xxe.URL,
					Param:      xxe.Param,
					Payload:    `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>`,
					Evidence:   fmt.Sprintf("XXE on %s + SSRF on %s — use XXE as SSRF vector for internal network access", xxe.URL, ssrf.URL),
					Detail:     "XXE→SSRF chain: use XXE file/URL entity to pivot to internal services (IMDS, Redis, Elasticsearch)",
					CWE:        "CWE-611",
					CVSS:       9.1,
					CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
					Confidence: modules.Likely,
					Remediation: "Disable external entity processing; block internal network access from app server",
					Tags:       []string{"chain", "xxe", "ssrf", "lateral-movement"},
					ChainOf:    xxe.URL,
					Session:    xxe.Session,
				})
				break
			}
		}
	}
	return dedup(chains)
}

// sstiToRCE correlates confirmed SSTI with RCE findings on the same host,
// or elevates a confirmed SSTI to a critical chain if RCE escalation wasn't already proven.
func sstiToRCE(findings []modules.Finding) []modules.Finding {
	var sstiConfirmed, rceFindings []modules.Finding
	for _, f := range findings {
		switch f.Module {
		case "ssti":
			if f.Confidence == modules.Confirmed {
				sstiConfirmed = append(sstiConfirmed, f)
			}
		case "rce":
			rceFindings = append(rceFindings, f)
		}
	}

	var chains []modules.Finding
	for _, ssti := range sstiConfirmed {
		// If already escalated to RCE (module reports confirmed-rce tag), skip
		for _, tag := range ssti.Tags {
			if tag == "confirmed-rce" {
				goto nextSSTI
			}
		}

		for _, rce := range rceFindings {
			if sameHost(ssti.URL, rce.URL) {
				chains = append(chains, modules.Finding{
					Module:      "chain",
					Severity:    modules.Critical,
					URL:         ssti.URL,
					Param:       ssti.Param,
					Payload:     ssti.Payload,
					Evidence:    fmt.Sprintf("SSTI (%s) + RCE on same host — full code execution", ssti.Evidence),
					Detail:      "SSTI→RCE chain: server-side template injection enables arbitrary OS command execution via template engine sandbox escape",
					CWE:         "CWE-94",
					CVSS:        10.0,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
					Confidence:  modules.Confirmed,
					Remediation: "Disable user-controlled template rendering; sandbox template engines; patch immediately",
					Tags:        []string{"chain", "ssti", "rce", "critical-chain"},
					ChainOf:     ssti.URL,
					Session:     ssti.Session,
				})
				break
			}
		}
	nextSSTI:
	}
	return dedup(chains)
}

// nosqlAuthBypass flags confirmed NoSQL injection on authentication endpoints.
func nosqlAuthBypass(findings []modules.Finding) []modules.Finding {
	var chains []modules.Finding
	for _, f := range findings {
		if f.Module != "nosql" || f.Confidence != modules.Confirmed {
			continue
		}
		if isAuthEndpoint(strings.ToLower(f.URL)) || isAuthParam(strings.ToLower(f.Param)) ||
			strings.Contains(strings.ToLower(f.Evidence), "auth") ||
			strings.Contains(strings.ToLower(f.Evidence), "bypass") {
			chains = append(chains, modules.Finding{
				Module:      "chain",
				Severity:    modules.Critical,
				URL:         f.URL,
				Param:       f.Param,
				Payload:     f.Payload,
				Evidence:    fmt.Sprintf("NoSQL operator injection on auth endpoint %s — full auth bypass", f.URL),
				Detail:      "NoSQL→auth bypass chain: MongoDB operator injection on login endpoint allows logging in as any user without valid credentials",
				CWE:         "CWE-943",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Type-check all auth inputs; reject object/array types for credential fields; use $eq explicitly",
				Tags:        []string{"chain", "nosql", "auth-bypass", "authentication"},
				ChainOf:     f.URL,
				Session:     f.Session,
			})
		}
	}
	return dedup(chains)
}

// uploadToRCE correlates confirmed file upload vulnerability with RCE on the same host.
func uploadToRCE(findings []modules.Finding) []modules.Finding {
	var uploadFindings, rceFindings []modules.Finding
	for _, f := range findings {
		switch f.Module {
		case "upload":
			if f.Confidence == modules.Confirmed {
				uploadFindings = append(uploadFindings, f)
			}
		case "rce":
			rceFindings = append(rceFindings, f)
		}
	}

	var chains []modules.Finding
	for _, up := range uploadFindings {
		// If upload already confirmed RCE internally (webshell tag), still emit chain summary
		hasWebshell := false
		for _, tag := range up.Tags {
			if tag == "webshell" {
				hasWebshell = true
				break
			}
		}
		if hasWebshell {
			chains = append(chains, modules.Finding{
				Module:      "chain",
				Severity:    modules.Critical,
				URL:         up.URL,
				Param:       up.Param,
				Payload:     up.Payload,
				Evidence:    "Unrestricted file upload → webshell deployed → RCE confirmed",
				Detail:      "Upload→RCE chain: unrestricted file upload allowed deploying a webshell; arbitrary OS commands executed as web server user",
				CWE:         "CWE-434",
				CVSS:        10.0,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Block PHP/ASP/JSP execution in upload directories; rename uploaded files; store outside web root",
				Tags:        []string{"chain", "upload", "rce", "webshell", "critical-chain"},
				ChainOf:     up.URL,
				Extracted:   up.Extracted,
				Session:     up.Session,
			})
			continue
		}
		for _, rce := range rceFindings {
			if sameHost(up.URL, rce.URL) {
				chains = append(chains, modules.Finding{
					Module:      "chain",
					Severity:    modules.Critical,
					URL:         up.URL,
					Param:       up.Param,
					Payload:     up.Payload + " + " + rce.Payload,
					Evidence:    fmt.Sprintf("File upload on %s + RCE on %s — webshell deployment path available", up.URL, rce.URL),
					Detail:      "Upload+RCE chain: file upload vulnerability combined with existing RCE suggests full server compromise is achievable",
					CWE:         "CWE-434",
					CVSS:        9.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Confidence:  modules.Likely,
					Remediation: "Fix file upload restrictions and RCE vulnerability independently",
					Tags:        []string{"chain", "upload", "rce"},
					ChainOf:     up.URL,
					Session:     up.Session,
				})
				break
			}
		}
	}
	return dedup(chains)
}

// corsWithAuth detects misconfigured CORS on authenticated endpoints — allows cross-origin
// data theft when the victim is authenticated (credentials: include).
func corsWithAuth(findings []modules.Finding) []modules.Finding {
	var corsFindings []modules.Finding
	hasAuth := false
	for _, f := range findings {
		if f.Module == "cors" && f.Confidence == modules.Confirmed {
			corsFindings = append(corsFindings, f)
		}
		if f.Module == "jwt" || f.Module == "csrf" || f.Module == "nosql" || f.Module == "sqli" {
			hasAuth = true
		}
	}

	if !hasAuth || len(corsFindings) == 0 {
		return nil
	}

	var chains []modules.Finding
	for _, cors := range corsFindings {
		chains = append(chains, modules.Finding{
			Module:      "chain",
			Severity:    modules.Critical,
			URL:         cors.URL,
			Param:       cors.Param,
			Payload:     cors.Payload,
			Evidence:    fmt.Sprintf("CORS misconfiguration on authenticated endpoint %s — cross-origin data theft possible", cors.URL),
			Detail:      "CORS+auth chain: misconfigured CORS policy allows attacker-controlled origins to make authenticated cross-origin requests and read sensitive API responses",
			CWE:         "CWE-942",
			CVSS:        8.1,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
			Confidence:  modules.Likely,
			Remediation: "Restrict CORS origins to trusted domains; never use wildcard with credentials; validate Origin header server-side",
			Tags:        []string{"chain", "cors", "auth", "data-theft"},
			ChainOf:     cors.URL,
			Session:     cors.Session,
		})
	}
	return dedup(chains)
}

// openRedirectOAuth detects open redirect on OAuth endpoints — used to steal authorization codes/tokens.
func openRedirectOAuth(findings []modules.Finding) []modules.Finding {
	var chains []modules.Finding
	var oauthFindings, redirectFindings []modules.Finding
	for _, f := range findings {
		switch f.Module {
		case "oauth":
			oauthFindings = append(oauthFindings, f)
		case "openredirect":
			redirectFindings = append(redirectFindings, f)
		}
	}

	for _, redir := range redirectFindings {
		urlLow := strings.ToLower(redir.URL)
		if !isAuthEndpoint(urlLow) {
			continue
		}
		chains = append(chains, modules.Finding{
			Module:      "chain",
			Severity:    modules.Critical,
			URL:         redir.URL,
			Param:       redir.Param,
			Payload:     redir.Payload,
			Evidence:    fmt.Sprintf("Open redirect on auth endpoint %s — OAuth code/token theft possible", redir.URL),
			Detail:      "Open redirect→OAuth token theft: open redirect on an OAuth/auth endpoint allows attackers to intercept authorization codes or tokens by crafting a malicious redirect_uri that passes server-side validation",
			CWE:         "CWE-601",
			CVSS:        8.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
			Confidence:  modules.Likely,
			Remediation: "Validate redirect_uri against registered allow-list; reject open redirects on auth flows",
			Tags:        []string{"chain", "openredirect", "oauth", "token-theft"},
			ChainOf:     redir.URL,
			Session:     redir.Session,
		})
	}

	for _, oauth := range oauthFindings {
		if oauth.Confidence != modules.Confirmed {
			continue
		}
		for _, redir := range redirectFindings {
			if sameHost(oauth.URL, redir.URL) {
				chains = append(chains, modules.Finding{
					Module:      "chain",
					Severity:    modules.Critical,
					URL:         oauth.URL,
					Param:       oauth.Param,
					Payload:     oauth.Payload,
					Evidence:    fmt.Sprintf("OAuth vulnerability (%s) + open redirect on same host", oauth.Evidence),
					Detail:      "OAuth flaw + open redirect: combined attack allows full account takeover via authorization code interception",
					CWE:         "CWE-601",
					CVSS:        9.3,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
					Confidence:  modules.Confirmed,
					Remediation: "Fix OAuth redirect_uri validation and open redirect independently; use PKCE; bind authorization codes to client",
					Tags:        []string{"chain", "oauth", "openredirect", "account-takeover"},
					ChainOf:     oauth.URL,
					Session:     oauth.Session,
				})
				break
			}
		}
	}
	return dedup(chains)
}

func isAuthEndpoint(urlLow string) bool {
	for _, kw := range []string{"login", "signin", "auth", "authenticate", "logon", "session", "token", "oauth"} {
		if strings.Contains(urlLow, kw) {
			return true
		}
	}
	return false
}

func isAuthParam(paramLow string) bool {
	for _, kw := range []string{"password", "passwd", "pass", "pwd", "username", "user", "email", "login"} {
		if strings.Contains(paramLow, kw) {
			return true
		}
	}
	return false
}

func sameHost(a, b string) bool {
	ai := strings.Index(a, "://")
	bi := strings.Index(b, "://")
	if ai < 0 || bi < 0 {
		return false
	}
	aHost := strings.SplitN(a[ai+3:], "/", 2)[0]
	bHost := strings.SplitN(b[bi+3:], "/", 2)[0]
	return aHost == bHost
}

func dedup(findings []modules.Finding) []modules.Finding {
	seen := make(map[string]struct{})
	var out []modules.Finding
	for _, f := range findings {
		key := f.URL + "|" + f.Detail
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}
