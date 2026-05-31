package sensitive

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

type pattern struct {
	name        string
	re          *regexp.Regexp
	severity    modules.Severity
	detail      string
	cwe         string
	remediation string
	tags        []string
}

var patterns = []pattern{
	// Cloud provider keys
	{
		"AWS Access Key ID",
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		modules.Critical,
		"AWS Access Key ID exposed in response",
		"CWE-200",
		"Revoke the key immediately in AWS IAM; rotate all credentials; store secrets in AWS Secrets Manager or Vault; audit CloudTrail for unauthorized use",
		[]string{"secrets", "aws", "cloud-credentials", "critical-exposure"},
	},
	{
		"AWS Secret Access Key",
		regexp.MustCompile(`(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key["'\s:=]+([A-Za-z0-9/+]{40})`),
		modules.Critical,
		"AWS Secret Access Key exposed",
		"CWE-200",
		"Revoke via AWS IAM immediately; rotate all associated credentials; audit CloudTrail; store secrets in AWS Secrets Manager",
		[]string{"secrets", "aws", "cloud-credentials", "critical-exposure"},
	},
	{
		"AWS Session Token",
		regexp.MustCompile(`(?i)aws[_\-\s]?session[_\-\s]?token["'\s:=]+([A-Za-z0-9/+=]{100,})`),
		modules.Critical,
		"AWS Session Token exposed",
		"CWE-200",
		"Session tokens expire automatically; investigate how the token was exposed; audit CloudTrail for unauthorized activity",
		[]string{"secrets", "aws", "cloud-credentials", "session-token"},
	},
	// Private key material
	{
		"Private Key",
		regexp.MustCompile(`-----BEGIN\s(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)\s(?:PRIVATE|SECRET)\sKEY-----`),
		modules.Critical,
		"Private key material exposed in response",
		"CWE-321",
		"Revoke and regenerate the key pair immediately; store private keys in HSMs or secrets managers; never serve private key material over HTTP",
		[]string{"secrets", "private-key", "cryptographic-material", "critical-exposure"},
	},
	// Google / Firebase
	{
		"Google/Firebase API Key",
		regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
		modules.High,
		"Google/Firebase API key exposed",
		"CWE-200",
		"Restrict the API key to allowed HTTP referrers and IP addresses in Google Cloud Console; rotate if unrestricted access is confirmed",
		[]string{"secrets", "google", "firebase", "api-key"},
	},
	{
		"Google OAuth Client Secret",
		regexp.MustCompile(`(?i)client[_\-]?secret["'\s:=]+([a-zA-Z0-9\-_]{24,})`),
		modules.Critical,
		"Google OAuth client secret exposed",
		"CWE-200",
		"Regenerate the OAuth client secret in Google Cloud Console immediately; audit for unauthorized OAuth grants",
		[]string{"secrets", "google", "oauth", "client-secret"},
	},
	{
		"GCP Service Account",
		regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		modules.Critical,
		"GCP service account JSON key in response",
		"CWE-200",
		"Delete the service account key in IAM; rotate credentials; move keys to Secret Manager; follow principle of least privilege for service accounts",
		[]string{"secrets", "gcp", "service-account", "cloud-credentials"},
	},
	// GitHub / GitLab
	{
		"GitHub Personal Access Token",
		regexp.MustCompile(`\b(ghp_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{59}|gho_[0-9a-zA-Z]{36})\b`),
		modules.Critical,
		"GitHub personal access token exposed",
		"CWE-200",
		"Revoke the token at github.com/settings/tokens; audit repository access and commit history for unauthorized changes",
		[]string{"secrets", "github", "personal-access-token"},
	},
	{
		"GitLab Personal Access Token",
		regexp.MustCompile(`\bglpat-[0-9a-zA-Z\-_]{20}\b`),
		modules.Critical,
		"GitLab personal access token exposed",
		"CWE-200",
		"Revoke the token in GitLab profile settings; audit project/group access for unauthorized changes",
		[]string{"secrets", "gitlab", "personal-access-token"},
	},
	// Stripe
	{
		"Stripe Live Secret Key",
		regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`),
		modules.Critical,
		"Stripe live secret key exposed",
		"CWE-200",
		"Roll the key immediately in Stripe Dashboard; audit payment logs for unauthorized charges; enable Stripe Radar fraud detection",
		[]string{"secrets", "stripe", "payment", "critical-exposure"},
	},
	{
		"Stripe Live Publishable Key",
		regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{24,}\b`),
		modules.Medium,
		"Stripe live publishable key exposed",
		"CWE-200",
		"Publishable keys are intended to be public but should be restricted to specific domains in Stripe Dashboard",
		[]string{"secrets", "stripe", "payment", "publishable-key"},
	},
	{
		"Stripe Restricted Key",
		regexp.MustCompile(`\brk_live_[0-9a-zA-Z]{24,}\b`),
		modules.Critical,
		"Stripe live restricted key exposed",
		"CWE-200",
		"Roll the key immediately in Stripe Dashboard; review restricted key permissions and audit activity",
		[]string{"secrets", "stripe", "payment", "critical-exposure"},
	},
	// Slack
	{
		"Slack Bot/User Token",
		regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b`),
		modules.High,
		"Slack token exposed",
		"CWE-200",
		"Revoke the token at api.slack.com/apps; audit workspace activity logs for unauthorized bot actions",
		[]string{"secrets", "slack", "bot-token"},
	},
	{
		"Slack Webhook",
		regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}`),
		modules.High,
		"Slack webhook URL exposed",
		"CWE-200",
		"Regenerate the webhook in Slack App settings; webhooks allow posting arbitrary messages to channels",
		[]string{"secrets", "slack", "webhook"},
	},
	// Twilio
	{
		"Twilio Account SID",
		regexp.MustCompile(`\bAC[0-9a-f]{32}\b`),
		modules.High,
		"Twilio Account SID exposed",
		"CWE-200",
		"Account SID alone is not sufficient for API calls; rotate the Auth Token immediately and audit SMS/call logs",
		[]string{"secrets", "twilio", "account-sid"},
	},
	{
		"Twilio Auth Token",
		regexp.MustCompile(`(?i)twilio[_\-\s]?auth[_\-\s]?token["'\s:=]+([0-9a-f]{32})`),
		modules.Critical,
		"Twilio Auth Token exposed",
		"CWE-200",
		"Rotate the Auth Token in Twilio Console immediately; audit account logs for unauthorized calls/SMS",
		[]string{"secrets", "twilio", "auth-token", "critical-exposure"},
	},
	// SendGrid
	{
		"SendGrid API Key",
		regexp.MustCompile(`\bSG\.[0-9a-zA-Z\-_]{22,}\.[0-9a-zA-Z\-_]{43,}\b`),
		modules.Critical,
		"SendGrid API key exposed",
		"CWE-200",
		"Revoke the key in SendGrid API Keys settings; audit email send activity for phishing or spam abuse",
		[]string{"secrets", "sendgrid", "api-key", "email"},
	},
	// Mailgun
	{
		"Mailgun API Key",
		regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`),
		modules.Critical,
		"Mailgun API key exposed",
		"CWE-200",
		"Rotate the key in Mailgun account settings; review sending logs for unauthorized email activity",
		[]string{"secrets", "mailgun", "api-key", "email"},
	},
	// Heroku
	{
		"Heroku API Key",
		regexp.MustCompile(`(?i)heroku[_\-\s]?api[_\-\s]?key["'\s:=]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`),
		modules.Critical,
		"Heroku API key exposed",
		"CWE-200",
		"Regenerate the API key in Heroku account settings; audit dyno and pipeline access",
		[]string{"secrets", "heroku", "api-key"},
	},
	// Tokens / sessions
	{
		"JWT Token",
		regexp.MustCompile(`\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b`),
		modules.Medium,
		"JWT token exposed — may allow session hijacking or privilege escalation",
		"CWE-200",
		"Implement short token lifetimes with refresh rotation; store tokens in httpOnly cookies, not localStorage; revoke affected sessions",
		[]string{"secrets", "jwt", "session-token", "auth"},
	},
	{
		"Bearer Token",
		regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9\-_.=+/]{20,})`),
		modules.High,
		"Bearer token exposed in response",
		"CWE-200",
		"Revoke the token; use short-lived tokens; never return tokens in response bodies; transmit only via Authorization headers over TLS",
		[]string{"secrets", "bearer-token", "auth"},
	},
	// Credentials in URLs and source
	{
		"Credentials in URL",
		regexp.MustCompile(`https?://[^:@/\s]{3,}:[^@/\s]{3,}@[^/\s]+`),
		modules.Critical,
		"Credentials embedded in URL",
		"CWE-522",
		"Remove credentials from URLs immediately; use environment variables or secrets managers; purge server logs containing the URL",
		[]string{"secrets", "credentials-in-url", "plaintext-credentials"},
	},
	{
		"Password in Source",
		regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|pass)\s*[=:]\s*["']?([^"'<>\s]{8,})`),
		modules.High,
		"Plaintext password/secret in source or response",
		"CWE-256",
		"Remove hardcoded credentials; use environment variables or secrets managers; rotate all exposed passwords",
		[]string{"secrets", "hardcoded-password", "plaintext-credentials"},
	},
	// Database connection strings
	{
		"Database Connection String",
		regexp.MustCompile(`(?i)(?:mysql|postgresql|postgres|mongodb|redis|mssql|sqlserver|oracle)://[^\s<>"']+`),
		modules.Critical,
		"Database connection string exposed",
		"CWE-200",
		"Remove connection strings from responses; store in environment variables or secrets managers; rotate database passwords; restrict DB network access to application servers only",
		[]string{"secrets", "database", "connection-string", "critical-exposure"},
	},
	{
		"JDBC Connection String",
		regexp.MustCompile(`(?i)jdbc:[a-z]+://[^\s"'<>]+`),
		modules.Critical,
		"JDBC connection string exposed",
		"CWE-200",
		"Remove JDBC URLs from responses; store credentials in environment variables; rotate database passwords",
		[]string{"secrets", "database", "jdbc", "connection-string"},
	},
	// Azure
	{
		"Azure Storage Key",
		regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}`),
		modules.Critical,
		"Azure Storage connection string exposed",
		"CWE-200",
		"Rotate the storage account key in Azure Portal immediately; use managed identities or SAS tokens with minimal permissions instead of account keys",
		[]string{"secrets", "azure", "storage", "cloud-credentials"},
	},
	{
		"Azure SAS Token",
		regexp.MustCompile(`(?i)sig=[A-Za-z0-9%+/=]{44,}`),
		modules.High,
		"Azure SAS token exposed",
		"CWE-200",
		"Revoke the SAS token by rotating the storage account key; use short-lived SAS tokens with minimal permissions and IP restrictions",
		[]string{"secrets", "azure", "sas-token"},
	},
	// Firebase
	{
		"Firebase DB URL",
		regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`),
		modules.Medium,
		"Firebase Realtime Database URL exposed — check public rules",
		"CWE-200",
		"Verify Firebase security rules deny unauthenticated read/write; avoid exposing DB URLs in client-side code if using server-side rendering",
		[]string{"secrets", "firebase", "database-url"},
	},
	// Dropbox / GitHub OAuth
	{
		"Dropbox Token",
		regexp.MustCompile(`\bsl\.[A-Za-z0-9_\-]{135,}\b`),
		modules.High,
		"Dropbox access token exposed",
		"CWE-200",
		"Revoke the token at dropbox.com/account/security; audit file access logs for unauthorized downloads",
		[]string{"secrets", "dropbox", "access-token"},
	},
	// NPM token
	{
		"NPM Token",
		regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
		modules.Critical,
		"NPM access token exposed — package publishing access",
		"CWE-200",
		"Revoke the token at npmjs.com/settings/tokens; audit published packages for supply-chain tampering; enable 2FA on the NPM account",
		[]string{"secrets", "npm", "supply-chain", "critical-exposure"},
	},
	// Internal IPs
	{
		"Internal IP Address",
		regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		modules.Low,
		"Internal/private IP address disclosed",
		"CWE-200",
		"Filter internal IP addresses from API responses, error messages, and headers; review reverse proxy configuration",
		[]string{"info-disclosure", "internal-ip", "network-recon"},
	},
	// Stack traces and errors
	{
		"Stack Trace",
		regexp.MustCompile(`(?i)(?:at [\w.$]+\([\w.]+:\d+\)|Traceback \(most recent call last\)|Exception in thread|java\.lang\.\w+Exception|System\.Exception|Fatal error:|Warning: mysqli_)`),
		modules.Medium,
		"Stack trace / exception detail exposed — internal paths and technology revealed",
		"CWE-209",
		"Configure production error handlers to return generic messages; log full stack traces server-side only; disable debug mode in production",
		[]string{"info-disclosure", "stack-trace", "error-handling"},
	},
	{
		"PHP Error / Warning",
		regexp.MustCompile(`(?i)(?:Fatal error|Parse error|Warning|Notice):\s+[^\n]{20,}\s+in\s+/[^\s]+`),
		modules.Medium,
		"PHP error message with file path exposed",
		"CWE-209",
		"Set display_errors=Off and log_errors=On in php.ini; use a custom error handler; never expose file paths in production",
		[]string{"info-disclosure", "php-error", "error-handling"},
	},
	// Email addresses (lower severity, useful for recon)
	{
		"Email Address",
		regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
		modules.Info,
		"Email address(es) found — useful for phishing/OSINT",
		"CWE-200",
		"Evaluate whether email addresses need to be included in API responses; consider obfuscation for public endpoints",
		[]string{"info-disclosure", "email", "osint"},
	},
	// Terraform / infra
	{
		"Terraform State Secret",
		regexp.MustCompile(`"sensitive":\s*true`),
		modules.High,
		"Terraform state with sensitive value exposed",
		"CWE-200",
		"Store Terraform state in encrypted remote backends (S3+SSE, Terraform Cloud); never expose state files via HTTP; restrict state file access to CI/CD only",
		[]string{"secrets", "terraform", "iac", "infrastructure"},
	},
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "sensitive" }

func (m *Module) Run(_ context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding
	body := string(page.Body)
	seen := make(map[string]struct{})

	for _, p := range patterns {
		match := p.re.FindString(body)
		if match == "" {
			continue
		}
		key := p.name + "|" + page.URL
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		findings = append(findings, modules.Finding{
			Module:      "sensitive",
			Severity:    p.severity,
			URL:         page.URL,
			Param:       "response body",
			Payload:     "",
			Evidence:    fmt.Sprintf("Pattern %q matched", p.name),
			Detail:      p.detail,
			CWE:         p.cwe,
			CVSS:        sensitiveCVSS(p.severity),
			CVSSVector:  sensitiveCVSSVector(p.severity),
			Confidence:  modules.Confirmed,
			Remediation: p.remediation,
			Tags:        p.tags,
			Extracted:   truncate(match, 200),
		})
	}

	// Excessive data exposure: API responses that return sensitive fields
	// not typically needed by the consuming UI (OWASP API3:2023 partial)
	findings = append(findings, m.checkExcessiveExposure(page)...)

	return findings, nil
}

// checkExcessiveExposure looks for JSON API responses that include fields the
// client almost certainly doesn't need: password hashes, internal flags, etc.
func (m *Module) checkExcessiveExposure(page crawler.Page) []modules.Finding {
	// Only check JSON API responses
	ct := page.Headers.Get("Content-Type")
	if !strings.Contains(ct, "application/json") && !strings.Contains(ct, "application/vnd.api") {
		return nil
	}

	body := strings.ToLower(string(page.Body))
	if len(body) < 20 {
		return nil
	}

	type exposure struct {
		field    string
		evidence string
		sev      modules.Severity
	}

	var found []exposure
	seen := make(map[string]struct{})

	checks := []exposure{
		{`"password"`, "password field in JSON response", modules.Critical},
		{`"password_hash"`, "password_hash in JSON response", modules.Critical},
		{`"passwd"`, "passwd field in JSON response", modules.Critical},
		{`"password_digest"`, "password_digest in JSON response", modules.Critical},
		{`"hashed_password"`, "hashed_password in JSON response", modules.Critical},
		{`"secret"`, "secret field in JSON response", modules.High},
		{`"api_secret"`, "api_secret in JSON response", modules.High},
		{`"private_key"`, "private_key in JSON response", modules.Critical},
		{`"access_token"`, "access_token in JSON response", modules.High},
		{`"refresh_token"`, "refresh_token in JSON response", modules.High},
		{`"ssn"`, "SSN (social security number) in JSON response", modules.Critical},
		{`"credit_card"`, "credit card number in JSON response", modules.Critical},
		{`"card_number"`, "credit card number in JSON response", modules.Critical},
		{`"cvv"`, "CVV in JSON response", modules.Critical},
		{`"social_security"`, "social security in JSON response", modules.Critical},
		{`"is_admin":true`, "is_admin:true exposed — internal privilege flag in API response", modules.High},
		{`"admin":true`, "admin:true exposed — internal privilege flag in API response", modules.High},
		{`"internal_id"`, "internal_id exposed in API response — may enable enumeration", modules.Medium},
		{`"__v"`, "MongoDB version key (__v) in API response — reveals ORM internals", modules.Low},
		{`"_id"`, "MongoDB _id in API response — reveals internal document ID", modules.Low},
		{`"created_at"`, "", modules.Info}, // common, skip
	}

	for _, c := range checks {
		if c.sev == modules.Info {
			continue
		}
		if !strings.Contains(body, c.field) {
			continue
		}
		if _, ok := seen[c.field]; ok {
			continue
		}
		seen[c.field] = struct{}{}
		found = append(found, c)
	}

	if len(found) == 0 {
		return nil
	}

	// Only report if ≥ 1 truly sensitive field, or ≥ 3 moderate ones
	criticalOrHigh := 0
	for _, f := range found {
		if f.sev == modules.Critical || f.sev == modules.High {
			criticalOrHigh++
		}
	}
	if criticalOrHigh == 0 && len(found) < 3 {
		return nil
	}

	names := make([]string, len(found))
	for i, f := range found {
		names[i] = strings.Trim(f.field, `"`)
	}

	maxSev := modules.Low
	for _, f := range found {
		if severityRank(f.sev) > severityRank(maxSev) {
			maxSev = f.sev
		}
	}

	return []modules.Finding{{
		Module:      "sensitive",
		Severity:    maxSev,
		URL:         page.URL,
		Param:       "JSON response body",
		Evidence:    fmt.Sprintf("Excessive data exposure: sensitive fields in API response: %s", strings.Join(names, ", ")),
		Detail:      "API returns more data than the client needs — sensitive internal fields (password hashes, tokens, privilege flags) are exposed in JSON responses. Clients should receive only the minimum necessary data.",
		CWE:         "CWE-213",
		CVSS:        exposureCVSS(maxSev),
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Confidence:  modules.Confirmed,
		Remediation: "Use response DTOs/serializers with explicit field allow-lists; never expose ORM model fields directly; use field-level access control",
		Tags:        []string{"excessive-data-exposure", "api3", "owasp-api", "info-disclosure"},
	}}
}

func sensitiveCVSS(sev modules.Severity) float64 {
	switch sev {
	case modules.Critical:
		return 9.8
	case modules.High:
		return 7.5
	case modules.Medium:
		return 5.3
	case modules.Low:
		return 2.7
	default:
		return 0.0
	}
}

func sensitiveCVSSVector(sev modules.Severity) string {
	switch sev {
	case modules.Critical:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	case modules.High:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
	case modules.Medium:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
	default:
		return "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
	}
}

func severityRank(s modules.Severity) int {
	switch s {
	case modules.Critical:
		return 4
	case modules.High:
		return 3
	case modules.Medium:
		return 2
	case modules.Low:
		return 1
	default:
		return 0
	}
}

func exposureCVSS(sev modules.Severity) float64 {
	switch sev {
	case modules.Critical:
		return 9.1
	case modules.High:
		return 7.5
	default:
		return 5.3
	}
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
