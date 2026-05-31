package paths

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

type pathEntry struct {
	path     string
	marker   string // must appear in body to confirm (empty = status code only)
	severity modules.Severity
	detail   string
}

var sensitivePaths = []pathEntry{
	// Version control — critical leaks
	{"/.git/HEAD", "ref:", modules.Critical, "Git repository HEAD exposed — full source code may be downloadable"},
	{"/.git/config", "[core]", modules.Critical, "Git config exposed — may contain remote credentials"},
	{"/.git/COMMIT_EDITMSG", "", modules.High, "Git commit message exposed"},
	{"/.svn/entries", "dir", modules.Critical, "SVN repository exposed"},
	{"/.hg/hgrc", "[paths]", modules.High, "Mercurial config exposed"},

	// Environment & secrets
	{"/.env", "DB_", modules.Critical, ".env file exposed — database credentials likely present"},
	{"/.env.local", "DB_", modules.Critical, ".env.local exposed"},
	{"/.env.production", "=", modules.Critical, ".env.production exposed"},
	{"/.env.backup", "=", modules.Critical, ".env.backup exposed"},
	{"/.env.dev", "=", modules.High, ".env.dev exposed"},
	{"/env.json", "\"db\"", modules.Critical, "env.json exposed"},

	// App configs
	{"/wp-config.php", "DB_NAME", modules.Critical, "WordPress config exposed — database credentials"},
	{"/config.php.bak", "<?php", modules.Critical, "PHP config backup exposed"},
	{"/config.php", "password", modules.High, "PHP config with credentials"},
	{"/configuration.php", "password", modules.High, "Joomla config exposed"},
	{"/settings.py", "SECRET_KEY", modules.Critical, "Django settings exposed — secret key present"},
	{"/local_settings.py", "SECRET_KEY", modules.Critical, "Django local settings exposed"},
	{"/application.properties", "spring", modules.High, "Spring Boot config exposed"},
	{"/application.yml", "password:", modules.High, "Spring Boot YAML config exposed"},
	{"/database.yml", "password:", modules.Critical, "Rails database config exposed"},
	{"/config/database.yml", "password:", modules.Critical, "Rails database config exposed"},
	{"/config.yml", "password:", modules.High, "YAML config with credentials"},
	{"/config.json", "password", modules.High, "JSON config with credentials"},
	{"/.npmrc", "_authToken", modules.Critical, "npm config with auth token"},
	{"/.pypirc", "password", modules.High, "PyPI config with credentials"},
	{"/composer.json", "require", modules.Info, "PHP composer.json exposed — dependency map"},

	// SSH / Keys
	{"/.ssh/id_rsa", "PRIVATE KEY", modules.Critical, "SSH private key exposed"},
	{"/.ssh/id_ed25519", "PRIVATE KEY", modules.Critical, "SSH private key (ed25519) exposed"},
	{"/id_rsa", "PRIVATE KEY", modules.Critical, "SSH private key in web root"},
	{"/server.key", "PRIVATE KEY", modules.Critical, "TLS private key exposed"},
	{"/private.key", "PRIVATE KEY", modules.Critical, "Private key exposed"},

	// Backups / archives
	{"/backup.zip", "PK\x03\x04", modules.Critical, "Backup ZIP archive exposed"},
	{"/backup.tar.gz", "\x1f\x8b", modules.Critical, "Backup tar.gz archive exposed"},
	{"/www.zip", "PK\x03\x04", modules.Critical, "Web root ZIP backup exposed"},
	{"/site.zip", "PK\x03\x04", modules.Critical, "Site backup ZIP exposed"},
	{"/db.sql", "CREATE TABLE", modules.Critical, "SQL database dump exposed"},
	{"/dump.sql", "CREATE TABLE", modules.Critical, "SQL dump exposed"},
	{"/database.sql", "CREATE TABLE", modules.Critical, "Database SQL dump exposed"},
	{"/backup.sql", "INSERT INTO", modules.Critical, "SQL backup exposed"},

	// Admin panels
	{"/admin", "", modules.Medium, "Admin panel accessible"},
	{"/admin/login", "", modules.Medium, "Admin login page found"},
	{"/admin/dashboard", "", modules.Medium, "Admin dashboard found"},
	{"/admin/users", "", modules.Medium, "Admin user management found"},
	{"/admin/config", "", modules.High, "Admin config endpoint"},
	{"/administrator", "", modules.Medium, "Administrator panel found"},
	{"/administrator/index.php", "Joomla", modules.Medium, "Joomla administrator panel"},
	{"/wp-admin", "WordPress", modules.Medium, "WordPress admin panel"},
	{"/wp-admin/", "log in", modules.Medium, "WordPress admin login"},
	{"/phpmyadmin", "phpMyAdmin", modules.High, "phpMyAdmin exposed — direct DB access"},
	{"/phpmyadmin/", "phpMyAdmin", modules.High, "phpMyAdmin exposed"},
	{"/pma/", "phpMyAdmin", modules.High, "phpMyAdmin at /pma/"},
	{"/pma", "phpMyAdmin", modules.High, "phpMyAdmin at /pma"},
	{"/myadmin", "phpMyAdmin", modules.High, "phpMyAdmin at /myadmin"},
	{"/db/", "phpMyAdmin", modules.High, "DB admin at /db/"},
	{"/adminer.php", "Adminer", modules.High, "Adminer DB admin tool exposed"},
	{"/adminer", "Adminer", modules.High, "Adminer exposed"},
	{"/panel", "", modules.Low, "Panel endpoint found"},
	{"/dashboard", "", modules.Low, "Dashboard endpoint found"},
	{"/cpanel", "", modules.Medium, "cPanel interface found"},
	{"/manage", "", modules.Low, "Management interface found"},
	{"/management", "", modules.Low, "Management interface found"},
	{"/mgmt", "", modules.Low, "Management endpoint found"},
	{"/controlpanel", "", modules.Medium, "Control panel found"},
	{"/admin-panel", "", modules.Medium, "Admin panel found"},
	{"/backend", "", modules.Medium, "Backend interface found"},
	{"/siteadmin", "", modules.Medium, "Site admin panel found"},
	{"/webadmin", "", modules.Medium, "Web admin interface found"},
	{"/sqladmin", "", modules.Medium, "SQL admin panel found"},
	{"/portal", "", modules.Low, "Portal interface found"},
	{"/secure", "", modules.Low, "Secure area found"},
	{"/private", "", modules.Low, "Private area found"},

	// Monitoring and observability dashboards
	{"/grafana", "grafana", modules.Medium, "Grafana dashboard exposed"},
	{"/grafana/", "grafana", modules.Medium, "Grafana dashboard at /grafana/"},
	{"/grafana/login", "grafana", modules.Medium, "Grafana login page exposed"},
	{"/prometheus", "Prometheus", modules.Medium, "Prometheus UI exposed"},
	{"/prometheus/", "Prometheus", modules.Medium, "Prometheus UI at /prometheus/"},
	{"/alertmanager", "Alertmanager", modules.Medium, "Alertmanager UI exposed"},
	{"/alertmanager/", "Alertmanager", modules.Medium, "Alertmanager at /alertmanager/"},
	{"/kibana", "kibana", modules.Medium, "Kibana dashboard exposed"},
	{"/kibana/", "kibana", modules.Medium, "Kibana at /kibana/"},
	{"/jaeger", "jaeger", modules.Medium, "Jaeger tracing UI exposed"},
	{"/zipkin", "zipkin", modules.Medium, "Zipkin tracing UI exposed"},

	// Jupyter notebooks — interactive code execution
	{"/jupyter", "jupyter", modules.High, "Jupyter Notebook exposed — interactive code execution"},
	{"/lab", "jupyter", modules.High, "JupyterLab exposed — interactive code execution"},
	{"/notebooks", "jupyter", modules.High, "Jupyter Notebooks exposed"},
	{"/jupyter/api/kernels", "\"id\"", modules.Critical, "Jupyter kernel API — active execution contexts"},
	{"/api/kernels", "kernel_id", modules.Critical, "Jupyter kernel API at /api/kernels"},

	// HashiCorp Vault
	{"/ui/vault", "Vault", modules.High, "HashiCorp Vault UI exposed"},
	{"/vault/ui", "Vault", modules.High, "HashiCorp Vault UI at /vault/ui"},
	{"/vault", "Vault", modules.High, "HashiCorp Vault endpoint"},

	// Jenkins
	{"/jenkins", "hudson", modules.High, "Jenkins CI/CD exposed"},
	{"/jenkins/script", "Groovy", modules.Critical, "Jenkins Script Console — Groovy RCE"},
	{"/script", "Groovy", modules.Critical, "Jenkins Script Console at /script"},

	// PHP debug / info
	{"/phpinfo.php", "phpinfo()", modules.High, "phpinfo() page exposed — full PHP/server config leak"},
	{"/info.php", "phpinfo()", modules.High, "phpinfo() exposed"},
	{"/php_info.php", "phpinfo()", modules.High, "phpinfo() exposed"},
	{"/_profiler", "Symfony", modules.High, "Symfony profiler exposed"},
	{"/_profiler/phpinfo", "phpinfo()", modules.High, "Symfony profiler phpinfo exposed"},

	// API documentation (extended)
	{"/redoc", "\"openapi\"", modules.Medium, "ReDoc API documentation exposed"},
	{"/api/docs", "swagger", modules.Medium, "API docs at /api/docs"},
	{"/docs/swagger", "swagger", modules.Medium, "Swagger docs at /docs/swagger"},
	{"/api/swagger-ui", "swagger", modules.Medium, "Swagger UI at /api/swagger-ui"},

	// API documentation
	{"/swagger.json", "\"swagger\"", modules.Medium, "Swagger API docs exposed — full API endpoint map"},
	{"/swagger-ui.html", "swagger", modules.Medium, "Swagger UI exposed"},
	{"/api/swagger.json", "\"swagger\"", modules.Medium, "Swagger API docs exposed"},
	{"/api/v1/swagger.json", "\"swagger\"", modules.Medium, "Swagger v1 docs exposed"},
	{"/openapi.json", "\"openapi\"", modules.Medium, "OpenAPI spec exposed"},
	{"/api/openapi.json", "\"openapi\"", modules.Medium, "OpenAPI spec exposed"},
	{"/api-docs", "", modules.Medium, "API docs endpoint found"},
	{"/graphql", "\"data\"", modules.Medium, "GraphQL endpoint exposed"},
	{"/graphiql", "graphiql", modules.Medium, "GraphiQL IDE exposed — interactive API exploration"},
	{"/api/graphql", "\"data\"", modules.Medium, "GraphQL endpoint at /api/graphql"},
	{"/v1/graphql", "\"data\"", modules.Medium, "GraphQL endpoint at /v1/graphql"},

	// Debug / metrics endpoints
	{"/debug/pprof", "goroutine", modules.High, "Go pprof debug endpoint exposed — heap/goroutine dumps"},
	{"/debug/pprof/heap", "heap", modules.High, "Go heap profile exposed"},
	{"/metrics", "# HELP", modules.Medium, "Prometheus metrics endpoint exposed"},
	{"/actuator", "\"_links\"", modules.High, "Spring Boot actuator exposed"},
	{"/actuator/env", "activeProfiles", modules.Critical, "Spring Boot env actuator — config + secrets exposed"},
	{"/actuator/health", "\"status\"", modules.Low, "Spring Boot health actuator"},
	{"/actuator/mappings", "\"mappings\"", modules.Medium, "Spring Boot route map exposed"},
	{"/actuator/beans", "\"beans\"", modules.Medium, "Spring Boot bean list exposed"},
	{"/server-status", "Apache Status", modules.Medium, "Apache server-status exposed"},
	{"/server-info", "Apache Server", modules.Medium, "Apache server-info exposed"},
	{"/.well-known/security.txt", "Contact:", modules.Info, "security.txt found — check for disclosed info"},

	// Logs
	{"/debug.log", "Error", modules.Medium, "Debug log exposed"},
	{"/error.log", "Error", modules.Medium, "Error log exposed"},
	{"/access.log", "GET", modules.Medium, "Access log exposed"},
	{"/logs/debug.log", "Error", modules.Medium, "Debug log exposed at /logs/"},
	{"/laravel.log", "local.ERROR", modules.High, "Laravel log exposed — may contain stack traces"},
	{"/storage/logs/laravel.log", "local.ERROR", modules.High, "Laravel log exposed"},

	// Misc sensitive
	{"/.htpasswd", ":", modules.Critical, ".htpasswd exposed — HTTP auth credentials"},
	{"/.htaccess", "RewriteRule", modules.Medium, ".htaccess exposed — reveals rewrite rules"},
	{"/web.config", "<configuration>", modules.Medium, "IIS web.config exposed"},
	{"/WEB-INF/web.xml", "<web-app", modules.High, "Java WEB-INF/web.xml exposed"},
	{"/crossdomain.xml", "<cross-domain-policy>", modules.Medium, "crossdomain.xml — Flash/Silverlight policy"},
	{"/clientaccesspolicy.xml", "<access-policy>", modules.Medium, "clientaccesspolicy.xml — Silverlight policy"},
	{"/.DS_Store", "\x00\x00\x00\x01", modules.Medium, ".DS_Store file exposed — reveals directory structure"},
	{"/robots.txt", "Disallow", modules.Info, "robots.txt — may reveal hidden paths"},
	{"/.bash_history", "cd ", modules.Critical, ".bash_history exposed — command history"},
	{"/composer.lock", "\"name\"", modules.Low, "composer.lock exposed — exact dependency versions"},
	{"/package.json", "\"name\"", modules.Low, "package.json exposed — dependency map"},
	{"/yarn.lock", "# yarn lockfile", modules.Low, "yarn.lock exposed"},

	// API versioning discovery
	{"/api", "\"", modules.Info, "API root exposed"},
	{"/api/v1", "\"", modules.Info, "API v1 endpoint"},
	{"/api/v2", "\"", modules.Info, "API v2 endpoint"},
	{"/api/v3", "\"", modules.Info, "API v3 endpoint"},
	{"/v1", "\"", modules.Info, "/v1 endpoint"},
	{"/v2", "\"", modules.Info, "/v2 endpoint"},
	{"/rest/api/2", "\"", modules.Info, "Jira REST API v2"},
	{"/rest/api/latest", "\"", modules.Info, "Jira REST API latest"},

	// WordPress enumeration
	{"/wp-json/wp/v2/users", "\"id\"", modules.High, "WordPress user enumeration via REST API"},
	{"/wp-json/wp/v2/posts", "\"id\"", modules.Medium, "WordPress posts via REST API"},
	{"/?author=1", "class=\"author", modules.Medium, "WordPress author ID enumeration"},
	{"/wp-content/debug.log", "PHP", modules.High, "WordPress debug.log exposed"},
	{"/wp-includes/version.php", "wp_version", modules.Medium, "WordPress version.php exposed"},
	{"/wp-cron.php", "", modules.Low, "WordPress wp-cron.php accessible"},
	{"/xmlrpc.php", "<?xml", modules.Medium, "WordPress XML-RPC enabled — bruteforce amplification"},

	// Drupal
	{"/CHANGELOG.txt", "Drupal", modules.Medium, "Drupal CHANGELOG.txt — version fingerprint"},
	{"/core/CHANGELOG.txt", "Drupal", modules.Medium, "Drupal 8+ CHANGELOG exposed"},
	{"/update.php", "Drupal", modules.Medium, "Drupal update.php accessible"},
	{"/install.php", "Drupal", modules.Medium, "Drupal install.php accessible"},
	{"/sites/default/files/.htaccess", "", modules.Low, "Drupal .htaccess accessible"},

	// Joomla
	{"/administrator/manifests/files/joomla.xml", "Joomla", modules.Medium, "Joomla version disclosure"},
	{"/language/en-GB/en-GB.xml", "Joomla", modules.Low, "Joomla language file exposed"},
	{"/htaccess.txt", "Joomla", modules.Low, "Joomla htaccess.txt exposed"},
	{"/web.config.txt", "", modules.Low, "Joomla web.config.txt exposed"},

	// Magento
	{"/app/etc/local.xml", "connection", modules.Critical, "Magento local.xml — database credentials"},
	{"/app/etc/env.php", "db", modules.Critical, "Magento env.php — database credentials"},
	{"/downloader/", "Magento", modules.High, "Magento Connect downloader exposed"},
	{"/var/log/system.log", "ERR", modules.Medium, "Magento system.log exposed"},
	{"/var/log/exception.log", "Exception", modules.Medium, "Magento exception.log exposed"},

	// Laravel / PHP frameworks
	{"/telescope", "telescope", modules.High, "Laravel Telescope (debug UI) exposed"},
	{"/telescope/requests", "\"data\"", modules.High, "Laravel Telescope requests exposed"},
	{"/_ignition/health-check", "can_execute_commands", modules.High, "Laravel Ignition health-check exposed"},
	{"/horizon", "horizon", modules.High, "Laravel Horizon (queue dashboard) exposed"},
	{"/laravel-filemanager", "", modules.High, "Laravel file manager exposed"},

	// Node.js / Express
	{"/node_modules/", "index of", modules.Critical, "node_modules directory listing"},
	{"/.npmrc", "_authToken", modules.Critical, "npm config with auth token"},
	{"/package-lock.json", "\"lockfileVersion\"", modules.Low, "package-lock.json exposed"},

	// Python / Django / Flask
	{"/__debug__/", "djdt", modules.High, "Django Debug Toolbar exposed"},
	{"/console", "Werkzeug", modules.Critical, "Werkzeug debug console — interactive Python RCE"},
	{"/manage.py", "django", modules.High, "Django manage.py accessible"},

	// Ruby on Rails
	{"/rails/info/properties", "Rails", modules.High, "Rails info properties exposed — environment details"},
	{"/rails/info/routes", "GET", modules.Medium, "Rails route list exposed"},

	// Spring Boot Actuator — extended
	{"/actuator/configprops", "\"contexts\"", modules.Critical, "Spring Boot configprops — all config properties"},
	{"/actuator/httptrace", "\"traces\"", modules.High, "Spring Boot httptrace — recent HTTP requests with headers"},
	{"/actuator/dump", "\"threads\"", modules.High, "Spring Boot thread dump"},
	{"/actuator/logfile", "", modules.High, "Spring Boot logfile exposed"},
	{"/actuator/shutdown", "", modules.Critical, "Spring Boot shutdown endpoint — kill application remotely"},
	{"/actuator/gateway/routes", "\"id\"", modules.High, "Spring Cloud Gateway routes exposed"},

	// Go / Prometheus
	{"/debug/vars", "cmdline", modules.Medium, "Go expvar endpoint exposed — runtime metrics"},
	{"/debug/requests", "", modules.Medium, "Go net/trace requests exposed"},
	{"/debug/events", "", modules.Medium, "Go net/trace events exposed"},

	// Container / Kubernetes / Cloud
	{"/v2/", "\"errors\"", modules.Medium, "Docker Registry v2 API accessible"},
	{"/v2/_catalog", "\"repositories\"", modules.High, "Docker Registry catalog — image list exposed"},
	{"/.dockerenv", "", modules.Low, ".dockerenv — confirms running inside Docker"},
	{"/kube/config", "apiVersion", modules.Critical, "Kubernetes config exposed"},
	{"/.kube/config", "apiVersion", modules.Critical, "Kubernetes ~/.kube/config exposed"},
	{"/healthz", "", modules.Info, "Kubernetes healthz endpoint"},
	{"/readyz", "", modules.Info, "Kubernetes readyz endpoint"},
	{"/livez", "", modules.Info, "Kubernetes livez endpoint"},
	// etcd, Vault, Consul exposure
	{"/v1/sys/health", "initialized", modules.High, "HashiCorp Vault health endpoint exposed"},
	{"/v1/kv/", "\"Key\"", modules.Critical, "Consul KV store accessible"},
	{"/v1/agent/members", "\"Name\"", modules.High, "Consul agent members exposed"},
	{"/v1/catalog/services", "\"consul\"", modules.High, "Consul service catalog exposed"},
	// Additional cloud provider credentials
	{"/gcloud-key.json", "\"private_key\"", modules.Critical, "GCP service account key exposed"},
	{"/secrets.json", "\"password\"", modules.Critical, "secrets.json exposed"},
	{"/secrets.yml", "password:", modules.Critical, "secrets.yml exposed"},
	{"/secrets.yaml", "password:", modules.Critical, "secrets.yaml exposed"},
	{"/.vault-token", "", modules.Critical, "Vault token file exposed"},

	// CI/CD and DevOps
	{"/.travis.yml", "language", modules.Medium, "Travis CI config exposed — build secrets may be present"},
	{"/.gitlab-ci.yml", "script", modules.Medium, "GitLab CI config exposed"},
	{"/.github/workflows", "", modules.Low, "GitHub Actions workflows accessible"},
	{"/Jenkinsfile", "pipeline", modules.Medium, "Jenkinsfile exposed — CI/CD pipeline config"},
	{"/Dockerfile", "FROM", modules.Medium, "Dockerfile exposed — infrastructure details"},
	{"/docker-compose.yml", "services", modules.Medium, "docker-compose.yml exposed — service topology"},
	{"/docker-compose.yaml", "services", modules.Medium, "docker-compose.yaml exposed"},
	{"/.env.staging", "=", modules.High, ".env.staging exposed"},
	{"/.env.test", "=", modules.Medium, ".env.test exposed"},

	// Cloud provider credentials / configs
	{"/.aws/credentials", "aws_access_key_id", modules.Critical, "AWS credentials file exposed"},
	{"/.aws/config", "[default]", modules.High, "AWS config file exposed"},
	{"/gcp-credentials.json", "\"type\"", modules.Critical, "GCP service account credentials exposed"},
	{"/service-account.json", "\"private_key\"", modules.Critical, "Service account JSON key exposed"},
	{"/terraform.tfstate", "\"serial\"", modules.Critical, "Terraform state file — infrastructure + secrets"},
	{"/terraform.tfvars", "=", modules.Critical, "Terraform variables — may contain secrets"},
	{"/.terraformrc", "credentials", modules.High, "Terraform credentials config exposed"},

	// Certificate / crypto material
	{"/fullchain.pem", "BEGIN CERTIFICATE", modules.High, "TLS certificate chain exposed"},
	{"/cert.pem", "BEGIN CERTIFICATE", modules.Medium, "TLS certificate exposed"},
	{"/privkey.pem", "PRIVATE KEY", modules.Critical, "TLS private key exposed"},
	{"/server.crt", "BEGIN CERTIFICATE", modules.Medium, "Server certificate exposed"},

	// Database / cache exports
	{"/.db", "", modules.High, "Database file in web root"},
	{"/data.db", "", modules.Critical, "SQLite database exposed"},
	{"/app.db", "", modules.Critical, "SQLite app database exposed"},
	{"/db.sqlite", "", modules.Critical, "SQLite database exposed"},
	{"/db.sqlite3", "", modules.Critical, "SQLite3 database exposed"},
	{"/redis.conf", "requirepass", modules.Critical, "Redis config — may contain password"},
	{"/memcached.conf", "port", modules.Medium, "Memcached config exposed"},

	// Common backup suffixes (root index)
	{"/index.php.bak", "<?php", modules.High, "PHP backup file exposed"},
	{"/index.php~", "<?php", modules.High, "PHP tilde backup exposed"},
	{"/index.html.bak", "<html", modules.Medium, "HTML backup exposed"},
	{"/config.bak", "=", modules.High, "Config backup exposed"},
	{"/web.xml.bak", "<web-app", modules.High, "web.xml backup exposed"},

	// Source code disclosure
	{"/.git/logs/HEAD", "commit", modules.Critical, "Git logs/HEAD exposed — commit history readable"},
	{"/.git/refs/heads/main", "", modules.High, "Git main branch ref exposed"},
	{"/.git/refs/heads/master", "", modules.High, "Git master branch ref exposed"},
	{"/.git/FETCH_HEAD", "", modules.Medium, "Git FETCH_HEAD exposed"},
	{"/.gitignore", "", modules.Low, ".gitignore exposed — reveals directory structure"},

	// Misc administrative / debug
	{"/test.php", "phpinfo", modules.Medium, "test.php exposed"},
	{"/test", "", modules.Info, "/test endpoint accessible"},
	{"/healthcheck", "", modules.Info, "Health check endpoint"},
	{"/health", "", modules.Info, "Health endpoint"},
	{"/ping", "", modules.Info, "Ping endpoint"},
	{"/status", "", modules.Info, "Status endpoint"},
	{"/version", "", modules.Info, "Version endpoint — technology fingerprint"},
	{"/config", "", modules.Medium, "Config endpoint accessible"},
	{"/info", "", modules.Low, "Info endpoint accessible"},
	{"/env", "", modules.High, "/env endpoint — may expose environment variables"},
	{"/trace", "", modules.Low, "/trace endpoint"},
	{"/dump", "", modules.Medium, "/dump endpoint"},
	{"/console", "", modules.High, "/console endpoint"},
	{"/admin/config", "", modules.High, "Admin config endpoint"},

	// WSDL / WADL service descriptions
	{"/service.wsdl", "<definitions", modules.Medium, "WSDL service description exposed — SOAP API map"},
	{"/api.wsdl", "<definitions", modules.Medium, "WSDL API description exposed"},
	{"/application.wadl", "<application", modules.Medium, "WADL REST API description exposed"},
}

type Module struct {
	client    *client.Client
	seenHosts sync.Map
}

func New(c *client.Client) *Module {
	return &Module{client: c}
}

func (m *Module) Name() string { return "paths" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}
	base := u.Scheme + "://" + u.Host

	// Run once per host
	if _, loaded := m.seenHosts.LoadOrStore(base, struct{}{}); loaded {
		return nil, nil
	}

	// Establish soft-404 fingerprint
	notFoundBody, notFoundStatus := m.probe(ctx, base+"/erebus_nonexistent_9x82b4")

	var findings []modules.Finding

	for _, entry := range sensitivePaths {
		if ctx.Err() != nil {
			break
		}
		body, status := m.probe(ctx, base+entry.path)
		if body == nil || status == 0 {
			continue
		}
		if status == 404 || status == 410 {
			continue
		}
		// Filter soft 404s: same status + similar body length
		if status == notFoundStatus && isSimilarBody(body, notFoundBody) {
			continue
		}
		// Require marker if specified
		if entry.marker != "" && !strings.Contains(string(body), entry.marker) {
			continue
		}
		// For marker-less entries: require non-redirect AND reject HTML (SPA catch-all).
		// An Angular/React app returns its index.html for every undefined route with HTTP 200.
		if entry.marker == "" {
			if status < 200 || status >= 300 {
				continue
			}
			if isHTMLBody(body) {
				continue
			}
		}

		cwe, cvss, cvssVec, remediation, tags := pathClassification(entry.severity)
		findings = append(findings, modules.Finding{
			Module:      "paths",
			Severity:    entry.severity,
			URL:         base + entry.path,
			Param:       "path",
			Payload:     entry.path,
			Evidence:    fmt.Sprintf("HTTP %d — %s", status, truncate(strings.TrimSpace(string(body)), 80)),
			Detail:      entry.detail,
			CWE:         cwe,
			CVSS:        cvss,
			CVSSVector:  cvssVec,
			Confidence:  modules.Confirmed,
			Remediation: remediation,
			Tags:        tags,
		})
	}

	return findings, nil
}

func (m *Module) probe(ctx context.Context, fullURL string) ([]byte, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, 0
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil, 0
	}
	return body, resp.StatusCode
}

// isSimilarBody returns true if two bodies are similar in size (soft-404 heuristic).
func isSimilarBody(a, b []byte) bool {
	if len(b) == 0 {
		return false
	}
	diff := len(a) - len(b)
	if diff < 0 {
		diff = -diff
	}
	// Within 15% or 200 bytes of each other → likely same template
	return diff < 200 || float64(diff)/float64(len(b)) < 0.15
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

func pathClassification(sev modules.Severity) (cwe string, cvss float64, cvssVector string, remediation string, tags []string) {
	switch sev {
	case modules.Critical:
		return "CWE-538", 9.1,
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			"Remove sensitive files from the web root; add them to .gitignore; rotate any exposed credentials immediately; configure the web server to deny access to these paths",
			[]string{"paths", "sensitive-file", "information-disclosure", "exposed-config"}
	case modules.High:
		return "CWE-538", 7.5,
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"Remove or restrict access to this file; ensure sensitive files are never placed in the web root; review web server configuration to deny directory traversal",
			[]string{"paths", "sensitive-file", "information-disclosure"}
	case modules.Medium:
		return "CWE-200", 5.3,
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			"Restrict access to this path; remove files that are not needed in the web root",
			[]string{"paths", "information-disclosure"}
	default:
		return "CWE-200", 2.4,
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
			"Review whether this file needs to be publicly accessible; restrict access if not required",
			[]string{"paths", "information-disclosure"}
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
