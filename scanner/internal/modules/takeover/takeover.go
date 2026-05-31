// Package takeover detects subdomain takeover vulnerabilities by resolving CNAME
// chains and checking for cloud-service "unclaimed resource" fingerprints.
// Runs once per unique host found during the crawl.
package takeover

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

type fingerprint struct {
	cnameSuffix string
	bodyPattern string
	service     string
	severity    modules.Severity
}

var fingerprints = []fingerprint{
	{"github.io", "There isn't a GitHub Pages site here", "GitHub Pages", modules.High},
	{"github.io", "For root URLs (apex domains) you must set up an A record", "GitHub Pages", modules.High},
	{"herokudns.com", "No such app", "Heroku", modules.High},
	{"herokuapp.com", "No such app", "Heroku", modules.High},
	{"netlify.app", "Not Found - Request ID", "Netlify", modules.High},
	{"netlifly.com", "Not Found - Request ID", "Netlify", modules.High},
	{"azurewebsites.net", "404 Web Site not found", "Azure Web Apps", modules.High},
	{"azurewebsites.net", "Microsoft Azure App Service", "Azure Web Apps", modules.Medium},
	{"cloudapp.net", "404 Web Site not found", "Azure Cloud", modules.High},
	{"s3-website", "NoSuchBucket", "AWS S3", modules.Critical},
	{"amazonaws.com", "NoSuchBucket", "AWS S3", modules.Critical},
	{"amazonaws.com", "The specified bucket does not exist", "AWS S3", modules.Critical},
	{"cloudfront.net", "ERROR: The request could not be satisfied", "AWS CloudFront", modules.High},
	{"fastly.net", "Fastly error: unknown domain", "Fastly CDN", modules.High},
	{"fastly.net", "Please check that this domain has been added", "Fastly CDN", modules.High},
	{"myshopify.com", "Sorry, this shop is currently unavailable", "Shopify", modules.Medium},
	{"surge.sh", "project not found", "Surge.sh", modules.High},
	{"surge.sh", "does not exist in our system", "Surge.sh", modules.High},
	{"readthedocs.io", "no project with that name", "ReadTheDocs", modules.Medium},
	{"ghost.io", "The thing you were looking for is no longer here", "Ghost.io", modules.Medium},
	{"helpjuice.com", "We could not find what you're looking for", "HelpJuice", modules.Medium},
	{"uservoice.com", "This UserVoice subdomain is currently available", "UserVoice", modules.Medium},
	{"wpengine.com", "The site you were looking for couldn't be found", "WP Engine", modules.Medium},
	{"zendesk.com", "Help Center Closed", "Zendesk", modules.Medium},
	{"zendesk.com", "Oops, this help center no longer exists", "Zendesk", modules.Medium},
	{"freshdesk.com", "We couldn't find this help center", "Freshdesk", modules.Medium},
	{"tumblr.com", "There's nothing here", "Tumblr", modules.Medium},
	{"bitbucket.io", "Repository not found", "Bitbucket Pages", modules.High},
	{"launchrock.com", "It looks like you may have taken a wrong turn somewhere", "Launchrock", modules.Medium},
	{"agilecrm.com", "Sorry, this page is no longer available", "Agile CRM", modules.Medium},
	{"pingdom.com", "This public report page has not been activated", "Pingdom", modules.Low},
	{"statuspage.io", "You are being redirected", "Statuspage.io", modules.Medium},
	{"cargocollective.com", "404 Not Found", "Cargo Collective", modules.Medium},
}

type Module struct {
	client    *client.Client
	seenHosts sync.Map
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "takeover" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}
	host := u.Hostname()
	if _, loaded := m.seenHosts.LoadOrStore(host, struct{}{}); loaded {
		return nil, nil
	}

	var findings []modules.Finding

	// Resolve CNAME chain
	cname, err := net.LookupCNAME(host)
	if err != nil || cname == host+"." {
		// No CNAME (A/AAAA record only) — still check for service fingerprints
		// if the host looks like a cloud resource itself
		for _, fp := range fingerprints {
			if strings.HasSuffix(strings.ToLower(host), fp.cnameSuffix) {
				if f := m.checkFingerprint(ctx, page.URL, host, host, fp); f != nil {
					findings = append(findings, *f)
					break
				}
			}
		}
		return findings, nil
	}

	cnameLow := strings.ToLower(strings.TrimSuffix(cname, "."))

	for _, fp := range fingerprints {
		if !strings.Contains(cnameLow, fp.cnameSuffix) {
			continue
		}
		if f := m.checkFingerprint(ctx, page.URL, host, cnameLow, fp); f != nil {
			findings = append(findings, *f)
			break
		}
	}

	return findings, nil
}

func (m *Module) checkFingerprint(ctx context.Context, pageURL, host, cname string, fp fingerprint) *modules.Finding {
	// Make HTTP request to the host to check for unclaimed-service response
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		// Try HTTP fallback
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/", nil)
		if err2 != nil {
			return nil
		}
		resp, err = m.client.Do(req2)
		if err != nil {
			return nil
		}
	}
	body, _ := client.ReadBody(resp)

	if !strings.Contains(strings.ToLower(string(body)), strings.ToLower(fp.bodyPattern)) {
		return nil
	}

	return &modules.Finding{
		Module:  "takeover",
		Severity: fp.severity,
		URL:     pageURL,
		Param:   "DNS CNAME",
		Payload: cname,
		Evidence: fmt.Sprintf(
			"Subdomain takeover: %s CNAME→%s — %s fingerprint detected in HTTP response: %q",
			host, cname, fp.service, fp.bodyPattern,
		),
		Detail: fmt.Sprintf(
			"Subdomain takeover vulnerability: %s has a CNAME record pointing to %s (%s), "+
				"but the target resource does not exist or is unclaimed. An attacker can register the cloud resource "+
				"(e.g. create the GitHub Pages repo, S3 bucket, or Heroku app) and serve arbitrary content "+
				"under the legitimate domain — enabling phishing, session cookie theft (if no HttpOnly/Secure), XSS, and credential harvesting.",
			host, cname, fp.service,
		),
		CWE:         "CWE-350",
		CVSS:        takeCVSS(fp.severity),
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
		Confidence:  modules.Confirmed,
		Remediation: "Remove dangling DNS CNAME records immediately; audit all subdomains for orphaned cloud resources; implement CNAME monitoring in CI/CD or DNS change alerts",
		Tags:        []string{"subdomain-takeover", "dns", fp.service, "infrastructure"},
	}
}

func takeCVSS(sev modules.Severity) float64 {
	switch sev {
	case modules.Critical:
		return 9.8
	case modules.High:
		return 8.1
	case modules.Medium:
		return 6.5
	default:
		return 4.3
	}
}
