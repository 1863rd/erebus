package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/erebus/scanner/internal/accessmatrix"
	"github.com/erebus/scanner/internal/browser"
	"github.com/erebus/scanner/internal/chains"
	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/engine"
	"github.com/erebus/scanner/internal/modules"
	"github.com/erebus/scanner/internal/modules/bfla"
	"github.com/erebus/scanner/internal/modules/bypass403"
	"github.com/erebus/scanner/internal/modules/enumeration"
	"github.com/erebus/scanner/internal/modules/paraminer"
	"github.com/erebus/scanner/internal/secondorder"
	"github.com/erebus/scanner/internal/modules/cache"
	"github.com/erebus/scanner/internal/modules/cors"
	"github.com/erebus/scanner/internal/modules/crlf"
	"github.com/erebus/scanner/internal/modules/csrf"
	"github.com/erebus/scanner/internal/modules/cve"
	"github.com/erebus/scanner/internal/modules/deserialization"
	"github.com/erebus/scanner/internal/modules/graphql"
	"github.com/erebus/scanner/internal/modules/headers"
	"github.com/erebus/scanner/internal/modules/hostheader"
	"github.com/erebus/scanner/internal/modules/httpmethods"
	"github.com/erebus/scanner/internal/modules/idor"
	"github.com/erebus/scanner/internal/modules/jwt"
	"github.com/erebus/scanner/internal/modules/lfi"
	"github.com/erebus/scanner/internal/modules/logic"
	"github.com/erebus/scanner/internal/modules/massassign"
	"github.com/erebus/scanner/internal/modules/oauth"
	"github.com/erebus/scanner/internal/modules/openredirect"
	"github.com/erebus/scanner/internal/modules/paths"
	"github.com/erebus/scanner/internal/modules/prototype"
	"github.com/erebus/scanner/internal/modules/race"
	"github.com/erebus/scanner/internal/modules/ratelimit"
	"github.com/erebus/scanner/internal/modules/rce"
	"github.com/erebus/scanner/internal/modules/sensitive"
	"github.com/erebus/scanner/internal/modules/hpp"
	"github.com/erebus/scanner/internal/modules/nosql"
	"github.com/erebus/scanner/internal/modules/smuggling"
	"github.com/erebus/scanner/internal/modules/upload"
	"github.com/erebus/scanner/internal/modules/sqli"
	"github.com/erebus/scanner/internal/modules/ssti"
	"github.com/erebus/scanner/internal/modules/ssrf"
	"github.com/erebus/scanner/internal/modules/takeover"
	"github.com/erebus/scanner/internal/modules/xss"
	"github.com/erebus/scanner/internal/modules/xxe"
	"github.com/erebus/scanner/internal/openapi"
	"github.com/erebus/scanner/internal/report"
	"github.com/erebus/scanner/internal/sessions"
	"github.com/erebus/scanner/internal/storedxss"
	"github.com/erebus/scanner/internal/waf"
)

type headerFlag []string

func (h *headerFlag) String() string     { return strings.Join(*h, ", ") }
func (h *headerFlag) Set(v string) error { *h = append(*h, v); return nil }

func main() {
	var (
		target      = flag.String("target", "", "Target URL (required)")
		output      = flag.String("output", "", "Report file (.json or .html)")
		proxy       = flag.String("proxy", "", "HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
		workers     = flag.Int("workers", 25, "Concurrent workers")
		depth       = flag.Int("depth", 3, "Crawl depth")
		maxURLs     = flag.Int("max-urls", 500, "Maximum pages to crawl")
		timeout     = flag.Duration("timeout", 15*time.Second, "Per-request timeout")
		scanTimeout = flag.Duration("scan-timeout", 0, "Total scan timeout (0 = unlimited)")
		rateFlag    = flag.Float64("rate", 60, "Max requests/second (0 = unlimited)")
		modList     = flag.String("modules",
			"sensitive,headers,cors,paths,cve,httpmethods,sqli,xss,ssti,rce,xxe,lfi,ssrf,openredirect,csrf,idor,jwt,graphql,cache,prototype,deserialization,smuggling,massassign,bfla,ratelimit,crlf,race,oauth,takeover,logic,bypass403,hostheader,nosql,upload,hpp,enumeration,paraminer",
			"Comma-separated module list (use 'all' for every module)")
		noCrawl     = flag.Bool("no-crawl", false, "Scan target URL only, skip crawling")
		noVerify    = flag.Bool("no-verify", false, "Skip TLS certificate verification")
		cookie      = flag.String("cookie", "", "Cookie header (e.g. session=abc123)")
		bearer      = flag.String("bearer", "", "Bearer token for Authorization header")
		auth        = flag.String("auth", "", "HTTP Basic auth credentials (user:password)")
		verbose     = flag.Bool("v", false, "Verbose output (print every crawled URL)")
		sessionFile = flag.String("session-file", "", "Multi-session file for identity comparison")
		headless    = flag.Bool("headless", false, "Enable headless Chrome SPA discovery")
		noChains    = flag.Bool("no-chains", false, "Disable attack chain analysis")
		noOpenAPI   = flag.Bool("no-openapi", false, "Disable OpenAPI/Swagger spec discovery")
		storedXSS   = flag.Bool("stored-xss", false, "Enable stored XSS second-pass detection (adds extra requests)")
		noWAF       = flag.Bool("no-waf", false, "Skip WAF fingerprinting")
		noMatrix    = flag.Bool("no-matrix", false, "Disable access control matrix analysis (multi-session only)")
		deepScan    = flag.Bool("deep", false, "Deep scan: extended payloads, hidden params, second-order injection, user enumeration (slower, more requests)")
	)
	var customHeaders headerFlag
	flag.Var(&customHeaders, "H", "Custom header, repeatable: -H 'X-Custom: value'")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: erebus-scanner [options]\n\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  erebus-scanner -target https://example.com -output report.html
  erebus-scanner -target https://app.com -cookie 'session=abc' -H 'X-Role: admin' -v
  erebus-scanner -target https://api.com -modules sqli,xss,idor,jwt -depth 5
  erebus-scanner -target https://app.com -session-file sessions.txt -output report.html
  erebus-scanner -target https://spa.com -headless -stored-xss -modules xss,sqli,idor
  erebus-scanner -target https://app.com -deep -session-file sessions.txt -output deep.html

Session file format (one per line):
  admin|cookie=sessionid=abc123
  user|bearer=eyJhbGc...
  anonymous

Available modules:
  passive  : sensitive, headers, cors, paths
  active   : cve, httpmethods, sqli, xss, ssti, rce, xxe, lfi, ssrf, openredirect, csrf, idor
  modern   : jwt, graphql, cache, prototype, deserialization, smuggling
  api      : massassign, bfla, ratelimit
  elite    : crlf, race, oauth, takeover, logic, bypass403, hostheader
  deep     : enumeration (user enumeration), paraminer (hidden params)
  phase2   : secondorder (run automatically with -deep, not a per-page module)
`)
	}
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required")
		flag.Usage()
		os.Exit(1)
	}

	targetURL, err := url.Parse(*target)
	if err != nil || targetURL.Host == "" {
		fmt.Fprintf(os.Stderr, "error: invalid target URL: %s\n", *target)
		os.Exit(1)
	}
	if targetURL.Scheme == "" {
		targetURL.Scheme = "https"
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *scanTimeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, *scanTimeout)
		defer timeoutCancel()
	}

	baseOpts := client.Options{
		Timeout:   *timeout,
		RateLimit: *rateFlag,
		Proxy:     *proxy,
		NoVerify:  *noVerify,
		Cookie:    *cookie,
		Bearer:    *bearer,
		BasicAuth: *auth,
		Workers:   *workers,
		Headers:   []string(customHeaders),
	}

	enabled := parseModuleList(*modList)
	rep := report.New(*output, *verbose)
	rep.Banner(targetURL.String())

	if *deepScan {
		if *depth < 6 {
			*depth = 6
		}
		if *maxURLs < 2000 {
			*maxURLs = 2000
		}
		*storedXSS = true
		if *rateFlag > 30 {
			*rateFlag = 30
		}
		fmt.Printf("  \033[1;35m[DEEP]\033[0m Deep scan mode active — extended payloads, second-order injection, hidden parameters\n")
	}

	crawlDepth := *depth
	crawlMaxURLs := *maxURLs
	if *noCrawl {
		crawlDepth = 0
		crawlMaxURLs = 1
	}

	type identity struct {
		name string
		opts client.Options
	}

	var identities []identity

	if *sessionFile != "" {
		sess, err := sessions.Parse(*sessionFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: session file: %v\n", err)
			os.Exit(1)
		}
		for _, s := range sess {
			o := baseOpts
			if s.Cookie != "" {
				o.Cookie = s.Cookie
			}
			if s.Bearer != "" {
				o.Bearer = s.Bearer
				o.Cookie = ""
			}
			if len(s.Headers) > 0 {
				o.Headers = append(append([]string{}, baseOpts.Headers...), s.Headers...)
			}
			identities = append(identities, identity{name: s.Name, opts: o})
		}
	} else {
		identities = []identity{{name: "", opts: baseOpts}}
	}

	var allFindings []modules.Finding
	var allPages []crawler.Page
	var allVisitedURLs []string
	var matrixIdentities []accessmatrix.Identity

	for _, id := range identities {
		if ctx.Err() != nil {
			break
		}

		if id.name != "" {
			fmt.Printf("\n  Scanning as: \033[1;36m%s\033[0m\n", id.name)
		}

		c, err := client.New(id.opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: client init (%s): %v\n", id.name, err)
			continue
		}

		// Keep client for access matrix
		matrixIdentities = append(matrixIdentities, accessmatrix.Identity{
			Name:   id.name,
			Client: c,
			Level:  accessmatrix.InferLevel(id.name),
		})

		// WAF fingerprinting (once per identity)
		var wafResult *waf.Result
		if !*noWAF {
			wafResult = waf.Detect(ctx, c, targetURL.String())
			if wafResult.Kind != waf.Unknown {
				fmt.Printf("  \033[1;33m[WAF]\033[0m %s detected (%s) — bypass payloads active\n",
					wafResult.Kind, wafResult.Confidence)
				if len(wafResult.Evidence) > 0 {
					fmt.Printf("       Evidence: %s\n", wafResult.Evidence[0])
				}
			}
		}

		mods := buildModules(c, enabled, *noVerify)
		if len(mods) == 0 {
			fmt.Fprintln(os.Stderr, "error: no modules enabled")
			os.Exit(1)
		}

		cr := crawler.New(c, targetURL, crawlDepth, crawlMaxURLs, *workers, *verbose)
		eng := engine.New(cr, mods, *workers)
		if wafResult != nil {
			eng.SetWAF(wafResult)
		}

		var extraPages []crawler.Page

		if !*noOpenAPI {
			if specPages, err := openapi.Discover(ctx, c, targetURL.String()); err == nil {
				extraPages = append(extraPages, specPages...)
				if len(specPages) > 0 {
					fmt.Printf("  [openapi] %d synthetic endpoints added\n", len(specPages))
				}
			}
		}

		if *headless {
			fmt.Printf("  [browser] Launching headless Chrome...\n")
			if bPages, err := browser.Discover(ctx, targetURL.String(), *noVerify); err == nil {
				extraPages = append(extraPages, bPages...)
				if len(bPages) > 0 {
					fmt.Printf("  [browser] %d API endpoints discovered\n", len(bPages))
				}
			} else {
				fmt.Fprintf(os.Stderr, "  [browser] warning: %v\n", err)
			}
		}

		scanCtx := ctx
		if *deepScan {
			scanCtx = modules.WithMode(ctx, modules.ModeDeep)
		}

		findings, visited, err := eng.RunWithExtra(scanCtx, extraPages)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: engine (%s): %v\n", id.name, err)
			continue
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			for u := range visited {
				rep.PrintVisited(u)
				allVisitedURLs = append(allVisitedURLs, u)
			}
		}()

		// Add extra page URLs to the matrix URL pool
		for _, p := range extraPages {
			allVisitedURLs = append(allVisitedURLs, p.URL)
		}

		var sessionPages []crawler.Page
		sessionName := id.name
		for f := range findings {
			if sessionName != "" {
				f.Session = sessionName
			}
			rep.PrintFinding(f)
			allFindings = append(allFindings, f)
		}

		<-done

		// Collect pages for stored XSS second pass
		if *storedXSS {
			sessionPages = append(sessionPages, extraPages...)
			for _, u := range allVisitedURLs {
				sessionPages = append(sessionPages, crawler.Page{URL: u})
			}
			allPages = append(allPages, sessionPages...)
		}
	}

	// Stored XSS second-pass
	if *storedXSS && len(allPages) > 0 && ctx.Err() == nil {
		fmt.Printf("\n  \033[1;35m[STORED-XSS]\033[0m Running second-pass stored XSS detection...\n")
		c, err := client.New(baseOpts)
		if err == nil {
			sxssFindings := storedxss.Scan(ctx, c, allPages)
			if len(sxssFindings) > 0 {
				fmt.Printf("  [stored-xss] %d canaries found:\n", len(sxssFindings))
				for _, f := range sxssFindings {
					rep.PrintFinding(f)
					allFindings = append(allFindings, f)
				}
			}
		}
	}

	// Second-order injection deep phase (deep mode only)
	if *deepScan && len(allVisitedURLs) > 0 && ctx.Err() == nil {
		fmt.Printf("\n  \033[1;35m[DEEP:2ND-ORDER]\033[0m Probing for second-order injection (SQLi, SSTI, stored reflection)...\n")
		c2, err := client.New(baseOpts)
		if err == nil {
			soFindings := secondorder.Scan(ctx, c2, allVisitedURLs)
			if len(soFindings) > 0 {
				fmt.Printf("  [2nd-order] %d finding(s):\n", len(soFindings))
				for _, f := range soFindings {
					rep.PrintFinding(f)
					allFindings = append(allFindings, f)
				}
			}
		}
	}

	// Access control matrix — runs only when multiple identities are present
	if !*noMatrix && len(matrixIdentities) >= 2 && len(allVisitedURLs) > 0 && ctx.Err() == nil {
		fmt.Printf("\n  \033[1;35m[MATRIX]\033[0m Building access control matrix across %d identities (%d URLs)...\n",
			len(matrixIdentities), len(allVisitedURLs))
		matrixFindings := accessmatrix.Build(ctx, allVisitedURLs, matrixIdentities, 300)
		if len(matrixFindings) > 0 {
			fmt.Printf("  [matrix] %d access control violation(s) detected:\n", len(matrixFindings))
			for _, f := range matrixFindings {
				rep.PrintFinding(f)
				allFindings = append(allFindings, f)
			}
			fmt.Print(accessmatrix.FormatMatrixTable(matrixFindings))
		} else {
			fmt.Printf("  [matrix] No access control violations detected.\n")
		}
	}

	// Attack chain analysis
	if !*noChains && len(allFindings) > 0 {
		chainFindings := chains.Analyze(allFindings)
		if len(chainFindings) > 0 {
			fmt.Printf("\n  \033[1;35m[CHAINS]\033[0m %d exploit chain(s) detected:\n", len(chainFindings))
			for _, f := range chainFindings {
				rep.PrintFinding(f)
				allFindings = append(allFindings, f)
			}
		}
	}

	rep.Summary(targetURL.String())
}

func parseModuleList(s string) map[string]struct{} {
	if strings.TrimSpace(strings.ToLower(s)) == "all" {
		return map[string]struct{}{
			"sensitive": {}, "headers": {}, "cors": {}, "paths": {},
			"cve": {}, "httpmethods": {}, "sqli": {}, "xss": {}, "ssti": {},
			"rce": {}, "xxe": {}, "lfi": {}, "ssrf": {}, "openredirect": {},
			"csrf": {}, "idor": {}, "jwt": {}, "graphql": {},
			"cache": {}, "prototype": {}, "deserialization": {}, "smuggling": {},
			"massassign": {}, "bfla": {}, "ratelimit": {},
			"crlf": {}, "race": {}, "oauth": {}, "takeover": {}, "logic": {},
			"bypass403": {}, "hostheader": {}, "nosql": {}, "upload": {}, "hpp": {},
			"enumeration": {}, "paraminer": {},
		}
	}
	m := make(map[string]struct{})
	for _, name := range strings.Split(s, ",") {
		name = strings.TrimSpace(strings.ToLower(name))
		if name != "" {
			m[name] = struct{}{}
		}
	}
	return m
}

func buildModules(c *client.Client, enabled map[string]struct{}, noVerify bool) []modules.Module {
	var mods []modules.Module
	add := func(m modules.Module) {
		if _, ok := enabled[m.Name()]; ok {
			mods = append(mods, m)
		}
	}

	// Passive / fingerprinting
	add(sensitive.New())
	add(headers.New(c))
	add(cors.New(c))
	add(paths.New(c))

	// Classic active
	add(cve.New(c))
	add(httpmethods.New(c))
	add(sqli.New(c))
	add(xss.New(c))
	add(ssti.New(c))
	add(rce.New(c))
	add(xxe.New(c))
	add(lfi.New(c))
	add(ssrf.New(c))
	add(openredirect.New(noVerify))
	add(csrf.New(c))
	add(idor.New(c))

	// Modern / token / API
	add(jwt.New(c))
	add(graphql.New(c))

	// Advanced / infrastructure
	add(cache.New(c))
	add(prototype.New(c))
	add(deserialization.New(c))
	add(smuggling.New(noVerify))

	// API-specific
	add(massassign.New(c))
	add(bfla.New(c))
	add(ratelimit.New(c))

	// Elite / advanced
	add(crlf.New(c))
	add(race.New(c))
	add(oauth.New(c))
	add(takeover.New(c))
	add(logic.New(c))
	add(bypass403.New(c))
	add(hostheader.New(c))
	add(nosql.New(c))
	add(upload.New(c))
	add(hpp.New(c))
	add(enumeration.New(c))
	add(paraminer.New(c))

	return mods
}
