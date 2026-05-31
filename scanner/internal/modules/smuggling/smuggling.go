package smuggling

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

// Module detects HTTP request smuggling (CL.TE, TE.CL, TE.TE) using raw TCP
// connections and timing probes. Go's http.Client normalizes these headers, so
// raw TCP is required to send the conflicting framing that triggers desync.
type Module struct {
	seenHosts sync.Map
	noVerify  bool
}

func New(noVerify bool) *Module { return &Module{noVerify: noVerify} }
func (m *Module) Name() string  { return "smuggling" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	u, err := url.Parse(page.URL)
	if err != nil {
		return nil, nil
	}
	host := u.Scheme + "://" + u.Host
	if _, loaded := m.seenHosts.LoadOrStore(host, struct{}{}); loaded {
		return nil, nil
	}

	baseRTT := m.baseline(ctx, u)
	if baseRTT == 0 {
		return nil, nil
	}

	var findings []modules.Finding
	for _, probe := range m.buildProbes(u, baseRTT) {
		if ctx.Err() != nil {
			break
		}
		rtt, respBody := m.rawProbe(ctx, u, probe.raw, 12*time.Second)
		if probe.timing && rtt > baseRTT+5*time.Second {
			findings = append(findings, modules.Finding{
				Module:      "smuggling",
				Severity:    modules.High,
				URL:         host,
				Param:       "HTTP framing",
				Payload:     displayReq(probe.raw),
				Evidence:    fmt.Sprintf("%s timing desync: probe=%v baseline=%v", probe.name, rtt.Round(time.Millisecond), baseRTT.Round(time.Millisecond)),
				Detail:      probe.detail,
				CWE:         "CWE-444",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				Confidence:  modules.Likely,
				Remediation: "Normalize Transfer-Encoding headers at the reverse proxy layer; reject ambiguous framing; use HTTP/2 end-to-end",
				Tags:        []string{"smuggling", probe.tag, "request-desync"},
			})
		} else if probe.marker != "" && strings.Contains(respBody, probe.marker) {
			findings = append(findings, modules.Finding{
				Module:      "smuggling",
				Severity:    modules.Critical,
				URL:         host,
				Param:       "HTTP framing",
				Payload:     displayReq(probe.raw),
				Evidence:    fmt.Sprintf("%s confirmed: smuggled prefix reflected in response body", probe.name),
				Detail:      probe.detail,
				CWE:         "CWE-444",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Normalize Transfer-Encoding headers at the reverse proxy layer; reject ambiguous framing",
				Tags:        []string{"smuggling", probe.tag, "request-desync", "confirmed"},
			})
		}
	}
	return findings, nil
}

type probe struct {
	name   string
	tag    string
	detail string
	raw    string
	timing bool
	marker string
}

func (m *Module) buildProbes(u *url.URL, baseRTT time.Duration) []probe {
	host := u.Host
	path := u.Path
	if path == "" {
		path = "/"
	}

	// CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding.
	// Body: 8-byte chunked payload that starts a chunk but has no terminator.
	// CL=8 is correct (front-end reads all 8 bytes, forwards a "complete" request).
	// Back-end reads TE chunked: processes 3-byte chunk, then stalls waiting for next chunk.
	clteBody := "3\r\nabc\r\n" // 8 bytes, one chunk, no terminator 0\r\n\r\n
	clteReq := "POST " + path + "?_smug HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(clteBody)) + "\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Connection: close\r\n\r\n" +
		clteBody

	// TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length.
	// CL is larger than the actual forwarded body → back-end stalls waiting for more bytes.
	teclBody := "3\r\nabc\r\n0\r\n\r\n" // 15 bytes (complete chunked body)
	teclReq := "POST " + path + "?_smug HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Length: 50\r\n" + // larger than actual 15-byte body → backend stalls
		"Transfer-Encoding: chunked\r\n" +
		"Connection: close\r\n\r\n" +
		teclBody

	// TE.TE obfuscation: send two Transfer-Encoding headers — one standard, one obfuscated.
	// If front-end picks the first (standard) and back-end picks the second (obfuscated,
	// and ignores it, falling back to CL), the same desync as TE.CL occurs.
	teteBody := "3\r\nabc\r\n0\r\n\r\n"
	teteReq := "POST " + path + "?_smug HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Length: 50\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Transfer-Encoding: identity\r\n" + // second obfuscated TE header
		"Connection: close\r\n\r\n" +
		teteBody

	return []probe{
		{
			name:   "CL.TE",
			tag:    "cl-te",
			detail: "CL.TE desync: front-end uses Content-Length, back-end uses Transfer-Encoding — back-end stalls waiting for incomplete chunk terminator",
			raw:    clteReq,
			timing: true,
		},
		{
			name:   "TE.CL",
			tag:    "te-cl",
			detail: "TE.CL desync: front-end uses Transfer-Encoding, back-end uses Content-Length — back-end stalls because CL exceeds forwarded body",
			raw:    teclReq,
			timing: true,
		},
		{
			name:   "TE.TE",
			tag:    "te-te",
			detail: "TE.TE desync: duplicate Transfer-Encoding headers — one end normalizes the obfuscated header while the other ignores it",
			raw:    teteReq,
			timing: true,
		},
	}
}

func (m *Module) baseline(ctx context.Context, u *url.URL) time.Duration {
	path := u.Path
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nConnection: close\r\n\r\n"

	var total time.Duration
	n := 0
	for i := 0; i < 3; i++ {
		if ctx.Err() != nil {
			break
		}
		rtt, _ := m.rawProbe(ctx, u, req, 8*time.Second)
		if rtt > 0 {
			total += rtt
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return total / time.Duration(n)
}

func (m *Module) rawProbe(ctx context.Context, u *url.URL, rawReq string, timeout time.Duration) (time.Duration, string) {
	conn, err := m.dial(u)
	if err != nil {
		return 0, ""
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	start := time.Now()
	if _, err := io.WriteString(conn, rawReq); err != nil {
		return 0, ""
	}

	buf := make([]byte, 8192)
	n, _ := io.ReadAtLeast(conn, buf, 12) // read at least HTTP/1.1 xxx
	return time.Since(start), string(buf[:n])
}

func (m *Module) dial(u *url.URL) (net.Conn, error) {
	addr := u.Host
	if !strings.Contains(addr, ":") {
		if u.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}
	if u.Scheme == "https" {
		d := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 6 * time.Second},
			Config: &tls.Config{
				InsecureSkipVerify: m.noVerify,
				ServerName:         u.Hostname(),
			},
		}
		return d.Dial("tcp", addr)
	}
	return net.DialTimeout("tcp", addr, 6*time.Second)
}

func displayReq(raw string) string {
	s := strings.ReplaceAll(raw, "\r\n", " ↵ ")
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}
