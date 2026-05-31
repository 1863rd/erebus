"""Security Misconfiguration: headers, cookies, CORS, CSP bypass, anti-automation, components."""
import re
import json
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.vuln_types import VT

logger = logging.getLogger(__name__)

class MisconfigFinding:
    _CATEGORY_MAP = (
        ("Missing Security Header (Content-Security-Policy",  VT.CSP_MISCONFIG),
        ("Missing Security Header (X-Frame-Options",          VT.CLICKJACKING),
        ("Missing Security Header",                           VT.MISSING_SECURITY_HEADER),
        ("Information Disclosure via Header",                 VT.INFO_DISCLOSURE),
        ("CORS Misconfiguration (Arbitrary",                  VT.CORS_CREDENTIALED),
        ("CORS Misconfiguration (Wildcard",                   VT.CORS_WILDCARD),
        ("CORS",                                              VT.CORS_WILDCARD),
        ("CSP",                                               VT.CSP_MISCONFIG),
        ("Insecure Cookie",                                   VT.INSECURE_COOKIE),
        ("Missing Rate Limiting",                             VT.RATE_LIMITING),
        ("Vulnerable Component",                              VT.VULNERABLE_COMPONENT),
        ("Component Version",                                 VT.COMPONENT_VERSION_DISC),
        ("Dangerous HTTP Method",                             VT.DANGEROUS_HTTP_METHOD),
        ("HTTP TRACE",                                        VT.HTTP_TRACE),
        ("Clickjacking",                                      VT.CLICKJACKING),
        ("Security Misconfiguration",                         VT.SECURITY_MISCONFIG),
    )

    def __init__(self, vuln_type, url, parameter, payload, evidence,
                 severity="Medium", confidence=0.90, exploitable=False):
        self.vuln_type = vuln_type
        self.url = url
        self.parameter = parameter
        self.payload = payload
        self.evidence = evidence
        self.severity = severity
        self.confidence = confidence
        self.exploitable = exploitable
        self.category = next((c for p, c in self._CATEGORY_MAP if vuln_type.startswith(p)), "")

    def to_dict(self):
        return {
            "type": self.vuln_type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
            "confidence": self.confidence,
            "exploitable": self.exploitable,
            "category": self.category,
        }


class SecurityMisconfigModule:
    _SEC_HEADERS = {
        "Content-Security-Policy":       ("High",   "CSP prevents XSS and data injection attacks"),
        "Strict-Transport-Security":     ("High",   "HSTS enforces HTTPS"),
        "X-Frame-Options":               ("Medium", "Clickjacking protection"),
        "X-Content-Type-Options":        ("Low",    "MIME-type sniffing prevention"),
        "X-XSS-Protection":              ("Low",    "Legacy XSS filter"),
        "Referrer-Policy":               ("Low",    "Referrer information leakage control"),
        "Permissions-Policy":            ("Low",    "Feature policy enforcement"),
        "Cross-Origin-Opener-Policy":    ("Low",    "Cross-origin window isolation"),
        "Cross-Origin-Resource-Policy":  ("Low",    "Cross-origin resource sharing control"),
    }
    _DANGEROUS_HEADERS = {
        "X-Powered-By":    "Technology disclosure",
        "Server":          "Server version disclosure",
        "X-AspNet-Version": "ASP.NET version disclosure",
        "X-AspNetMvc-Version": "ASP.NET MVC version disclosure",
        "X-Generator":     "CMS generator disclosure",
    }
    _COOKIE_FLAGS = {
        "HttpOnly": "Cookie not protected from JavaScript access (XSS session hijack risk)",
        "Secure":   "Cookie transmitted over HTTP (credential interception risk)",
        "SameSite": "Cookie not protected against CSRF",
    }
    _VERBOSE_COMPONENT_VERSIONS = [
        re.compile(r'express[/\s]+([\d.]+)', re.I),
        re.compile(r'node\.?js[/\s]+([\d.]+)', re.I),
        re.compile(r'nginx[/\s]+([\d.]+)', re.I),
        re.compile(r'apache[/\s]+([\d.]+)', re.I),
        re.compile(r'php[/\s]+([\d.]+)', re.I),
        re.compile(r'"version"\s*:\s*"([\d.]+)"'),
    ]
    _KNOWN_VULN_PACKAGES = {
        "angular": {"<1.6.0": "Multiple XSS bypasses", "<1.8.0": "CSP bypass"},
        "lodash":  {"<4.17.21": "Prototype pollution", "<4.17.19": "ReDoS"},
        "jquery":  {"<3.5.0": "XSS via HTML parsing", "<1.9.0": "Multiple XSS"},
        "moment":  {"<2.29.4": "ReDoS vulnerability"},
        "express": {"<4.17.3": "Known CVEs"},
        "sequelize": {"<6.19.0": "SQL injection in ORDER BY"},
    }
    _RATE_LIMIT_ENDPOINTS = [
        "/rest/user/login",
        "/api/Users",
        "/rest/products/search",
    ]

    def __init__(self, http_engine, evasion_engine=None):
        self.http = http_engine
        self._seen: set = set()

    def scan(self, url: str) -> List[MisconfigFinding]:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._seen:
            return []
        self._seen.add(origin)

        results: List[MisconfigFinding] = []
        results.extend(self._check_security_headers(origin))
        results.extend(self._check_cors(origin))
        results.extend(self._check_cookies(origin))
        results.extend(self._check_csp_bypass(origin))
        results.extend(self._check_rate_limiting(origin))
        results.extend(self._check_components(origin))
        results.extend(self._check_http_methods(origin))
        results.extend(self._check_clickjacking(origin))
        results.extend(self._check_debug_endpoints(origin))
        return results

    def _check_security_headers(self, origin: str) -> List[MisconfigFinding]:
        results: List[MisconfigFinding] = []
        try:
            resp = self.http.get(origin)
            if not resp:
                return results
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for header, (severity, reason) in self._SEC_HEADERS.items():
                if header.lower() not in resp_headers_lower:
                    results.append(MisconfigFinding(
                        vuln_type=f"Missing Security Header ({header})",
                        url=origin,
                        parameter=header,
                        payload="-",
                        evidence=f"Header absent — {reason}",
                        severity=severity,
                        confidence=1.0,
                        exploitable=False,
                    ))

            for header, reason in self._DANGEROUS_HEADERS.items():
                if header.lower() in resp_headers_lower:
                    val = resp_headers_lower[header.lower()]
                    results.append(MisconfigFinding(
                        vuln_type=f"Information Disclosure via Header ({header})",
                        url=origin,
                        parameter=header,
                        payload="-",
                        evidence=f"{header}: {val} — {reason}",
                        severity="Low",
                        confidence=1.0,
                        exploitable=False,
                    ))
        except Exception:
            pass
        return results

    def _check_cors(self, origin: str) -> List[MisconfigFinding]:
        results: List[MisconfigFinding] = []
        canary = "https://evil.attackdomain.internal"
        rest_endpoints = [
            "/rest/products/search",
            "/api/Users",
            "/rest/user/whoami",
        ]
        for path in rest_endpoints:
            try:
                resp = self.http.get(f"{origin}{path}",
                                      headers={"Origin": canary})
                if not resp:
                    continue
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                acam = resp.headers.get("Access-Control-Allow-Methods", "")

                if acao == "*":
                    results.append(MisconfigFinding(
                        vuln_type="CORS Misconfiguration (Wildcard Origin)",
                        url=f"{origin}{path}",
                        parameter="Origin",
                        payload=f"Origin: {canary}",
                        evidence=f"ACAO: * — Any domain can read this API",
                        severity="High",
                        confidence=0.97,
                        exploitable=True,
                    ))
                elif canary in acao:
                    creds = acac.lower() == "true"
                    results.append(MisconfigFinding(
                        vuln_type="CORS Misconfiguration (Arbitrary Origin Reflected with Credentials)" if creds
                                  else "CORS Misconfiguration (Arbitrary Origin Reflected)",
                        url=f"{origin}{path}",
                        parameter="Origin",
                        payload=f"Origin: {canary}",
                        evidence=f"ACAO={acao!r} ACAC={acac!r} ACAM={acam!r}",
                        severity="Critical" if creds else "High",
                        confidence=0.97,
                        exploitable=True,
                    ))
                    break
            except Exception:
                pass
        return results

    def _check_cookies(self, origin: str) -> List[MisconfigFinding]:
        results: List[MisconfigFinding] = []
        try:
            # Try to get a session cookie
            resp = self.http.post(
                f"{origin}/rest/user/login",
                data='{"email":"' + "' OR 1=1--" + '","password":"x"}',
                headers={"Content-Type": "application/json"},
            )
            if not resp:
                return results
            for cookie in resp.cookies:
                flags_text = str(resp.headers.get("Set-Cookie", ""))
                for flag, reason in self._COOKIE_FLAGS.items():
                    if flag.lower() not in flags_text.lower():
                        results.append(MisconfigFinding(
                            vuln_type=f"Insecure Cookie (Missing {flag} Flag)",
                            url=f"{origin}/rest/user/login",
                            parameter="Set-Cookie",
                            payload="-",
                            evidence=f"Cookie {cookie.name!r} missing {flag} → {reason}",
                            severity="Medium",
                            confidence=0.95,
                            exploitable=False,
                        ))
        except Exception:
            pass
        return results

    def _check_csp_bypass(self, origin: str) -> List[MisconfigFinding]:
        results: List[MisconfigFinding] = []
        try:
            resp = self.http.get(origin)
            if not resp:
                return results
            csp = resp.headers.get("Content-Security-Policy", "")
            if not csp:
                return results

            weaknesses = []
            if "unsafe-inline" in csp:
                weaknesses.append("'unsafe-inline' allows inline script execution (XSS bypass)")
            if "unsafe-eval" in csp:
                weaknesses.append("'unsafe-eval' allows eval() (XSS bypass)")
            if re.search(r"script-src[^;]*\*", csp):
                weaknesses.append("Wildcard in script-src allows any domain")
            if "data:" in csp:
                weaknesses.append("data: URI in CSP allows XSS via data: payloads")
            if re.search(r"https?://[^;]*cdn[^;]*", csp, re.I):
                weaknesses.append("CDN in CSP may be bypassable via user-controlled CDN content")
            if not re.search(r"default-src|script-src", csp):
                weaknesses.append("No script-src/default-src fallback")

            for w in weaknesses:
                results.append(MisconfigFinding(
                    vuln_type="CSP Misconfiguration (Bypassable Policy)",
                    url=origin,
                    parameter="Content-Security-Policy",
                    payload=csp[:120],
                    evidence=w,
                    severity="Medium",
                    confidence=0.90,
                    exploitable=True,
                ))
        except Exception:
            pass
        return results

    def _check_rate_limiting(self, origin: str) -> List[MisconfigFinding]:
        results: List[MisconfigFinding] = []
        for path in self._RATE_LIMIT_ENDPOINTS:
            try:
                url = f"{origin}{path}"
                # Send 15 rapid requests
                responses = []
                for _ in range(15):
                    r = self.http.post(url, data='{"email":"x","password":"x"}',
                                       headers={"Content-Type": "application/json"}) if "login" in path \
                        else self.http.get(url)
                    if r:
                        responses.append(r.status_code)

                # If no 429 and all succeeded, no rate limiting
                if responses and 429 not in responses and len(responses) >= 10:
                    all_ok = all(s in (200, 400, 401) for s in responses)
                    if all_ok:
                        results.append(MisconfigFinding(
                            vuln_type="Missing Rate Limiting / Broken Anti-Automation",
                            url=url,
                            parameter="-",
                            payload=f"15 rapid requests → {responses[:5]}...",
                            evidence=f"No 429 throttling after 15 requests to {path}",
                            severity="Medium",
                            confidence=0.88,
                            exploitable=True,
                        ))
                        break
            except Exception:
                pass
        return results

    def _check_components(self, origin: str) -> List[MisconfigFinding]:
        results: List[MisconfigFinding] = []
        try:
            resp = self.http.get(f"{origin}/package.json")
            if resp and resp.status_code == 200:
                try:
                    pkg = resp.json()
                    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                    for pkg_name, known_vulns in self._KNOWN_VULN_PACKAGES.items():
                        if pkg_name in deps:
                            installed_ver = deps[pkg_name].lstrip("^~>=")
                            for vuln_ver, vuln_desc in known_vulns.items():
                                try:
                                    inst = tuple(int(x) for x in installed_ver.split(".")[:3])
                                    threshold = tuple(int(x) for x in vuln_ver.lstrip("<>= ").split(".")[:3])
                                    if "<" in vuln_ver and inst < threshold:
                                        results.append(MisconfigFinding(
                                            vuln_type=f"Vulnerable Component ({pkg_name}@{installed_ver})",
                                            url=f"{origin}/package.json",
                                            parameter=pkg_name,
                                            payload=f"{pkg_name}@{installed_ver}",
                                            evidence=f"Version {installed_ver} {vuln_ver}: {vuln_desc}",
                                            severity="High",
                                            confidence=0.85,
                                            exploitable=False,
                                        ))
                                except Exception:
                                    pass
                except Exception:
                    pass
        except Exception:
            pass

        # Also check server header for known vulnerable versions
        try:
            resp = self.http.get(origin)
            if resp:
                server = resp.headers.get("Server", "") + resp.headers.get("X-Powered-By", "")
                for pattern in self._VERBOSE_COMPONENT_VERSIONS:
                    m = pattern.search(server + (resp.text[:1000] if resp.text else ""))
                    if m:
                        results.append(MisconfigFinding(
                            vuln_type="Component Version Disclosure",
                            url=origin,
                            parameter="Server/X-Powered-By",
                            payload="-",
                            evidence=f"Version disclosed: {m.group(0)}",
                            severity="Low",
                            confidence=0.90,
                            exploitable=False,
                        ))
        except Exception:
            pass

        return results

    def _check_http_methods(self, origin: str) -> List[MisconfigFinding]:
        results: List[MisconfigFinding] = []
        dangerous_methods = ["TRACE", "TRACK", "DELETE", "PUT", "PATCH"]
        try:
            resp = self.http.options(origin)
            if resp:
                allow = resp.headers.get("Allow", "") + resp.headers.get("Access-Control-Allow-Methods", "")
                enabled = [m for m in dangerous_methods if m in allow.upper()]
                if enabled:
                    results.append(MisconfigFinding(
                        vuln_type="Dangerous HTTP Methods Enabled",
                        url=origin,
                        parameter="Allow",
                        payload="OPTIONS /",
                        evidence=f"Dangerous methods allowed: {', '.join(enabled)}",
                        severity="Medium",
                        confidence=0.88,
                        exploitable=False,
                    ))
        except Exception:
            pass

        try:
            resp = self.http.request("TRACE", origin)
            if resp and resp.status_code == 200 and "TRACE" in resp.text.upper():
                results.append(MisconfigFinding(
                    vuln_type="HTTP TRACE Method Enabled (Cross-Site Tracing)",
                    url=origin,
                    parameter="-",
                    payload="TRACE /",
                    evidence=f"TRACE reflected request → {resp.text[:150]}",
                    severity="Low",
                    confidence=0.95,
                    exploitable=False,
                ))
        except Exception:
            pass
        return results

    def _check_clickjacking(self, origin: str) -> List[MisconfigFinding]:
        results: List[MisconfigFinding] = []
        try:
            resp = self.http.get(origin)
            if not resp:
                return results
            xfo = resp.headers.get("X-Frame-Options", "")
            csp = resp.headers.get("Content-Security-Policy", "")
            has_frame_ancestors = "frame-ancestors" in csp.lower()
            if not xfo and not has_frame_ancestors:
                results.append(MisconfigFinding(
                    vuln_type="Clickjacking Vulnerability (Missing X-Frame-Options / CSP frame-ancestors)",
                    url=origin,
                    parameter="X-Frame-Options",
                    payload="<iframe src='TARGET'>",
                    evidence="Neither X-Frame-Options nor CSP frame-ancestors present — page can be embedded",
                    severity="Medium",
                    confidence=0.95,
                    exploitable=True,
                ))
        except Exception:
            pass
        return results

    _DBG_PROMETHEUS = re.compile(r'^#\s*(HELP|TYPE)\s+\w+', re.M)
    _DBG_SPRING_LINKS = re.compile(r'"_links"\s*:\s*\{', re.I)
    _DBG_SPRING_ENV = re.compile(r'"(activeProfiles|propertySources)"\s*:', re.I)
    _DBG_TRACE = re.compile(r'"traceId"\s*:', re.I)
    _DBG_LOG = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}.*?(INFO|DEBUG|WARN|ERROR)', re.I)
    _DBG_STACK = re.compile(r'(at Object\.<anonymous>|at Module\._|node_modules|Traceback \(most recent)', re.I)
    _DBG_CONSOLE = re.compile(r'(H2 Console|Web Console|>REPL<|<form[^>]*action[^>]*(login|h2-console))', re.I)
    _DBG_API = re.compile(r'"(swagger|openapi|paths|basePath)"\s*:', re.I)

    # (path, description, confirm_fn_or_None, confidence)
    # confirm_fn receives (text, content_type) → bool; None means heapdump binary check
    _DEBUG_ENDPOINTS = [
        ("/metrics",           "Prometheus Metrics",       lambda t, ct: bool(SecurityMisconfigModule._DBG_PROMETHEUS.search(t)),  0.92),
        ("/actuator",          "Spring Actuator Root",     lambda t, ct: bool(SecurityMisconfigModule._DBG_SPRING_LINKS.search(t)), 0.92),
        ("/actuator/env",      "Spring Actuator Env",      lambda t, ct: bool(SecurityMisconfigModule._DBG_SPRING_ENV.search(t)),   0.94),
        ("/actuator/heapdump", "Spring JVM Heap Dump",     None,                                                                     0.96),
        ("/debug",             "Debug Page",               lambda t, ct: bool(SecurityMisconfigModule._DBG_STACK.search(t)),        0.82),
        ("/trace",             "Distributed Trace",        lambda t, ct: bool(SecurityMisconfigModule._DBG_TRACE.search(t)),        0.88),
        ("/console",           "Admin Console",            lambda t, ct: bool(SecurityMisconfigModule._DBG_CONSOLE.search(t)),      0.90),
        ("/__debug__",         "Django Debug Page",        lambda t, ct: bool(SecurityMisconfigModule._DBG_STACK.search(t)),        0.88),
        ("/support/logs",      "Application Log Exposure", lambda t, ct: bool(SecurityMisconfigModule._DBG_LOG.search(t)),          0.88),
        ("/b2b/v2/",           "B2B API Endpoint",         lambda t, ct: bool(SecurityMisconfigModule._DBG_API.search(t)),          0.80),
    ]

    def _check_debug_endpoints(self, origin: str) -> List[MisconfigFinding]:
        results: List[MisconfigFinding] = []
        for path, desc, confirm_fn, confidence in self._DEBUG_ENDPOINTS:
            try:
                resp = self.http.get(f"{origin}{path}")
                if not resp or resp.status_code != 200:
                    continue
                ct = (resp.headers.get("Content-Type") or "").lower()
                text = resp.text

                if confirm_fn is None:
                    confirmed = "octet-stream" in ct
                else:
                    confirmed = confirm_fn(text, ct)

                if not confirmed:
                    continue

                size = len(resp.content) if hasattr(resp, "content") else len(text.encode())
                excerpt = text[:200].replace("\n", " ")
                results.append(MisconfigFinding(
                    vuln_type=f"Security Misconfiguration ({desc} Exposed)",
                    url=f"{origin}{path}",
                    parameter="-",
                    payload=f"GET {path}",
                    evidence=f"HTTP 200 | {ct or 'unknown'} | {size}B → {excerpt}",
                    severity="Medium",
                    confidence=confidence,
                    exploitable=False,
                ))
            except Exception:
                pass
        return results
