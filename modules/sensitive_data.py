"""Sensitive Data Exposure: FTP dirs, backups, API keys, password hashes, crypto issues."""
import re
import json
import hashlib
import logging
from typing import List, Optional
from urllib.parse import urlparse

from core.vuln_types import VT

logger = logging.getLogger(__name__)


class SensitiveFinding:
    _CATEGORY_MAP = (
        ("Sensitive File Exposure",             VT.SENSITIVE_FILE),
        ("Cryptographic Key Exposure",          VT.CRYPTO_KEY_EXPOSURE),
        ("Password Hash Leak",                  VT.PASSWORD_HASH_LEAK),
        ("Sensitive Data in API",               VT.SENSITIVE_DATA_API),
        ("Sensitive Data in JavaScript",        VT.SENSITIVE_DATA_JS),
        ("Leaked API Key",                      VT.LEAKED_API_KEY),
        ("Cryptographic Issue (Weak",           VT.CRYPTO_ISSUE_WEAK_HASH),
        ("Cryptographic Issue",                 VT.CRYPTO_ISSUE),
        ("Information Disclosure",              VT.INFO_DISCLOSURE_STACK),
    )

    def __init__(self, vuln_type, url, parameter, payload, evidence,
                 severity="High", confidence=0.90, exploitable=True):
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


class SensitiveDataModule:
    _FTP_FILES = [
        ("/ftp/",                         "FTP Directory Listing"),
        ("/ftp/acquisitions.md",          "Confidential Acquisition Document"),
        ("/ftp/coupons_2013.md",          "Historical Coupon Codes"),
        ("/ftp/eastere.gg",               "Hidden Easter Egg File"),
        ("/ftp/incident-support.kdbx",    "KeePass Database (Credentials Store)"),
        ("/ftp/legal.md",                 "Legal Document"),
        ("/ftp/package.json.bak",         "Developer Backup (package.json)"),
        ("/ftp/suspicious_errors.yml",    "Error Log with Sensitive Data"),
        ("/ftp/quarantine/",              "Quarantine Directory Listing"),
        ("/ftp/coupons_2013.md.bak",      "Backup File"),
    ]
    _BACKUP_FILES = [
        ("/package.json",                 "Package Manifest (tech fingerprint)"),
        ("/package-lock.json",            "Package Lock (exact versions)"),
        ("/.env",                         "Environment Variables"),
        ("/.env.local",                   "Local Environment Variables"),
        ("/.env.production",              "Production Secrets"),
        ("/config.json",                  "Configuration File"),
        ("/config/database.yml",          "Database Configuration"),
        ("/application.yml",              "Application Configuration"),
        ("/wp-config.php",                "WordPress Database Credentials"),
        ("/backup.sql",                   "Database Dump"),
        ("/dump.sql",                     "Database Dump"),
        ("/database.sql",                 "Database Dump"),
        ("/.git/config",                  "Git Repository Config"),
        ("/.git/HEAD",                    "Git HEAD Reference"),
        ("/.git/logs/HEAD",               "Git Commit History"),
        ("/.gitignore",                   "Git Ignore (Path Disclosure)"),
        ("/phpinfo.php",                  "PHP Info Page"),
        ("/info.php",                     "PHP Info Page"),
        ("/server-status",                "Apache Server Status"),
        ("/server-info",                  "Apache Server Info"),
        ("/web.config",                   "IIS Configuration"),
        ("/.htaccess",                    "Apache Access Rules"),
        ("/crossdomain.xml",              "Flash Cross-Domain Policy"),
        ("/clientaccesspolicy.xml",       "Silverlight Policy"),
        ("/swagger.json",                 "API Specification"),
        ("/openapi.json",                 "OpenAPI Specification"),
        ("/api-docs",                     "Swagger UI (API Docs)"),
    ]
    _ENCRYPTION_PATHS = [
        ("/encryptionkeys/",              "Encryption Keys Directory"),
        ("/encryptionkeys/jwt.pub",       "JWT Public Key Exposed"),
        ("/encryptionkeys/premium.key",   "Premium Encryption Key"),
    ]
    _HASH_PATTERNS = [
        (re.compile(r'\b[0-9a-f]{32}\b', re.I),   "MD5",    "Weak hash (MD5)"),
        (re.compile(r'\b[0-9a-f]{40}\b', re.I),   "SHA1",   "Weak hash (SHA1)"),
        (re.compile(r'\b[0-9a-f]{64}\b', re.I),   "SHA256", "Cryptographic hash (SHA256)"),
        (re.compile(r'\$2[aby]\$\d+\$', re.I),    "bcrypt", "bcrypt hash"),
    ]
    _API_KEY_PATTERNS = [
        re.compile(r'"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)"\s*:\s*"([^"]{8,})"', re.I),
        re.compile(r'(?:api[_-]?key|apikey)\s*=\s*["\']([^"\']{8,})["\']', re.I),
        re.compile(r'Bearer\s+([A-Za-z0-9\-_]{20,})', re.I),
    ]
    _JS_SENSITIVE_PATTERNS = [
        (re.compile(r'(?:password|passwd|secret|api_?key|token|credential)\s*[=:]\s*["\']([^"\']{4,})["\']', re.I), "Hardcoded Secret in JavaScript"),
        (re.compile(r'(?:mongodb|mysql|postgres|redis)://[^\s"\']{5,}', re.I), "Database Connection String in JavaScript"),
        (re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', re.I), "Private Key in JavaScript"),
    ]

    def __init__(self, http_engine, evasion_engine=None):
        self.http = http_engine
        self._seen: set = set()

    def scan(self, url: str) -> List[SensitiveFinding]:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._seen:
            return []
        self._seen.add(origin)

        results: List[SensitiveFinding] = []
        results.extend(self._check_ftp(origin))
        results.extend(self._check_backups(origin))
        results.extend(self._check_encryption_keys(origin))
        results.extend(self._check_api_user_data(origin))
        results.extend(self._check_js_secrets(origin))
        results.extend(self._check_crypto_weaknesses(origin))
        results.extend(self._check_error_disclosure(origin))
        return results

    def _check_ftp(self, origin: str) -> List[SensitiveFinding]:
        results: List[SensitiveFinding] = []
        for path, desc in self._FTP_FILES:
            try:
                resp = self.http.get(f"{origin}{path}")
                if not resp or resp.status_code not in (200, 206):
                    continue
                body = resp.text
                if len(body) < 3:
                    continue
                # FTP directory listing detection
                if path.endswith("/"):
                    if "<a href" in body.lower() or "index of" in body.lower() or ".md" in body:
                        results.append(SensitiveFinding(
                            vuln_type=f"Sensitive File Exposure ({desc})",
                            url=f"{origin}{path}",
                            parameter="-",
                            payload=f"GET {path}",
                            evidence=f"Directory listing accessible → {body[:200]}",
                            severity="High",
                            confidence=0.93,
                        ))
                else:
                    results.append(SensitiveFinding(
                        vuln_type=f"Sensitive File Exposure ({desc})",
                        url=f"{origin}{path}",
                        parameter="-",
                        payload=f"GET {path}",
                        evidence=f"File accessible ({len(body)} bytes) → {body[:200]}",
                        severity="High",
                        confidence=0.95,
                    ))
            except Exception:
                pass
        return results

    def _check_backups(self, origin: str) -> List[SensitiveFinding]:
        results: List[SensitiveFinding] = []
        _SENSITIVE_KW = [
            "password", "passwd", "secret", "api_key", "apikey", "token",
            "database", "db_host", "db_user", "mysql", "postgres",
            "[core]", "repositoryformat", "<?php", "phpinfo",
            "dependencies", "devdependencies", "scripts",
            "private", "BEGIN RSA", "BEGIN EC",
        ]
        for path, desc in self._BACKUP_FILES:
            try:
                resp = self.http.get(f"{origin}{path}")
                if not resp or resp.status_code != 200 or len(resp.text) < 5:
                    continue
                text_low = resp.text.lower()
                if any(kw.lower() in text_low for kw in _SENSITIVE_KW):
                    results.append(SensitiveFinding(
                        vuln_type=f"Sensitive File Exposure ({desc})",
                        url=f"{origin}{path}",
                        parameter="-",
                        payload=f"GET {path}",
                        evidence=f"Sensitive file accessible → {resp.text[:200]}",
                        severity="High",
                        confidence=0.90,
                    ))
            except Exception:
                pass
        return results

    def _check_encryption_keys(self, origin: str) -> List[SensitiveFinding]:
        results: List[SensitiveFinding] = []
        for path, desc in self._ENCRYPTION_PATHS:
            try:
                resp = self.http.get(f"{origin}{path}")
                if resp and resp.status_code == 200 and len(resp.text) > 5:
                    results.append(SensitiveFinding(
                        vuln_type=f"Cryptographic Key Exposure ({desc})",
                        url=f"{origin}{path}",
                        parameter="-",
                        payload=f"GET {path}",
                        evidence=f"Key/directory accessible → {resp.text[:200]}",
                        severity="Critical",
                        confidence=0.95,
                    ))
            except Exception:
                pass
        return results

    def _check_api_user_data(self, origin: str) -> List[SensitiveFinding]:
        results: List[SensitiveFinding] = []
        # Check if /api/Users leaks password hashes
        try:
            resp = self.http.get(f"{origin}/api/Users")
            if not resp or resp.status_code != 200:
                return results
            text = resp.text
            hash_types_found = []
            for pattern, hash_type, desc in self._HASH_PATTERNS:
                if hash_type in ("MD5", "SHA1") and pattern.search(text):
                    hash_types_found.append(desc)
            if hash_types_found or '"password"' in text or '"passwordHash"' in text:
                results.append(SensitiveFinding(
                    vuln_type="Password Hash Leak via API",
                    url=f"{origin}/api/Users",
                    parameter="-",
                    payload="GET /api/Users",
                    evidence=f"API returns user data with hashes: {', '.join(hash_types_found) or 'password field exposed'} → {text[:250]}",
                    severity="Critical",
                    confidence=0.96,
                ))
        except Exception:
            pass

        # Check for plaintext password storage
        try:
            resp = self.http.get(f"{origin}/api/Users/1")
            if resp and resp.status_code == 200:
                text = resp.text
                if '"password"' in text:
                    m = re.search(r'"password"\s*:\s*"([^"]{3,})"', text)
                    if m:
                        results.append(SensitiveFinding(
                            vuln_type="Sensitive Data in API Response (Password Field Exposed)",
                            url=f"{origin}/api/Users/1",
                            parameter="-",
                            payload="GET /api/Users/1",
                            evidence=f"Password field in response: {m.group(0)[:80]}",
                            severity="Critical",
                            confidence=0.97,
                        ))
        except Exception:
            pass

        return results

    def _check_js_secrets(self, origin: str) -> List[SensitiveFinding]:
        results: List[SensitiveFinding] = []
        js_paths = [
            "/main.js", "/app.js", "/bundle.js",
            "/static/js/main.js", "/assets/js/app.js",
            "/dist/main.js", "/build/static/js/main.js",
        ]
        # Also try to get script tags from main page
        try:
            resp = self.http.get(origin)
            if resp and resp.status_code == 200:
                js_urls_found = re.findall(r'src="([^"]*\.js[^"]*)"', resp.text)
                for jsurl in js_urls_found[:10]:
                    if not jsurl.startswith("http"):
                        jsurl = origin.rstrip("/") + "/" + jsurl.lstrip("/")
                    if jsurl not in js_paths:
                        js_paths.append(jsurl)
        except Exception:
            pass

        for js_path in js_paths:
            url = js_path if js_path.startswith("http") else f"{origin}{js_path}"
            try:
                resp = self.http.get(url)
                if not resp or resp.status_code != 200 or len(resp.text) < 100:
                    continue
                for pattern, desc in self._JS_SENSITIVE_PATTERNS:
                    m = pattern.search(resp.text)
                    if m:
                        results.append(SensitiveFinding(
                            vuln_type=f"Sensitive Data in JavaScript ({desc})",
                            url=url,
                            parameter="-",
                            payload=f"GET {js_path}",
                            evidence=f"Found in JS: {m.group(0)[:120]}",
                            severity="High",
                            confidence=0.85,
                        ))
                for pattern in self._API_KEY_PATTERNS:
                    m = pattern.search(resp.text)
                    if m:
                        results.append(SensitiveFinding(
                            vuln_type="Leaked API Key / Token in JavaScript",
                            url=url,
                            parameter="-",
                            payload=f"GET {js_path}",
                            evidence=f"API key/token: {m.group(0)[:100]}",
                            severity="High",
                            confidence=0.85,
                        ))
            except Exception:
                pass
        return results

    def _check_crypto_weaknesses(self, origin: str) -> List[SensitiveFinding]:
        results: List[SensitiveFinding] = []
        # Check known MD5-hashed password (admin password in Juice Shop is md5'd)
        # admin123 MD5 = 0192023a7bbd73250516f069df18b500
        known_md5_hashes = {
            "0192023a7bbd73250516f069df18b500": "admin123",
            "e10adc3949ba59abbe56e057f20f883e": "123456",
            "5f4dcc3b5aa765d61d8327deb882cf99": "password",
            "827ccb0eea8a706c4c34a16891f84e7b": "12345678",
        }
        try:
            resp = self.http.get(f"{origin}/api/Users")
            if resp and resp.status_code == 200:
                for md5hash, plaintext in known_md5_hashes.items():
                    if md5hash.lower() in resp.text.lower():
                        results.append(SensitiveFinding(
                            vuln_type="Cryptographic Issue (Weak MD5 Password Hashing)",
                            url=f"{origin}/api/Users",
                            parameter="-",
                            payload=f"MD5({plaintext}) = {md5hash}",
                            evidence=f"Known MD5 hash found: {md5hash} = '{plaintext}'",
                            severity="Critical",
                            confidence=0.99,
                        ))
                        break
        except Exception:
            pass

        # Check for JWT using HS256 with weak secret (alg exposure in error)
        try:
            resp = self.http.get(f"{origin}/rest/user/whoami",
                                  headers={"Authorization": "Bearer invalid.token.here"})
            if resp and resp.status_code in (401, 403):
                if "HS256" in resp.text or "algorithm" in resp.text.lower():
                    results.append(SensitiveFinding(
                        vuln_type="Cryptographic Issue (JWT Algorithm Exposed in Error)",
                        url=f"{origin}/rest/user/whoami",
                        parameter="Authorization",
                        payload="Bearer invalid.token.here",
                        evidence=f"Error reveals algorithm → {resp.text[:150]}",
                        severity="Low",
                        confidence=0.85,
                        exploitable=False,
                    ))
        except Exception:
            pass

        return results

    def _check_error_disclosure(self, origin: str) -> List[SensitiveFinding]:
        results: List[SensitiveFinding] = []
        # Trigger errors and check for stack traces / internal path disclosure
        error_probes = [
            ("/rest/products/search?q='", "SQLite error"),
            ("/api/Users/99999",          "ORM not-found error"),
            ("/rest/user/reset-password", "Missing body error"),
            ("/%00",                       "Null byte error"),
        ]
        stack_patterns = re.compile(
            r'(Error:|at Object\.|at Module\.|stacktrace|stack trace|'
            r'node_modules|/app/|/home/|/var/www|Exception in|Traceback)',
            re.I
        )
        for path, desc in error_probes:
            try:
                resp = self.http.get(f"{origin}{path}")
                if not resp:
                    continue
                if stack_patterns.search(resp.text) and resp.status_code >= 400:
                    results.append(SensitiveFinding(
                        vuln_type="Information Disclosure (Stack Trace / Error Detail Exposure)",
                        url=f"{origin}{path}",
                        parameter="-",
                        payload=f"GET {path}",
                        evidence=f"{desc} → {resp.text[:250]}",
                        severity="Medium",
                        confidence=0.87,
                        exploitable=False,
                    ))
            except Exception:
                pass
        return results
