"""
Professional Scanner Orchestrator
- Smart crawler with form, JS endpoint, and API path discovery
- Robots.txt / sitemap.xml seeding
- Parallel module execution with progress bar and ETA
- CVSS v3.1 vector string generation per finding
- Extended exploit-chain correlation (10 chains)
- Scope management (include/exclude regex patterns)
- Authentication manager (cookie, Bearer, Basic, API key)
- URL normalisation and parameter-signature deduplication
- GraphQL introspection probe
- POST body parameter testing
- Host header injection endpoint discovery
- Technology fingerprinting (extended — 22 stacks)
- Multi-format reporting (JSON, Markdown, HTML)
"""

import base64
import json
import re
import time
import threading
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from colorama import Fore, Style
from core.vuln_types import VT

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# ---------------------------------------------------------------------------
# Severity model and CVSS v3.1
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


_DEFAULT_VECTOR = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

# Primary classification table: exact O(1) lookup by VT category code.
# All module findings must include "category": VT.XXX in their dicts.
_CATEGORY_SEV_MAP: Dict[str, Tuple[Severity, float, str]] = {
    # ── Injection ────────────────────────────────────────────────────────────
    VT.SQL_INJECTION:           (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    VT.NOSQL_INJECTION:         (Severity.HIGH,     8.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.SSTI:                    (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    VT.COMMAND_INJECTION:       (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    VT.RCE:                     (Severity.CRITICAL, 10.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    VT.DESERIALIZATION:         (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    VT.LFI:                     (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    VT.RFI:                     (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.PROTOTYPE_POLLUTION:     (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    # ── XSS ──────────────────────────────────────────────────────────────────
    VT.XSS_STORED:              (Severity.HIGH,     8.8,  "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"),
    VT.XSS:                     (Severity.HIGH,     7.2,  "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    # ── Other injection / request forgery ────────────────────────────────────
    VT.XXE:                     (Severity.HIGH,     8.6,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.SSRF:                    (Severity.HIGH,     8.6,  "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    VT.CSRF:                    (Severity.HIGH,     8.8,  "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    # ── Authentication ────────────────────────────────────────────────────────
    VT.JWT_WEAK:                (Severity.HIGH,     8.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.DEFAULT_CREDS:           (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.WEAK_PASSWORD_RESET:     (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.MASS_ASSIGNMENT:         (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.AUTH_STATE_EXPOSURE:     (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    VT.BROKEN_AUTH:             (Severity.HIGH,     8.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    # ── Access control ────────────────────────────────────────────────────────
    VT.BROKEN_ACCESS_CONTROL:   (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.IDOR:                    (Severity.HIGH,     8.1,  "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    VT.HTTP_METHOD_OVERRIDE:    (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    VT.PARAMETER_POLLUTION:     (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # ── Misconfiguration ──────────────────────────────────────────────────────
    VT.MISSING_SECURITY_HEADER: (Severity.LOW,      2.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    VT.CORS_CREDENTIALED:       (Severity.CRITICAL, 9.1,  "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    VT.CORS_WILDCARD:           (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    VT.CSP_MISCONFIG:           (Severity.MEDIUM,   4.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    VT.INSECURE_COOKIE:         (Severity.MEDIUM,   4.3,  "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    VT.CLICKJACKING:            (Severity.MEDIUM,   4.3,  "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    VT.RATE_LIMITING:           (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    VT.DANGEROUS_HTTP_METHOD:   (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    VT.HTTP_TRACE:              (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    VT.SECURITY_MISCONFIG:      (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    VT.VULNERABLE_COMPONENT:    (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    VT.COMPONENT_VERSION_DISC:  (Severity.LOW,      2.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    VT.DEBUG_ENDPOINT:          (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # ── Sensitive data ────────────────────────────────────────────────────────
    VT.SENSITIVE_FILE:          (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    VT.CRYPTO_KEY_EXPOSURE:     (Severity.CRITICAL, 9.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.PASSWORD_HASH_LEAK:      (Severity.CRITICAL, 9.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    VT.SENSITIVE_DATA_API:      (Severity.CRITICAL, 9.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    VT.SENSITIVE_DATA_JS:       (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    VT.LEAKED_API_KEY:          (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    VT.CRYPTO_ISSUE_WEAK_HASH:  (Severity.CRITICAL, 9.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    VT.CRYPTO_ISSUE:            (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # ── Disclosure ────────────────────────────────────────────────────────────
    VT.INFO_DISCLOSURE:         (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    VT.INFO_DISCLOSURE_STACK:   (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # ── Misc ─────────────────────────────────────────────────────────────────
    VT.OPEN_REDIRECT:           (Severity.MEDIUM,   6.1,  "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    VT.HOST_HEADER:             (Severity.MEDIUM,   6.5,  "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    VT.GRAPHQL:                 (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

# Legacy fallback: regex rules for any finding that hasn't been migrated to a
# VT category code yet.  Once all modules emit "category", this table can be removed.
# Design: longer/anchored patterns first; short abbreviations use \b word boundaries.
_SEVERITY_RULES: List[Tuple["re.Pattern[str]", Tuple[Severity, float, str]]] = [
    # ── Sensitive data / credential exposure ─────────────────────────────────
    (re.compile(r'weak md5 password',                                    re.I), (Severity.CRITICAL, 9.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'cryptographic key exposure',                           re.I), (Severity.CRITICAL, 9.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'password hash leak',                                   re.I), (Severity.CRITICAL, 9.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")),
    (re.compile(r'sensitive data in api response',                       re.I), (Severity.CRITICAL, 9.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")),
    (re.compile(r'sensitive file exposure',                              re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")),
    (re.compile(r'sensitive data in javascript',                         re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")),
    (re.compile(r'leaked api key',                                       re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")),
    (re.compile(r'cryptographic issue',                                  re.I), (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    # ── Misconfig / header / disclosure ──────────────────────────────────────
    (re.compile(r'missing security header',                              re.I), (Severity.LOW,      2.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")),
    (re.compile(r'information disclosure \(stack trace',                 re.I), (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    (re.compile(r'information disclosure',                               re.I), (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    (re.compile(r'component version disclosure',                         re.I), (Severity.LOW,      2.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    (re.compile(r'insecure cookie',                                      re.I), (Severity.MEDIUM,   4.3,  "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N")),
    (re.compile(r'csp misconfiguration',                                 re.I), (Severity.MEDIUM,   4.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    (re.compile(r'cors misconfiguration \(arbitrary origin reflected with credentials\)', re.I), (Severity.CRITICAL, 9.1, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N")),
    (re.compile(r'cors misconfiguration',                                re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")),
    (re.compile(r'clickjacking',                                         re.I), (Severity.MEDIUM,   4.3,  "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N")),
    (re.compile(r'missing rate limiting|broken anti.?automation',        re.I), (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    (re.compile(r'http trace',                                           re.I), (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    (re.compile(r'http method override',                                 re.I), (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")),
    (re.compile(r'parameter pollution',                                  re.I), (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    (re.compile(r'dangerous http method',                                re.I), (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")),
    (re.compile(r'security misconfiguration',                            re.I), (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    (re.compile(r'vulnerable component',                                 re.I), (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    # ── Auth / access control ─────────────────────────────────────────────────
    (re.compile(r'broken access control',                                re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'broken authentication',                                re.I), (Severity.HIGH,     8.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'weak credentials|default.{0,10}credentials',          re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'weak password reset',                                  re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'mass assignment',                                      re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'authentication state exposure',                        re.I), (Severity.LOW,      3.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    (re.compile(r'\bjwt\b',                                              re.I), (Severity.HIGH,     8.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'\bidor\b',                                             re.I), (Severity.HIGH,     8.1,  "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N")),
    # ── Injection — full names before short abbreviations ────────────────────
    (re.compile(r'server-side template injection',                       re.I), (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")),
    (re.compile(r'remote code execution',                                re.I), (Severity.CRITICAL, 10.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")),
    (re.compile(r'command injection',                                    re.I), (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
    (re.compile(r'sql injection',                                        re.I), (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
    (re.compile(r'nosql injection',                                      re.I), (Severity.HIGH,     8.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'prototype pollution',                                  re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'cross-site scripting',                                 re.I), (Severity.HIGH,     7.2,  "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N")),
    (re.compile(r'deserialization',                                      re.I), (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
    # Stored XSS before generic XSS
    (re.compile(r'\bxss\b.*\bstored\b|\bstored\b.*\bxss\b',             re.I), (Severity.HIGH,     8.8,  "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N")),
    # Short abbreviations — word boundaries prevent collision with unrelated words
    (re.compile(r'\bssti\b',                                             re.I), (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")),
    (re.compile(r'\brce\b',                                              re.I), (Severity.CRITICAL, 10.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")),
    (re.compile(r'\bxxe\b',                                              re.I), (Severity.HIGH,     8.6,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'\bssrf\b',                                             re.I), (Severity.HIGH,     8.6,  "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N")),
    (re.compile(r'\bcsrf\b',                                             re.I), (Severity.HIGH,     8.8,  "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N")),
    (re.compile(r'\blfi\b',                                              re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")),
    (re.compile(r'\brfi\b',                                              re.I), (Severity.HIGH,     7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")),
    (re.compile(r'\bsqli\b',                                             re.I), (Severity.CRITICAL, 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
    (re.compile(r'\bxss\b',                                              re.I), (Severity.HIGH,     7.2,  "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N")),
    # ── Misc ─────────────────────────────────────────────────────────────────
    (re.compile(r'host header',                                          re.I), (Severity.MEDIUM,   6.5,  "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")),
    (re.compile(r'open redirect',                                        re.I), (Severity.MEDIUM,   6.1,  "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")),
    (re.compile(r'graphql',                                              re.I), (Severity.MEDIUM,   5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
]

# Safety-net for future modules whose vuln_type strings aren't in _SEVERITY_RULES yet.
# Only activated when classify_severity() returns the INFO/2.0 default.
_FALLBACK_SEV_MAP: Dict[str, Tuple[Severity, float, str]] = {
    "critical": (Severity.CRITICAL, 9.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "high":     (Severity.HIGH,     7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "medium":   (Severity.MEDIUM,   5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "low":      (Severity.LOW,      3.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}


def classify_severity(category_or_type: str) -> Tuple[Severity, float, str]:
    """Return (Severity, cvss_score, cvss_v3.1_vector).

    Lookup order:
    1. Exact match on a VT category code  — O(1), no ambiguity.
    2. Regex pattern search on the raw vuln_type string — legacy fallback for
       findings that haven't been migrated to a VT category yet.
    3. INFO/2.0 default.
    """
    exact = _CATEGORY_SEV_MAP.get(category_or_type)
    if exact:
        return exact
    for pattern, data in _SEVERITY_RULES:
        if pattern.search(category_or_type):
            return data
    return (Severity.INFO, 2.0, _DEFAULT_VECTOR)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    vuln_type: str
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: Severity
    cvss: float
    cvss_vector: str
    exploitable: bool
    confidence: float
    module: str
    category: str = ""
    raw: Any = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")

    def to_dict(self) -> Dict:
        return {
            "type": self.vuln_type,
            "category": self.category,
            "severity": self.severity.value,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "confidence": round(self.confidence * 100, 1),
            "exploitable": self.exploitable,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload[:200],
            "evidence": self.evidence[:300],
            "module": self.module,
            "timestamp": self.timestamp,
        }

    def dedup_key(self) -> Tuple[str, str, str]:
        return (self.vuln_type.lower(), self.parameter, _normalise_url(self.url))


# ---------------------------------------------------------------------------
# URL normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_url(url: str) -> str:
    """
    Canonical URL form for deduplication.
    Lowercases scheme+host, strips fragment, sorts query params, strips trailing slash.
    """
    try:
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(qs.items()), doseq=True)
        path = p.path.rstrip("/") or "/"
        return urlunparse((p.scheme.lower(), p.netloc.lower(), path, "", sorted_query, ""))
    except Exception:
        return url


def _param_signature(url: str) -> str:
    """'host+path+sorted_param_names' — identifies duplicate URL structures regardless of values."""
    try:
        p = urlparse(url)
        keys = sorted(parse_qs(p.query).keys())
        return f"{p.netloc.lower()}{p.path}?{'&'.join(keys)}"
    except Exception:
        return url


# ---------------------------------------------------------------------------
# Scope manager
# ---------------------------------------------------------------------------

class ScopeManager:
    """
    URL allowlist/denylist via regex patterns.
    If include_patterns are set a URL must match at least one to be in scope.
    If exclude_patterns are set a URL matching any is out of scope.
    """

    def __init__(
        self,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ):
        self._include = [re.compile(p) for p in (include_patterns or [])]
        self._exclude = [re.compile(p) for p in (exclude_patterns or [])]

    def in_scope(self, url: str) -> bool:
        if self._exclude and any(p.search(url) for p in self._exclude):
            return False
        if self._include and not any(p.search(url) for p in self._include):
            return False
        return True

    def filter(self, urls: List[str]) -> List[str]:
        return [u for u in urls if self.in_scope(u)]


# ---------------------------------------------------------------------------
# Authentication manager
# ---------------------------------------------------------------------------

class AuthManager:
    """
    Injects authentication credentials into an HTTPEngine session.

    Supported modes:
        session_cookie  — name=value cookie pairs
        bearer          — Authorization: Bearer <token>
        basic           — Authorization: Basic base64(user:pass)
        api_key         — custom header (default X-Api-Key)
    """

    def __init__(self):
        self._headers: Dict[str, str] = {}
        self._cookies: Dict[str, str] = {}

    def set_session_cookie(self, cookies: Dict[str, str]) -> None:
        self._cookies.update(cookies)

    def set_bearer(self, token: str) -> None:
        self._headers["Authorization"] = f"Bearer {token}"

    def set_basic(self, username: str, password: str) -> None:
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._headers["Authorization"] = f"Basic {encoded}"

    def set_api_key(self, key: str, header: str = "X-Api-Key") -> None:
        self._headers[header] = key

    def inject(self, http_engine) -> None:
        """Patch http_engine.session so all subsequent requests carry auth."""
        if hasattr(http_engine, "session"):
            http_engine.session.headers.update(self._headers)
            http_engine.session.cookies.update(self._cookies)


# ---------------------------------------------------------------------------
# Technology fingerprinter
# ---------------------------------------------------------------------------

class TechFingerprinter:
    """Identify server technologies from HTTP response headers, body, and cookies."""

    SIGNATURES: Dict[str, List[str]] = {
        "PHP":           ["x-powered-by: php", ".php", "phpsessid"],
        "ASP.NET":       ["x-powered-by: asp.net", "x-aspnet-version", "aspxauth", "__viewstate"],
        "JSP/Java":      [".jsp", ".do", ".action", "jsessionid"],
        "Spring Boot":   ["x-application-context", "whitelabel error page"],
        "Python/Django": ["csrfmiddlewaretoken", "django"],
        "Python/Flask":  ["werkzeug", "flask"],
        "Ruby on Rails": ["x-request-id", "_session_id", "rails"],
        "Laravel":       ["laravel_session", "laravel"],
        "Symfony":       ["symfony", "_sf2_meta"],
        "Node.js":       ["x-powered-by: express", "connect.sid"],
        "Next.js":       ["x-nextjs", "__next_data"],
        "GraphQL":       ["/graphql", "application/graphql", "__schema"],
        "WordPress":     ["wp-content", "wp-includes", "xmlrpc.php"],
        "Drupal":        ["drupal", "x-drupal-cache", "x-generator: drupal"],
        "Joomla":        ["joomla", "mosconfig", "option=com_"],
        "Magento":       ["mage-", "/skin/frontend/", "magento"],
        "Apache":        ["server: apache"],
        "Nginx":         ["server: nginx"],
        "IIS":           ["server: microsoft-iis"],
        "Tomcat":        ["server: apache-coyote", "apache tomcat"],
        "Cloudflare":    ["server: cloudflare", "cf-ray"],
        "AWS":           ["x-amz-", "x-amzn-", "awsalb", "x-cache: hit from cloudfront"],
    }

    @classmethod
    def fingerprint(cls, response) -> List[str]:
        if response is None:
            return []
        combined = (
            response.text[:4096].lower() + " " +
            " ".join(f"{k}: {v}" for k, v in response.headers.items()).lower() + " " +
            " ".join(response.cookies.keys()).lower()
        )
        return [tech for tech, sigs in cls.SIGNATURES.items()
                if any(sig.lower() in combined for sig in sigs)]


# ---------------------------------------------------------------------------
# JavaScript endpoint extractor
# ---------------------------------------------------------------------------

class JSAnalyzer:
    """
    Scrape inline and external JavaScript for API endpoint paths.
    Prioritises API-looking paths (/api/, /v1/, /graphql, …) then falls back
    to any quoted path string of reasonable length.
    """

    _API_PATH_RE = re.compile(
        r"""['"`](/(?:api|v\d+|graphql|rest|service|endpoint|data|user|auth|admin|search|upload)[\w/.-]*)['"`]""",
        re.IGNORECASE,
    )
    _GENERIC_PATH_RE = re.compile(r"""['"`](/[\w/.-]{5,80})['"`]""")
    _ASSET_EXT_RE = re.compile(r"\.(css|js|png|jpg|gif|svg|woff2?|ttf|ico|map)$", re.I)

    def __init__(self, http_engine):
        self.http = http_engine

    def extract_from_response(self, html: str, base_url: str) -> List[str]:
        if not BS4_AVAILABLE:
            return []

        endpoints: Set[str] = set()
        soup = BeautifulSoup(html, "html.parser")

        for script in soup.find_all("script", src=False):
            endpoints.update(self._scrape(script.string or ""))

        for script in soup.find_all("script", src=True):
            abs_src = urljoin(base_url, script["src"])
            resp = self.http.get(abs_src)
            if resp and resp.status_code == 200:
                endpoints.update(self._scrape(resp.text))

        return [urljoin(base_url, ep) for ep in endpoints]

    def _scrape(self, js_text: str) -> Set[str]:
        found: Set[str] = set()
        for m in self._API_PATH_RE.finditer(js_text):
            found.add(m.group(1))
        for m in self._GENERIC_PATH_RE.finditer(js_text):
            path = m.group(1)
            if not self._ASSET_EXT_RE.search(path):
                found.add(path)
        return found


# ---------------------------------------------------------------------------
# API path discoverer
# ---------------------------------------------------------------------------

_API_WORDLIST: List[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/docs",
    "/rest", "/rest/v1", "/rest/v2",
    "/admin", "/admin/api", "/management",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/actuator/loggers", "/actuator/heapdump", "/actuator/threaddump", "/actuator/configprops",
    "/health", "/status", "/metrics", "/info",
    "/wp-json", "/wp-json/wp/v2",
    "/xmlrpc.php", "/jsonrpc",
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.env.production",
    "/config.json", "/app.config", "/config.yml", "/config.yaml",
    "/robots.txt", "/sitemap.xml",
    "/login", "/register", "/signup", "/logout",
    "/auth", "/oauth", "/oauth2/token",
    "/api/users", "/api/user", "/api/me", "/api/profile",
    "/api/search", "/api/upload", "/api/files",
    "/api/admin", "/api/settings", "/api/config",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders", "/api/v1/auth/login",
    "/api/v2/users", "/api/v2/products",
    "/api/auth/login", "/api/auth/register", "/api/auth/token", "/api/auth/refresh",
    "/api/health", "/api/status", "/api/version",
    "/rest/products/search", "/rest/user/login", "/rest/user/register", "/rest/user/whoami",
    "/rest/basket", "/rest/products", "/rest/memories", "/rest/wallet",
    "/rest/track-order", "/rest/users/authentication", "/rest/deluxe-membership",
    "/api/Challenges", "/api/Products", "/api/Users", "/api/SecurityQuestions",
    "/api/Feedbacks", "/api/Complaints", "/api/Recycles", "/api/Quantitys",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php", "/admin.php",
    "/.htaccess", "/web.config", "/server-status", "/server-info",
    "/package.json", "/composer.json", "/yarn.lock",
    "/application.properties", "/application.yml", "/app.yaml",
    "/config/database.yml", "/config/secrets.yml",
    "/backup/", "/debug", "/trace", "/__debug__",
    "/v1", "/v2", "/v3", "/internal/api", "/private/api",
    "/api/token", "/api/key", "/api/keys",
    "/api/reports", "/api/logs", "/api/events",
    "/api/roles", "/api/permissions", "/api/groups",
    "/api/orders", "/api/cart", "/api/checkout",
    "/api/comments", "/api/reviews", "/api/messages",
    "/.npmrc", "/npm-debug.log",
]

_GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name}}}"}'


class APIDiscoverer:
    """Probe common API paths; attempt GraphQL introspection."""

    def __init__(self, http_engine):
        self.http = http_engine

    def discover(self, origin: str) -> List[str]:
        """Return URLs that responded with 200/401/403."""
        found: List[str] = []
        for path in _API_WORDLIST:
            url = origin.rstrip("/") + path
            try:
                resp = self.http.get(url)
                if resp and resp.status_code in (200, 201, 401, 403):
                    found.append(url)
            except Exception:
                pass
        return found

    def graphql_introspection(self, graphql_url: str) -> Optional[Dict]:
        """Return schema summary dict if introspection is open, else None."""
        try:
            resp = self.http.post(
                graphql_url,
                data=_GRAPHQL_INTROSPECTION,
                headers={"Content-Type": "application/json"},
            )
            if resp and resp.status_code == 200 and "__schema" in resp.text:
                data = resp.json()
                types_ = [
                    t["name"]
                    for t in data.get("data", {}).get("__schema", {}).get("types", [])
                ]
                return {
                    "introspection": True,
                    "types_count": len(types_),
                    "types_sample": types_[:10],
                }
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Parameter fuzzer — discovers params on bare endpoints (SPAs, REST APIs)
# ---------------------------------------------------------------------------

class ParamFuzzer:
    _PATH_HINTS: Dict[str, List[str]] = {
        r'search|query|find|lookup|filter':       ["q", "query", "search", "keyword", "term", "s", "filter"],
        r'user|account|member|profile|login':     ["id", "user_id", "userId", "username", "email", "uid"],
        r'product|item|goods|catalog|shop':       ["id", "product_id", "productId", "category", "cat", "q"],
        r'order|cart|checkout|purchase|basket':   ["id", "order_id", "orderId", "userId", "user_id"],
        r'redirect|return|forward|callback|goto': ["url", "redirect", "next", "return", "returnUrl", "goto"],
        r'file|upload|download|attach|image':     ["file", "filename", "path", "name", "id"],
        r'page|post|article|blog|news|content':   ["id", "slug", "page", "name", "category"],
        r'admin|manage|dashboard|panel|config':   ["id", "action", "section", "module"],
        r'auth|token|session|access':             ["token", "code", "state", "scope"],
        r'api|rest|service|endpoint':             ["id", "q", "search", "format", "version"],
    }
    _FALLBACK_PARAMS = ["q", "id", "search", "name", "page", "limit", "type", "user_id", "userId", "email"]
    _ALWAYS_TRY = ["q", "id", "search"]

    def __init__(self, http_engine):
        self.http = http_engine

    def fuzz(self, url: str) -> List[str]:
        parsed = urlparse(url)
        if parsed.query:
            return []

        path_lower = parsed.path.lower()
        last_seg = path_lower.rstrip("/").rsplit("/", 1)[-1]
        candidates: Set[str] = set(self._ALWAYS_TRY)

        for pattern, params in self._PATH_HINTS.items():
            if re.search(pattern, path_lower) or re.search(pattern, last_seg):
                candidates.update(params)

        if len(candidates) <= len(self._ALWAYS_TRY):
            candidates.update(self._FALLBACK_PARAMS)

        baseline_resp = self.http.get(url)
        baseline_status = baseline_resp.status_code if baseline_resp else 200
        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        found: List[str] = []
        for param in candidates:
            try:
                test_url = f"{url}?{param}=test123"
                resp = self.http.get(test_url)
                if not resp:
                    continue
                if resp.status_code in (200, 400, 422, 500):
                    if resp.status_code != baseline_status or abs(len(resp.text) - baseline_len) > 20:
                        found.append(test_url)
            except Exception:
                pass

        return found


# ---------------------------------------------------------------------------
# Quick detector — sensitive files, headers, CORS, open redirect, IDOR, traversal
# ---------------------------------------------------------------------------

class QuickDetector:
    _SENSITIVE_PATHS = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/config", "/.git/HEAD",
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/config.json", "/config.yml", "/app.config",
        "/backup.sql", "/dump.sql", "/.htaccess", "/web.config",
        "/server-status", "/server-info", "/.DS_Store",
        "/package.json", "/composer.json", "/yarn.lock",
        "/wp-config.php", "/wp-config.php.bak",
        "/application.properties", "/application.yml",
        "/config/database.yml", "/config/secrets.yml",
        "/.npmrc", "/.aws/credentials",
    ]
    _SENSITIVE_KEYWORDS = [
        "password", "passwd", "secret", "api_key", "apikey", "token", "db_host",
        "database_url", "mysql_", "postgres", "[core]", "repositoryformat",
        "<?php", "phpinfo", "dependencies", "\"scripts\"", "username", "db_pass",
    ]
    _SECURITY_HEADERS = [
        "Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security",
        "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy",
    ]
    _REDIRECT_PARAMS = {
        "redirect", "url", "next", "return", "returnurl", "goto", "dest",
        "destination", "ref", "redir", "redirect_uri", "continue", "forward",
        "callback", "target", "link", "location", "redirect_to", "to",
    }
    _TRAVERSAL_PAYLOADS = [
        "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
    ]
    _CANARY = "https://evil.erebus-scan.internal"

    def __init__(self, http_engine):
        self.http = http_engine

    def check_all(self, target: str, param_urls: List[str]) -> List[Finding]:
        out: List[Finding] = []
        parsed = urlparse(target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        out.extend(self._sensitive_files(origin))
        out.extend(self._security_headers(target))
        out.extend(self._cors(target))
        for url in param_urls[:30]:
            out.extend(self._open_redirect(url))
            out.extend(self._path_traversal(url))
        out.extend(self._idor_paths(target))
        return out

    def _sensitive_files(self, origin: str) -> List[Finding]:
        out: List[Finding] = []
        for path in self._SENSITIVE_PATHS:
            url = origin.rstrip("/") + path
            try:
                resp = self.http.get(url)
                if resp and resp.status_code == 200 and len(resp.text) > 10:
                    text_low = resp.text.lower()
                    if any(kw in text_low for kw in self._SENSITIVE_KEYWORDS):
                        out.append(Finding(
                            vuln_type="Sensitive File Exposure",
                            url=url,
                            parameter="-",
                            payload=f"GET {path}",
                            evidence=resp.text[:200].strip(),
                            severity=Severity.HIGH,
                            cvss=7.5,
                            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            exploitable=True,
                            confidence=0.90,
                            module="QuickDetector",
                        ))
            except Exception:
                pass
        return out

    def _security_headers(self, url: str) -> List[Finding]:
        try:
            resp = self.http.get(url)
            if not resp:
                return []
            resp_header_keys = {k.lower() for k in resp.headers}
            missing = [h for h in self._SECURITY_HEADERS if h.lower() not in resp_header_keys]
            if missing:
                return [Finding(
                    vuln_type="Missing Security Headers",
                    url=url,
                    parameter="-",
                    payload="-",
                    evidence=f"Missing: {', '.join(missing)}",
                    severity=Severity.LOW,
                    cvss=3.1,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    exploitable=False,
                    confidence=1.0,
                    module="QuickDetector",
                )]
        except Exception:
            pass
        return []

    def _cors(self, url: str) -> List[Finding]:
        try:
            resp = self.http.get(url, headers={"Origin": self._CANARY})
            if not resp:
                return []
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            vuln = acao == "*" or self._CANARY in acao
            if vuln:
                creds = acac.lower() == "true"
                return [Finding(
                    vuln_type="CORS Misconfiguration",
                    url=url,
                    parameter="Origin",
                    payload=f"Origin: {self._CANARY}",
                    evidence=f"ACAO={acao!r} ACAC={acac!r}",
                    severity=Severity.HIGH if creds else Severity.MEDIUM,
                    cvss=8.1 if creds else 6.5,
                    cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" if creds else "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    exploitable=True,
                    confidence=0.95,
                    module="QuickDetector",
                )]
        except Exception:
            pass
        return []

    def _open_redirect(self, url: str) -> List[Finding]:
        out: List[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        redirect_params = [p for p in params if p.lower() in self._REDIRECT_PARAMS]
        for param in redirect_params:
            try:
                tp = params.copy()
                tp[param] = [self._CANARY]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(tp, doseq=True)}"
                resp = self.http.get(test_url, allow_redirects=False)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if "erebus-scan" in loc or loc.startswith("https://evil"):
                        sev, cvss, vector = classify_severity(VT.OPEN_REDIRECT)
                        out.append(Finding(
                            vuln_type="Open Redirect",
                            url=url,
                            parameter=param,
                            payload=f"{param}={self._CANARY}",
                            evidence=f"HTTP {resp.status_code} → Location: {loc}",
                            severity=sev,
                            cvss=cvss,
                            cvss_vector=vector,
                            exploitable=True,
                            confidence=0.97,
                            module="QuickDetector",
                        ))
            except Exception:
                pass
        return out

    def _path_traversal(self, url: str) -> List[Finding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in list(params.keys())[:3]:
            for payload in self._TRAVERSAL_PAYLOADS:
                try:
                    tp = params.copy()
                    tp[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(tp, doseq=True)}"
                    resp = self.http.get(test_url)
                    if resp and resp.status_code == 200:
                        if "root:" in resp.text or "[extensions]" in resp.text or "for 16-bit" in resp.text:
                            sev, cvss, vector = classify_severity(VT.LFI)
                            return [Finding(
                                vuln_type="Path Traversal (LFI)",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=resp.text[:200],
                                severity=sev,
                                cvss=cvss,
                                cvss_vector=vector,
                                exploitable=True,
                                confidence=0.99,
                                module="QuickDetector",
                            )]
                except Exception:
                    pass
        return []

    def _idor_paths(self, url: str) -> List[Finding]:
        out: List[Finding] = []
        parsed = urlparse(url)
        parts = parsed.path.rstrip("/").split("/")
        # Fetch baseline once — reused across all numeric segments
        try:
            r1_baseline = self.http.get(url)
        except Exception:
            return out
        if not r1_baseline:
            return out
        for i, part in enumerate(parts):
            if not re.match(r'^\d+$', part):
                continue
            try:
                orig_id = int(part)
                alt_id = str(orig_id + 1) if orig_id > 0 else "2"
                new_parts = parts.copy()
                new_parts[i] = alt_id
                test_url = f"{parsed.scheme}://{parsed.netloc}{'/'.join(new_parts)}"
                r1 = r1_baseline
                r2 = self.http.get(test_url)
                if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
                    if abs(len(r1.text) - len(r2.text)) > 30:
                        sev, cvss, vector = classify_severity(VT.IDOR)
                        out.append(Finding(
                            vuln_type="Potential IDOR",
                            url=url,
                            parameter=f"path:{orig_id}",
                            payload=f"/{orig_id}/ → /{alt_id}/",
                            evidence=f"ID {orig_id} → {len(r1.text)}B, ID {alt_id} → {len(r2.text)}B",
                            severity=sev,
                            cvss=cvss,
                            cvss_vector=vector,
                            exploitable=True,
                            confidence=0.75,
                            module="QuickDetector",
                        ))
            except Exception:
                pass
        return out


# ---------------------------------------------------------------------------
# Smart router — matches URLs to relevant modules only
# ---------------------------------------------------------------------------

class SmartRouter:
    """
    Profiles a (url, method, params) tuple and returns the minimal set of
    module names that should test it.  Eliminates the N × M cartesian blast
    of running every module on every URL.

    Module name taxonomy (must match erebus.py _VALID_MODULES):
        per-url  : sqli xss rce xxe ssti
        per-origin: auth acl sensitive misconfig
    """

    _STATIC_EXT = re.compile(
        r'\.(css|js|mjs|png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|eot|otf|map|pdf|zip|tar|gz)$',
        re.I,
    )
    _AUTH_PATH     = re.compile(r'login|signin|logout|auth|register|signup|password|token|oauth|reset|session', re.I)
    _FILE_PARAMS   = frozenset({'file', 'path', 'dir', 'filename', 'include', 'require', 'load', 'template', 'page', 'source', 'dest', 'src'})
    _SEARCH_PARAMS = frozenset({'q', 'search', 'query', 'keyword', 'filter', 's', 'term', 'text', 'find', 'name', 'q[]'})
    _SQLI_PARAMS   = frozenset({'id', 'user_id', 'userid', 'cat', 'category', 'sort', 'order', 'product_id', 'item_id', 'pid', 'cid', 'offset', 'limit', 'page'})
    _REDIRECT_PARAMS = frozenset({'redirect', 'url', 'next', 'return', 'returnurl', 'goto', 'dest', 'destination', 'callback'})
    _REFLECT_PARAMS  = frozenset({'message', 'msg', 'comment', 'review', 'feedback', 'description', 'title', 'content', 'body', 'note', 'text', 'subject'})
    _XML_PATH        = re.compile(r'xml|soap|wsdl|import|upload', re.I)
    _TEMPLATE_PATH   = re.compile(r'render|template|view|preview|report|generate|pdf|export|print', re.I)
    _API_PATH        = re.compile(r'/api/|/rest/|/v\d+/|/graphql|/rpc', re.I)

    # Paths where SQLi/XSS/SSTI actually make sense (data-processing endpoints)
    _INJECTION_WORTHY = re.compile(
        r'/(?:api|rest|v\d+|graphql|login|signin|sign-in|auth|search|product|item|user|account'
        r'|order|filter|category|admin|checkout|cart|basket|comment|review|feedback|report'
        r'|query|find|lookup|profile|setting|config|register|forgot|reset|invite|coupon'
        r'|ticket|message|post|thread|topic|tag|label)',
        re.I,
    )
    # Paths that belong to Spring Boot / Java stacks — skip on Node/Express/Angular targets
    _SPRING_PATHS = re.compile(
        r'^/(?:actuator|management|jolokia|health|beans|env|heapdump|threaddump'
        r'|logfile|loggers|dump|info|metrics|prometheus|configprops|httptrace'
        r'|mappings|scheduledtasks|flyway|liquibase|caches|shutdown|refresh)',
        re.I,
    )
    # Tech-stack name tokens that imply a Node.js / JavaScript server
    _NODE_STACK_TOKENS = frozenset({
        'express', 'node.js', 'nodejs', 'node', 'angular', 'angularjs',
        'react', 'vue', 'nuxt', 'next.js', 'nestjs', 'koa', 'fastify',
    })

    # These modules own origin-level deduplication internally (self._seen).
    # The router submits them exactly once — against the origin root URL.
    ORIGIN_MODULES: frozenset = frozenset({'auth', 'acl', 'sensitive', 'misconfig'})
    PER_URL_MODULES: frozenset = frozenset({'sqli', 'xss', 'rce', 'xxe', 'ssti', 'openredirect'})

    @classmethod
    def route(
        cls,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        technologies: frozenset = frozenset(),
    ) -> frozenset:
        """Return frozenset of module names relevant for this (url, method, params) combination."""
        parsed = urlparse(url)
        path   = parsed.path.lower()
        qs     = parse_qs(parsed.query)
        all_params = set(qs.keys()) | set((params or {}).keys())
        all_params_lower = {p.lower() for p in all_params}
        method = method.upper()

        # Static asset — nothing to test
        if cls._STATIC_EXT.search(path):
            return frozenset()

        # Tech-aware: skip Spring Boot management paths when a Node.js stack is detected
        tech_lower = {t.lower() for t in technologies}
        is_node_stack = bool(tech_lower & cls._NODE_STACK_TOKENS)
        if is_node_stack and cls._SPRING_PATHS.match(path):
            return frozenset()

        relevant: set = set()

        has_data = bool(all_params) or method in ("POST", "PUT", "PATCH", "DELETE")
        is_api   = bool(cls._API_PATH.search(path))
        # A path is "injection-worthy" if it's an API/REST path, matches known
        # data-processing patterns, or is an auth route — not just any path with
        # a query string injected by ParamFuzzer.
        is_injection_worthy = (
            is_api
            or bool(cls._INJECTION_WORTHY.search(path))
            or bool(cls._AUTH_PATH.search(path))
            or method in ("POST", "PUT")
        )

        if is_injection_worthy and has_data:
            # SQLi: param names or path suggest structured data lookup
            if (all_params_lower & cls._SQLI_PARAMS or
                    all_params_lower & cls._SEARCH_PARAMS or
                    any(v and re.match(r'^\d+$', v[0]) for v in qs.values()) or
                    method in ("POST", "PUT")):
                relevant.add("sqli")

            # XSS: reflected/stored input fields
            if (all_params_lower & cls._SEARCH_PARAMS or
                    all_params_lower & cls._REFLECT_PARAMS or
                    method in ("POST", "PUT")):
                relevant.add("xss")

            # SSTI: template-rendering or text-input paths
            if (cls._TEMPLATE_PATH.search(path) or
                    all_params_lower & cls._SEARCH_PARAMS or
                    all_params_lower & cls._REFLECT_PARAMS or
                    method in ("POST", "PUT")):
                relevant.add("ssti")

            # RCE: file/path parameter names
            if all_params_lower & cls._FILE_PARAMS:
                relevant.add("rce")

        # XXE: XML paths or upload endpoints — independent of injection worthiness
        if cls._XML_PATH.search(path) or "xml" in all_params_lower:
            relevant.add("xxe")

        # Open redirect: redirect/url/next params — independent of injection worthiness
        if all_params_lower & cls._REDIRECT_PARAMS:
            relevant.add("openredirect")

        return frozenset(relevant)

    # Maps class-name-derived keys → canonical short names used in ORIGIN/PER_URL_MODULES
    _NAME_ALIASES: Dict[str, str] = {
        "brokenauth":      "auth",
        "accesscontrol":   "acl",
        "sensitivedata":   "sensitive",
        "securitymisconfig": "misconfig",
    }

    @classmethod
    def _canonical(cls, module) -> str:
        raw = module.__class__.__name__.replace("Module", "").lower()
        return cls._NAME_ALIASES.get(raw, raw)

    @classmethod
    def build_jobs(
        cls,
        targets: List[Tuple],
        modules: List,
        enabled_names: Optional[Set[str]] = None,
        technologies: frozenset = frozenset(),
    ) -> List[Tuple]:
        """
        Build deduplicated job list:
          - Origin-level modules: one job per origin (first URL of each origin)
          - Per-URL modules: one job per (module, url) where module is relevant

        Returns list of (module, url, method, params).
        """
        mod_map: Dict[str, Any] = {cls._canonical(m): m for m in modules}
        active = enabled_names if enabled_names else set(mod_map.keys())

        origin_scheduled: Set[str] = set()
        jobs: List[Tuple] = []

        for url, method, params in targets:
            parsed    = urlparse(url)
            origin    = f"{parsed.scheme}://{parsed.netloc}"
            # Origin-level modules: schedule once per origin
            if origin not in origin_scheduled:
                origin_scheduled.add(origin)
                for name in cls.ORIGIN_MODULES & set(mod_map) & active:
                    jobs.append((mod_map[name], origin, "GET", None))

            # Per-URL modules: only if relevant
            relevant = cls.route(url, method, params, technologies=technologies)
            for name in relevant & set(mod_map) & active:
                jobs.append((mod_map[name], url, method, params))

        return jobs


# ---------------------------------------------------------------------------
# Robots.txt / sitemap.xml parser
# ---------------------------------------------------------------------------

class SiteMapParser:
    """Seed the crawler with paths from robots.txt and sitemap.xml."""

    def __init__(self, http_engine):
        self.http = http_engine

    def parse_robots(self, origin: str) -> List[str]:
        paths: List[str] = []
        try:
            resp = self.http.get(origin.rstrip("/") + "/robots.txt")
            if resp and resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            if path and path != "/":
                                paths.append(urljoin(origin, path))
        except Exception:
            pass
        return paths

    def parse_sitemap(self, origin: str) -> List[str]:
        urls: List[str] = []
        try:
            resp = self.http.get(origin.rstrip("/") + "/sitemap.xml")
            if resp and resp.status_code == 200:
                try:
                    root = ET.fromstring(resp.text)
                    for loc in root.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                        if loc.text:
                            urls.append(loc.text.strip())
                except ET.ParseError:
                    pass
        except Exception:
            pass
        return urls


# ---------------------------------------------------------------------------
# Host header injection tester
# ---------------------------------------------------------------------------

class HostHeaderTester:
    """
    Send a request with a canary value in Host / X-Forwarded-Host.
    If the canary is reflected in the response body the endpoint is vulnerable
    to host header injection (password reset poisoning, cache poisoning, SSRF).
    """

    _CANARY = "evil.erebus-test.internal"

    def __init__(self, http_engine):
        self.http = http_engine

    def test(self, url: str) -> Optional[Finding]:
        try:
            resp = self.http.get(url, headers={
                "Host": self._CANARY,
                "X-Forwarded-Host": self._CANARY,
                "X-Host": self._CANARY,
            })
            if resp and self._CANARY in resp.text:
                sev, cvss, vector = classify_severity(VT.HOST_HEADER)
                return Finding(
                    vuln_type="Host Header Injection",
                    url=url,
                    parameter="Host",
                    payload=f"Host: {self._CANARY}",
                    evidence=f"Canary '{self._CANARY}' reflected in response (len={len(resp.text)})",
                    severity=sev,
                    cvss=cvss,
                    cvss_vector=vector,
                    exploitable=True,
                    confidence=0.90,
                    module="HostHeader",
                )
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class Crawler:
    """
    BFS crawler with:
    - Same-origin link extraction
    - Form discovery (GET + POST with full param maps)
    - JS endpoint extraction via JSAnalyzer
    - Robots.txt / sitemap.xml seeding
    - Parameter-signature deduplication (avoid testing N URLs with same shape)
    - Scope enforcement
    """

    def __init__(
        self,
        http_engine,
        max_depth: int = 3,
        max_urls: int = 300,
        scope: Optional[ScopeManager] = None,
    ):
        self.http = http_engine
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.scope = scope or ScopeManager()
        self._visited: Set[str] = set()
        self._param_sigs: Set[str] = set()
        self._lock = threading.Lock()
        self.forms: List[Dict] = []
        self._js = JSAnalyzer(http_engine)
        self._sitemap = SiteMapParser(http_engine)

    def crawl(self, start_url: str) -> List[str]:
        parsed = urlparse(start_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        seeds = (
            self._sitemap.parse_robots(origin) +
            self._sitemap.parse_sitemap(origin)
        )

        from collections import deque as _deque
        queue: _deque = _deque(
            [(start_url, 0)] +
            [(s, 0) for s in seeds if s.startswith(origin)]
        )
        discovered: List[str] = []

        while queue and len(discovered) < self.max_urls:
            url, depth = queue.popleft()
            url = url.split("#")[0].rstrip("/") or url
            norm = _normalise_url(url)
            sig = _param_signature(url)

            if not self.scope.in_scope(url):
                continue

            with self._lock:
                if norm in self._visited:
                    continue
                if "?" in url and sig in self._param_sigs:
                    continue
                self._visited.add(norm)
                if "?" in url:
                    self._param_sigs.add(sig)

            resp = self.http.get(url)
            if not resp or resp.status_code not in (200, 201):
                continue

            discovered.append(url)

            if depth >= self.max_depth or not BS4_AVAILABLE:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if not href or href.startswith(("javascript:", "mailto:", "tel:")):
                    continue
                abs_url = urljoin(url, href).split("#")[0]
                if abs_url.startswith(origin):
                    queue.append((abs_url, depth + 1))

            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", url))
                method = form.get("method", "GET").upper()
                inputs = [
                    {
                        "name": inp.get("name"),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    }
                    for inp in form.find_all(["input", "textarea", "select"])
                    if inp.get("name")
                ]
                if inputs:
                    self.forms.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                        "source_url": url,
                    })

            for ep in self._js.extract_from_response(resp.text, url):
                if ep.startswith(origin):
                    queue.append((ep, depth + 1))

        return discovered

    def get_param_urls(self, urls: List[str]) -> List[str]:
        return [u for u in urls if "?" in u and parse_qs(urlparse(u).query)]

    def get_form_targets(self) -> List[Tuple[str, str, Dict]]:
        """Return list of (action_url, method, {name: value}) for form-based targets."""
        targets = []
        for form in self.forms:
            params = {inp["name"]: "FUZZ" for inp in form["inputs"] if inp["name"]}
            targets.append((form["action"], form["method"], params))
        return targets


# ---------------------------------------------------------------------------
# Exploit chain analyser
# ---------------------------------------------------------------------------

KNOWN_CHAINS: List[Dict] = [
    {
        "name": "SQLi → Auth Bypass → Admin Takeover",
        "requires": [["sqli"]],
        "description": "SQL injection allows bypassing authentication and gaining admin access.",
        "severity": Severity.CRITICAL,
        "references": ["CWE-89", "OWASP A03:2021"],
    },
    {
        "name": "XSS (Stored) → Session Hijack → Account Takeover",
        "requires": [["xss (stored)", "stored xss", "xss stored", "cross-site scripting (xss) — stored"]],
        "description": "Stored XSS enables cookie theft and full session hijacking.",
        "severity": Severity.HIGH,
        "references": ["CWE-79", "OWASP A03:2021"],
    },
    {
        "name": "XXE → SSRF → Internal Network Pivoting",
        "requires": [["xxe"]],
        "description": "XXE with SSRF can reach internal services and cloud metadata endpoints.",
        "severity": Severity.HIGH,
        "references": ["CWE-611", "OWASP A05:2021"],
    },
    {
        "name": "XXE → SSRF → RCE via Cloud Metadata Credential Theft",
        "requires": [["xxe"], ["ssrf"]],
        "description": "XXE enables SSRF to AWS/GCP/Azure metadata; stolen IAM credentials lead to RCE.",
        "severity": Severity.CRITICAL,
        "references": ["CWE-918", "OWASP A10:2021"],
    },
    {
        "name": "LFI → Log Poisoning → RCE",
        "requires": [["lfi"]],
        "description": "LFI combined with log file inclusion leads to remote code execution.",
        "severity": Severity.CRITICAL,
        "references": ["CWE-22", "OWASP A01:2021"],
    },
    {
        "name": "SSTI → RCE → Full Compromise",
        "requires": [["ssti"]],
        "description": "Server-side template injection directly executes arbitrary server-side code.",
        "severity": Severity.CRITICAL,
        "references": ["CWE-94", "OWASP A03:2021"],
    },
    {
        "name": "IDOR → Horizontal Privilege Escalation → Mass Data Breach",
        "requires": [["idor"]],
        "description": "Insecure direct object references expose all user records to an authenticated attacker.",
        "severity": Severity.HIGH,
        "references": ["CWE-639", "OWASP A01:2021"],
    },
    {
        "name": "Open Redirect → CSRF Token Theft → Account Takeover",
        "requires": [["open redirect"], ["csrf"]],
        "description": "Open redirect leaks CSRF token via Referer header, enabling cross-site request forgery.",
        "severity": Severity.HIGH,
        "references": ["CWE-601", "CWE-352"],
    },
    {
        "name": "Deserialization → RCE → Full Compromise",
        "requires": [["deserialization"]],
        "description": "Unsafe deserialization of attacker-controlled data allows arbitrary code execution.",
        "severity": Severity.CRITICAL,
        "references": ["CWE-502", "OWASP A08:2021"],
    },
    {
        "name": "Host Header Injection → Password Reset Poisoning → Account Takeover",
        "requires": [["host header"]],
        "description": "Manipulated Host header poisons password reset links sent via email.",
        "severity": Severity.HIGH,
        "references": ["CWE-113", "OWASP A03:2021"],
    },
]


def analyse_chains(findings: List[Finding]) -> List[Dict]:
    """Return exploit chains backed only by confirmed, exploitable findings.

    A chain is created only when:
      - Every required finding group is satisfied by a real finding with
        confidence >= 0.80 AND exploitable=True.
      - Actual source evidence (URL, parameter, payload, response excerpt) is
        attached to each chain so the report shows proof, not speculation.
    """
    confirmed = [f for f in findings if f.confidence >= 0.80 and f.exploitable]
    if not confirmed:
        return []

    vuln_types_lower = {f.vuln_type.lower() for f in confirmed}
    chains = []

    for chain in KNOWN_CHAINS:
        # All requirement groups must be satisfied (AND logic across groups,
        # OR logic within a group).
        if not all(
            any(alt in vt for vt in vuln_types_lower for alt in group)
            for group in chain["requires"]
        ):
            continue

        # Collect the first matching finding per requirement group as evidence.
        source_findings = []
        for group in chain["requires"]:
            match = next(
                (f for f in confirmed if any(alt in f.vuln_type.lower() for alt in group)),
                None,
            )
            if match:
                source_findings.append({
                    "finding": match.vuln_type,
                    "url": match.url,
                    "parameter": match.parameter,
                    "payload": match.payload[:150] if match.payload else "",
                    "evidence": match.evidence[:200] if match.evidence else "",
                    "confidence": f"{match.confidence:.0%}",
                })

        chains.append({
            "chain": chain["name"],
            "description": chain["description"],
            "severity": chain["severity"].value,
            "references": chain.get("references", []),
            "source_findings": source_findings,
        })

    return chains


# ---------------------------------------------------------------------------
# Progress tracker with ETA
# ---------------------------------------------------------------------------

class ProgressTracker:
    """Thread-safe progress bar with ETA displayed inline."""

    def __init__(self, total: int):
        self._total = total
        self._done = 0
        self._lock = threading.Lock()
        self._start = time.time()

    def increment(self) -> None:
        with self._lock:
            self._done += 1
            self._render()

    def _render(self) -> None:
        done = self._done
        total = self._total
        elapsed = time.time() - self._start
        eta = (elapsed / done * (total - done)) if done else 0.0
        pct = done / total * 100 if total else 100
        bar_len = 28
        filled = int(bar_len * done / total) if total else bar_len
        bar = "█" * filled + "░" * (bar_len - filled)
        print(
            f"\r{Fore.CYAN}  [{bar}] {done}/{total} ({pct:.0f}%)  ETA {eta:.0f}s{Style.RESET_ALL}",
            end="",
            flush=True,
        )
        if done >= total:
            print()


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    """
    Professional scan orchestrator.

    Usage example:
        http = HTTPEngine(...)
        evasion = WAFEvasion(http)

        auth = AuthManager()
        auth.set_bearer("eyJ...")
        auth.inject(http)

        scope = ScopeManager(
            include_patterns=[r"example\\.com"],
            exclude_patterns=[r"/logout", r"\\.css$"],
        )

        scanner = Scanner(target, http, evasion, scope=scope)
        modules = [SQLiModule(http), XSSModule(http), RCEModule(http), XXEModule(http)]
        findings = scanner.scan(modules)
        scanner.generate_report("report.html")
    """

    def __init__(
        self,
        target: str,
        http_engine,
        evasion_engine,
        max_workers: int = 8,
        scope: Optional[ScopeManager] = None,
        host_header_test: bool = True,
        api_discovery: bool = True,
    ):
        self.target = target
        self.http = http_engine
        self.evasion = evasion_engine
        self.max_workers = max_workers
        self.scope = scope or ScopeManager()
        self.host_header_test = host_header_test
        self.api_discovery = api_discovery

        self.findings: List[Finding] = []
        self.technologies: List[str] = []
        self.waf_info: Dict = {}
        self.chains: List[Dict] = []
        self.graphql_info: Optional[Dict] = None

        self._lock = threading.Lock()
        self._start_time: float = 0.0
        self._crawled_urls: List[str] = []
        self._seen_findings: Set[Tuple] = set()
        self._scan_stats: Dict = {
            "urls_crawled": 0,
            "targets_tested": 0,
            "modules_run": 0,
            "findings_raw": 0,
            "findings_deduplicated": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, modules: List, crawl: bool = True, max_depth: int = 2, max_urls: int = 300) -> List[Finding]:
        """
        Full scan pipeline:
          1. WAF detection
          2. Technology fingerprinting
          3. Crawl + JS analysis + robots.txt/sitemap.xml + API discovery
          4. Host header injection probe
          5. Parallel module execution (GET + POST) with live progress + ETA
          6. Finding deduplication
          7. Exploit chain analysis

        Returns:
            Findings sorted by CVSS descending.
        """
        self._start_time = time.time()
        self._print_banner()

        # Phase 1 — WAF detection
        self._phase("WAF Detection")
        waf = self.evasion.detect(self.target)
        self.waf_info = self.evasion.summary()
        self._ok(f"WAF: {waf.value}  (confidence {self.waf_info.get('confidence', 0):.1f}%)")

        # Phase 2 — Tech fingerprinting
        self._phase("Technology Fingerprinting")
        root_resp = self.http.get(self.target)
        if root_resp:
            self.technologies = TechFingerprinter.fingerprint(root_resp)
            self._ok(f"Stack: {', '.join(self.technologies) if self.technologies else 'undetected'}")

        parsed = urlparse(self.target)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # (url, method, params_or_None)
        targets: List[Tuple[str, str, Optional[Dict]]] = [(self.target, "GET", None)]

        # Phase 3 — Crawl
        if crawl:
            self._phase("Crawling + JS Analysis + Robots/Sitemap")
            crawler = Crawler(self.http, max_depth=max_depth, max_urls=max_urls, scope=self.scope)
            all_urls = crawler.crawl(self.target)
            self._crawled_urls = all_urls
            self._scan_stats["urls_crawled"] = len(all_urls)

            for url in crawler.get_param_urls(all_urls):
                targets.append((url, "GET", None))

            for action, method, params in crawler.get_form_targets():
                if method == "POST":
                    targets.append((action, "POST", params))
                else:
                    qs = urlencode({k: "FUZZ" for k in params})
                    targets.append((f"{action}?{qs}", "GET", None))

            self._ok(f"Discovered {len(all_urls)} URLs → {len(targets)} testable targets")

        # Phase 4 — API discovery
        if self.api_discovery:
            self._phase("API Path Discovery")
            discoverer = APIDiscoverer(self.http)
            api_urls = discoverer.discover(origin)
            existing = {t[0] for t in targets}
            for url in api_urls:
                if self.scope.in_scope(url) and url not in existing:
                    targets.append((url, "GET", None))

            graphql_url = origin + "/graphql"
            if any(t[0] == graphql_url for t in targets) or "GraphQL" in self.technologies:
                self.graphql_info = discoverer.graphql_introspection(graphql_url)
                if self.graphql_info:
                    self._ok(
                        f"GraphQL introspection open — "
                        f"{self.graphql_info['types_count']} types exposed"
                    )
                    sev, cvss, vector = classify_severity(VT.GRAPHQL)
                    self._add_finding(Finding(
                        vuln_type="GraphQL Introspection Exposed",
                        url=graphql_url,
                        parameter="-",
                        payload=_GRAPHQL_INTROSPECTION,
                        evidence=(
                            "Types: " +
                            ", ".join(self.graphql_info["types_sample"][:5])
                        ),
                        severity=sev,
                        cvss=cvss,
                        cvss_vector=vector,
                        exploitable=True,
                        confidence=0.95,
                        module="APIDiscovery",
                    ))

            self._ok(f"API discovery: {len(api_urls)} endpoints responded")

        # Phase 4b — Parameter fuzzing for parameterless endpoints
        self._phase("Parameter Fuzzing (SPA/API endpoint param discovery)")
        paramless = [t[0] for t in targets if "?" not in t[0] and t[0] != self.target]
        fuzzer = ParamFuzzer(self.http)
        existing_urls = {t[0] for t in targets}
        fuzz_added = 0
        for ep in paramless[:60]:
            for fuzz_url in fuzzer.fuzz(ep):
                if fuzz_url not in existing_urls:
                    targets.append((fuzz_url, "GET", None))
                    existing_urls.add(fuzz_url)
                    fuzz_added += 1
        self._ok(f"Parameter fuzzing added {fuzz_added} parameterized targets")

        # Phase 4c — Quick detection
        self._phase("Quick Detection (files, headers, CORS, redirects, traversal, IDOR)")
        qd = QuickDetector(self.http)
        param_urls_for_qd = [t[0] for t in targets if "?" in t[0]]
        for qdf in qd.check_all(self.target, param_urls_for_qd):
            if self._add_finding(qdf):
                self._vuln(qdf.severity, qdf.vuln_type, qdf.url, qdf.parameter, qdf.confidence)

        # Phase 5 — Host header injection
        if self.host_header_test:
            self._phase("Host Header Injection")
            hh = HostHeaderTester(self.http)
            hh_finding = hh.test(self.target)
            if hh_finding:
                self._add_finding(hh_finding)
                self._vuln(hh_finding.severity, hh_finding.vuln_type, self.target, "Host", hh_finding.confidence)
            else:
                self._ok("Not vulnerable")

        # Phase 6 — Smart-routed parallel module scan
        self._scan_stats["targets_tested"] = len(targets)
        active_names = {SmartRouter._canonical(m) for m in modules}
        jobs = SmartRouter.build_jobs(targets, modules, active_names, technologies=frozenset(self.technologies))
        total_jobs = len(jobs)
        naive_jobs = len(targets) * len(modules)
        skipped    = naive_jobs - total_jobs

        self._phase(
            f"Smart scan: {len(targets)} target(s) × {len(modules)} module(s) "
            f"→ {total_jobs} relevant jobs  ({skipped} skipped by router)"
        )

        progress = ProgressTracker(total_jobs)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._run_module, mod, url, method, params): (mod.__class__.__name__, url)
                for mod, url, method, params in jobs
            }
            for future in as_completed(futures):
                mod_name, url = futures[future]
                try:
                    new_findings = future.result(timeout=300)
                    for f in new_findings:
                        self._scan_stats["findings_raw"] += 1
                        if self._add_finding(f):
                            self._vuln(f.severity, f.vuln_type, url, f.parameter, f.confidence)
                except Exception as exc:
                    self._warn(f"{mod_name} @ {url}: {exc}")
                finally:
                    progress.increment()

        # Phase 7 — Chain analysis
        self._phase("Exploit Chain Analysis")
        self.chains = analyse_chains(self.findings)
        for chain in self.chains:
            self._chain(chain["chain"], chain["severity"])

        self._scan_stats["modules_run"] = len(modules)
        self._print_summary()

        return sorted(self.findings, key=lambda f: f.cvss, reverse=True)

    def generate_report(self, output_file: str = "report.json") -> str:
        """Write findings to file — format selected from extension (.json/.md/.html)."""
        ext = output_file.rsplit(".", 1)[-1].lower()
        content = {
            "json": self._render_json,
            "md": self._render_markdown,
            "markdown": self._render_markdown,
            "html": self._render_html,
        }.get(ext, self._render_json)()

        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(content)

        self._ok(f"Report saved → {output_file}")
        return output_file

    # ------------------------------------------------------------------
    # Module runner
    # ------------------------------------------------------------------

    def _run_module(
        self,
        module,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        try:
            if method == "POST" and params is not None:
                raw_results = module.scan(url, method="POST", data=params)
            else:
                raw_results = module.scan(url)
        except TypeError as exc:
            logger.debug(
                "_run_module: %s does not accept method/data kwargs (%s) — retrying GET-only",
                module.__class__.__name__, exc,
            )
            try:
                raw_results = module.scan(url)
            except Exception:
                return findings
        except Exception:
            return findings

        mod_name = module.__class__.__name__.replace("Module", "")

        for raw in (raw_results or []):
            if hasattr(raw, "to_dict"):
                d = raw.to_dict()
            elif isinstance(raw, dict):
                d = raw
            else:
                continue

            vuln_type = d.get("type") or d.get("technique", "") or mod_name
            if hasattr(vuln_type, "value"):
                vuln_type = vuln_type.value

            # Prefer the explicit VT category code; fall back to vuln_type string
            # (which goes through the legacy regex rules in classify_severity).
            category = d.get("category", "")
            sev, cvss, vector = classify_severity(category if category else str(vuln_type))
            if sev == Severity.INFO and cvss == 2.0:
                fallback = _FALLBACK_SEV_MAP.get(d.get("severity", "").lower())
                if fallback:
                    sev, cvss, vector = fallback

            findings.append(Finding(
                vuln_type=str(vuln_type),
                url=d.get("url", url),
                parameter=d.get("parameter", d.get("param", "-")),
                payload=str(d.get("payload", ""))[:300],
                evidence=str(d.get("evidence", d.get("command_output_preview", "")))[:300],
                severity=sev,
                cvss=cvss,
                cvss_vector=vector,
                exploitable=bool(d.get("exploitable", True)),
                confidence=float(d.get("confidence", 0.5)),
                module=mod_name,
                category=category,
                raw=raw,
            ))

        return findings

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _add_finding(self, finding: Finding) -> bool:
        """Add finding if not already seen (by vuln_type + parameter + normalised_url)."""
        key = finding.dedup_key()
        with self._lock:
            if key in self._seen_findings:
                self._scan_stats["findings_deduplicated"] += 1
                return False
            self._seen_findings.add(key)
            self.findings.append(finding)
        return True

    # ------------------------------------------------------------------
    # Report renderers
    # ------------------------------------------------------------------

    def _render_json(self) -> str:
        elapsed = round(time.time() - self._start_time, 2)
        return json.dumps({
            "meta": {
                "target": self.target,
                "scan_date": datetime.now(timezone.utc).isoformat() + "Z",
                "duration_seconds": elapsed,
                "tool": "EREBUS",
                "waf": self.waf_info,
                "technologies": self.technologies,
                "graphql": self.graphql_info,
                "stats": self._scan_stats,
            },
            "summary": self._summary_dict(),
            "exploit_chains": self.chains,
            "findings": [f.to_dict() for f in self.findings],
        }, indent=2)

    def _render_markdown(self) -> str:
        lines = [
            "# EREBUS Scan Report",
            "",
            f"**Target:** {self.target}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**WAF:** {self.waf_info.get('product', 'N/A')}",
            f"**Stack:** {', '.join(self.technologies) or 'Unknown'}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        summary = self._summary_dict()
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            lines.append(f"| {sev} | {summary.get(sev, 0)} |")

        if self.chains:
            lines += ["", "## Exploit Chains", ""]
            for c in self.chains:
                refs = ", ".join(c.get("references", []))
                lines.append(f"- **{c['chain']}** [{c['severity']}] — {c['description']}")
                if refs:
                    lines.append(f"  - References: {refs}")

        lines += ["", "## Findings", ""]

        for i, f in enumerate(self.findings, 1):
            lines += [
                f"### {i}. {f.vuln_type} [{f.severity.value}]",
                "",
                f"- **URL:** `{f.url}`",
                f"- **Parameter:** `{f.parameter}`",
                f"- **CVSS:** {f.cvss} | `{f.cvss_vector}`",
                f"- **Confidence:** {f.confidence:.0%}",
                f"- **Exploitable:** {'Yes' if f.exploitable else 'No'}",
                f"- **Payload:** `{f.payload[:120]}`",
                f"- **Evidence:** `{f.evidence[:120]}`",
                "",
            ]

        return "\n".join(lines)

    # One-line remediation hint per VT category code.
    _REMEDIATION: Dict[str, str] = {
        "sql_injection":           "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
        "nosql_injection":         "Validate input types. Whitelist allowed MongoDB operators; reject $where and operator keys from user input.",
        "ssti":                    "Never pass user-supplied strings to a template engine. Use sandboxed rendering or a static template with typed parameters.",
        "command_injection":       "Avoid shell execution entirely. If unavoidable, use subprocess with a list (no shell=True) and strict input validation.",
        "rce":                     "Patch the vulnerable component. Remove or restrict the endpoint. Apply least-privilege to the server process.",
        "deserialization":         "Avoid deserializing untrusted data. Use safe formats (JSON). Implement a deserialization allowlist.",
        "lfi":                     "Validate file paths against a whitelist. Use realpath() and ensure the result stays within an allowed base directory.",
        "rfi":                     "Disable allow_url_include in PHP. Validate and whitelist any path used in includes.",
        "prototype_pollution":     "Freeze Object.prototype. Reject __proto__ and constructor keys in JSON input. Use Object.create(null) for maps.",
        "xss_stored":              "HTML-encode all user-supplied output. Implement a strict Content-Security-Policy with no 'unsafe-inline'.",
        "xss":                     "HTML-encode output at the point of rendering. Use CSP and avoid eval/innerHTML with user data.",
        "xxe":                     "Disable external entity processing (FEATURE_EXTERNAL_GENERAL_ENTITIES = false). Use a safe XML library default.",
        "ssrf":                    "Validate and whitelist outbound URLs. Block requests to 169.254.x.x, 10.x.x.x, and ::1 at the network level.",
        "csrf":                    "Use Synchronizer Token Pattern or SameSite=Strict cookies. Verify Origin/Referer on state-changing requests.",
        "jwt_weak":                "Use strong random secrets (≥256 bits). Reject 'alg: none'. Validate iss, aud, exp on every request.",
        "default_creds":           "Change all default credentials. Enforce a strong password policy and MFA on admin interfaces.",
        "weak_password_reset":     "Use time-limited, single-use, cryptographically random reset tokens. Rate-limit and lock after failed attempts.",
        "mass_assignment":         "Explicitly allowlist accepted fields in each endpoint. Never bind the full request body to a model.",
        "auth_state_exposure":     "Require authentication before returning any user state. Return 401 for unauthenticated requests.",
        "broken_auth":             "Implement proper session management, MFA, and rate limiting on authentication endpoints.",
        "broken_access_control":   "Deny by default. Enforce server-side authorization on every resource — do not rely on client-supplied roles.",
        "idor":                    "Enforce object-level authorization. Use indirect references (UUIDs mapped server-side) instead of sequential IDs.",
        "http_method_override":    "Ignore X-HTTP-Method-Override unless strictly required. Apply the same authorization checks to overridden methods.",
        "parameter_pollution":     "Parse and validate query parameters strictly. Reject duplicate parameter keys or resolve them deterministically.",
        "missing_security_header": "Add the missing response header in the web server or application middleware configuration.",
        "cors_credentialed":       "Never reflect arbitrary Origin with Access-Control-Allow-Credentials: true. Whitelist trusted origins explicitly.",
        "cors_wildcard":           "Replace the wildcard origin with a specific trusted domain if credentials are involved.",
        "csp_misconfig":           "Tighten the Content-Security-Policy: remove 'unsafe-inline', 'unsafe-eval', and wildcard source directives.",
        "insecure_cookie":         "Set Secure, HttpOnly, and SameSite=Strict flags on all session and authentication cookies.",
        "clickjacking":            "Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors none'.",
        "rate_limiting":           "Implement rate limiting and account lockout on login, registration, and password-reset endpoints.",
        "dangerous_http_method":   "Disable unused HTTP methods (PUT, DELETE, CONNECT) in the web server configuration.",
        "http_trace":              "Disable the TRACE method: 'TraceEnable off' (Apache) or 'deny_method TRACE' (nginx).",
        "security_misconfig":      "Harden server configuration: remove default pages, disable unnecessary features, apply least-privilege.",
        "debug_endpoint":          "Remove or restrict access to debug/monitoring endpoints in production. Require authentication at minimum.",
        "vulnerable_component":    "Update the component to the patched version. Subscribe to the vendor's security advisories.",
        "component_version_disc":  "Remove version strings from HTTP headers and error pages to reduce fingerprinting surface.",
        "sensitive_file":          "Remove or deny access to the exposed file via web server rules. Add it to .gitignore.",
        "crypto_key_exposure":     "Remove cryptographic key files from the web root. Rotate the exposed keys immediately.",
        "password_hash_leak":      "Strip password/hash fields from API responses. Apply field-level serialization filters.",
        "sensitive_data_api":      "Remove sensitive fields (passwords, tokens, PII) from API responses. Use response DTOs.",
        "sensitive_data_js":       "Move secrets to server-side configuration. Never embed credentials or keys in client-side JavaScript.",
        "leaked_api_key":          "Revoke the exposed key immediately. Store API keys in environment variables or a secrets manager.",
        "crypto_issue_weak_hash":  "Replace MD5/SHA1 password hashing with bcrypt, scrypt, or Argon2 with an appropriate cost factor.",
        "crypto_issue":            "Review the cryptographic implementation. Use well-tested libraries and avoid custom crypto.",
        "info_disclosure_stack":   "Disable detailed error output in production. Return generic error pages and log details server-side only.",
        "info_disclosure":         "Remove internal path, version, and stack information from responses and error pages.",
        "open_redirect":           "Validate redirect destinations against an allowlist of trusted URLs. Reject absolute URLs from user input.",
        "host_header":             "Validate the Host header against a whitelist of known hostnames. Use absolute URLs from configuration.",
        "graphql":                 "Disable introspection in production. Implement query depth/complexity limits and field-level authorization.",
    }

    def _render_html(self) -> str:
        _SEV_COLORS = {
            "Critical":      "#dc2626",
            "High":          "#ea580c",
            "Medium":        "#d97706",
            "Low":           "#65a30d",
            "Informational": "#6b7280",
        }

        import html as _html

        rows = ""
        for i, f in enumerate(self.findings):
            color      = _SEV_COLORS.get(f.severity.value, "#6b7280")
            sev_val    = f.severity.value
            exploitable_badge = (
                "<span style='color:#22c55e;font-weight:bold'>Yes</span>"
                if f.exploitable else
                "<span style='color:#6b7280'>No</span>"
            )
            evidence_s = _html.escape(str(f.evidence or ""))[:600]
            payload_s  = _html.escape(str(f.payload  or ""))[:400]
            url_esc    = _html.escape(f.url)
            url_short  = _html.escape(f.url[:80]) + ("…" if len(f.url) > 80 else "")
            remediation = _html.escape(
                self._REMEDIATION.get(f.category, "Review and remediate according to OWASP guidelines.")
            )

            detail_parts = []
            if evidence_s:
                detail_parts.append(
                    f"<div><span class='dlabel'>Evidence</span>"
                    f"<code class='dval'>{evidence_s}</code></div>"
                )
            if payload_s:
                detail_parts.append(
                    f"<div><span class='dlabel'>Payload</span>"
                    f"<span class='copy-wrap'>"
                    f"<code class='dval' id='p{i}'>{payload_s}</code>"
                    f"<button class='copy-btn' onclick='copyPayload({i},event)'>Copy</button>"
                    f"</span></div>"
                )
            detail_parts.append(
                f"<div><span class='dlabel'>Remediation</span>"
                f"<span style='color:#86efac'>{remediation}</span></div>"
            )
            detail_inner = "\n".join(detail_parts)

            rows += (
                f"<tr class='finding-row' data-sev='{sev_val}' onclick='toggle({i})' title='Click to expand'>"
                f"<td><span style='color:{color};font-weight:bold'>{sev_val}</span></td>"
                f"<td><code style='font-size:0.8em'>{_html.escape(f.module)}</code></td>"
                f"<td>{_html.escape(f.vuln_type)}</td>"
                f"<td>{f.cvss:.1f}<br><small>{_html.escape(f.cvss_vector)}</small></td>"
                f"<td><code>{_html.escape(f.parameter)}</code></td>"
                f"<td><small><a href='{url_esc}' target='_blank' onclick='event.stopPropagation()'"
                f" style='color:#60a5fa'>{url_short}</a></small></td>"
                f"<td>{f.confidence:.0%}</td>"
                f"<td>{exploitable_badge}</td>"
                f"</tr>\n"
                f"<tr class='detail-row' id='d{i}' data-sev='{sev_val}'>"
                f"<td colspan='8' class='detail-cell'>{detail_inner}</td>"
                f"</tr>\n"
            )

        summary_cells = ""
        summary = self._summary_dict()
        for sev, color in _SEV_COLORS.items():
            n = summary.get(sev, 0)
            summary_cells += (
                f"<div class='sumcard' style='background:{color}' onclick='filterSev(\"{sev}\")'>"
                f"<div style='font-size:2em;font-weight:bold'>{n}</div>"
                f"<div>{sev}</div></div>\n"
            )

        chains_html = ""
        for c in self.chains:
            refs = ", ".join(c.get("references", []))
            chains_html += (
                f"<li><strong>{_html.escape(c['chain'])}</strong> [{_html.escape(c['severity'])}]"
                f" — {_html.escape(c['description'])}"
                + (f"<br><small>{_html.escape(refs)}</small>" if refs else "")
                + "</li>"
            )

        stack     = _html.escape(", ".join(self.technologies) or "Unknown")
        waf       = _html.escape(self.waf_info.get("product", "N/A"))
        target_e  = _html.escape(self.target)
        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        total     = len(self.findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>EREBUS Report — {target_e}</title>
<style>
  *{{box-sizing:border-box}}
  body{{font-family:monospace;background:#0d0d0d;color:#e2e8f0;padding:24px;max-width:1400px;margin:0 auto}}
  h1{{color:#ef4444;margin-bottom:4px}}
  h2{{color:#f97316;border-bottom:1px solid #333;padding-bottom:4px;margin-top:28px}}
  table{{width:100%;border-collapse:collapse;margin:10px 0}}
  th{{background:#1e1e2e;padding:8px 10px;text-align:left;white-space:nowrap;font-size:0.85em;color:#94a3b8}}
  td{{padding:6px 10px;border-bottom:1px solid #1e1e2e;vertical-align:top;font-size:0.9em}}
  .summary{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:12px 0}}
  .sumcard{{color:#fff;padding:14px;border-radius:8px;text-align:center;cursor:pointer;transition:opacity .15s}}
  .sumcard:hover{{opacity:.8}}
  .sumcard.active{{outline:2px solid #fff}}
  code{{background:#1e1e2e;padding:2px 5px;border-radius:3px;font-size:0.85em}}
  ul{{list-style:disc;padding-left:20px}}
  small{{font-size:0.78em;color:#9ca3af}}
  a{{text-decoration:none}}
  a:hover{{text-decoration:underline}}
  .finding-row{{cursor:pointer}}
  .finding-row:hover td{{background:#141420}}
  .detail-row{{display:none}}
  .detail-row.open{{display:table-row}}
  .detail-cell{{padding:12px 24px!important;background:#080810;border-left:3px solid #334155}}
  .detail-cell > div{{margin-bottom:8px}}
  .dlabel{{color:#64748b;display:inline-block;width:110px;flex-shrink:0;font-size:0.82em;text-transform:uppercase;letter-spacing:.04em}}
  .dval{{white-space:pre-wrap;word-break:break-all;display:inline}}
  .copy-wrap{{display:inline}}
  .copy-btn{{margin-left:8px;padding:1px 8px;background:#1e3a5f;color:#93c5fd;border:1px solid #1d4ed8;border-radius:4px;cursor:pointer;font-size:0.78em;font-family:monospace}}
  .copy-btn:hover{{background:#1d4ed8}}
  .filters{{display:flex;gap:8px;align-items:center;margin:10px 0 4px}}
  .filter-btn{{padding:3px 12px;border-radius:4px;border:1px solid #374151;background:#1e1e2e;color:#e2e8f0;cursor:pointer;font-family:monospace;font-size:0.82em}}
  .filter-btn:hover{{background:#374151}}
  .filter-btn.active{{background:#374151;border-color:#6b7280}}
  .hidden-row{{display:none!important}}
</style>
<script>
  var _activeSev = null;

  function toggle(i) {{
    var r = document.getElementById('d'+i);
    r.classList.toggle('open');
  }}

  function copyPayload(i, e) {{
    e.stopPropagation();
    var el = document.getElementById('p'+i);
    navigator.clipboard.writeText(el.innerText).then(function() {{
      var btn = e.target;
      btn.textContent = 'Copied!';
      setTimeout(function(){{btn.textContent='Copy';}}, 1500);
    }});
  }}

  function filterSev(sev) {{
    var cards = document.querySelectorAll('.sumcard');
    cards.forEach(function(c){{c.classList.remove('active');}});
    if (_activeSev === sev) {{
      _activeSev = null;
      showAll();
      return;
    }}
    _activeSev = sev;
    event.currentTarget.classList.add('active');
    var rows = document.querySelectorAll('.finding-row, .detail-row');
    rows.forEach(function(r) {{
      if (r.dataset.sev === sev) {{
        r.classList.remove('hidden-row');
      }} else {{
        r.classList.add('hidden-row');
        r.classList.remove('open');
      }}
    }});
    updateCounter();
  }}

  function showAll() {{
    document.querySelectorAll('.finding-row, .detail-row').forEach(function(r){{
      r.classList.remove('hidden-row');
    }});
    updateCounter();
  }}

  function resetFilter() {{
    _activeSev = null;
    document.querySelectorAll('.sumcard').forEach(function(c){{c.classList.remove('active');}});
    showAll();
  }}

  function updateCounter() {{
    var visible = document.querySelectorAll('.finding-row:not(.hidden-row)').length;
    document.getElementById('finding-count').textContent = visible + ' finding(s) shown';
  }}
</script>
</head>
<body>
<h1>&#x1F6A8; EREBUS Scan Report</h1>
<p style="color:#94a3b8">
  Target: <code><a href="{target_e}" target="_blank" style="color:#60a5fa">{target_e}</a></code>
  &nbsp;|&nbsp; Date: {scan_date} &nbsp;|&nbsp; WAF: {waf} &nbsp;|&nbsp; Stack: {stack}
  &nbsp;|&nbsp; <strong style="color:#e2e8f0">{total}</strong> finding(s)
</p>
<h2>Summary</h2>
<p style="font-size:0.82em;color:#64748b">Click a severity card to filter the findings table.</p>
<div class="summary">{summary_cells}</div>
<h2>Exploit Chains</h2>
<ul>{chains_html or "<li>None identified</li>"}</ul>
<h2>Findings</h2>
<div class="filters">
  <button class="filter-btn" onclick="resetFilter()">Show all</button>
  <span id="finding-count" style="color:#64748b;font-size:0.82em">{total} finding(s) shown</span>
</div>
<table>
<tr>
  <th>Severity</th><th>Module</th><th>Type</th><th>CVSS</th>
  <th>Parameter</th><th>URL</th><th>Conf</th><th>Exploitable</th>
</tr>
{rows}
</table>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Terminal helpers
    # ------------------------------------------------------------------

    def _summary_dict(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.severity.value] += 1
        return dict(counts)

    def _print_banner(self) -> None:
        print(f"\n{Fore.RED}{'═' * 66}{Style.RESET_ALL}")
        print(f"{Fore.RED}  EREBUS SCAN ENGINE{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 66}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Target : {self.target}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Date   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}{Style.RESET_ALL}")
        print()

    def _phase(self, name: str) -> None:
        print(f"\n{Fore.CYAN}[*] {name}...{Style.RESET_ALL}")

    def _ok(self, msg: str) -> None:
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

    def _warn(self, msg: str) -> None:
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

    def _vuln(self, severity: Severity, vuln_type: str, url: str, param: str, conf: float) -> None:
        color = {
            Severity.CRITICAL: Fore.RED,
            Severity.HIGH:     Fore.YELLOW,
            Severity.MEDIUM:   Fore.YELLOW,
            Severity.LOW:      Fore.WHITE,
            Severity.INFO:     Fore.CYAN,
        }.get(severity, Fore.WHITE)
        short_url = url if len(url) <= 52 else url[:49] + "..."
        print(
            f"\n{color}[VULN] {severity.value:8s}  {vuln_type:<26s}  "
            f"param={param!r:<14s}  conf={conf:.0%}  {short_url}{Style.RESET_ALL}"
        )

    def _chain(self, name: str, sev: str) -> None:
        print(f"{Fore.RED}  [chain] {sev}: {name}{Style.RESET_ALL}")

    def _print_summary(self) -> None:
        elapsed = time.time() - self._start_time
        summary = self._summary_dict()
        total = sum(summary.values())

        print(f"\n{Fore.RED}{'═' * 66}{Style.RESET_ALL}")
        print(f"{Fore.RED}  SCAN COMPLETE  ({elapsed:.1f}s){Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 66}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Total findings   : {total}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Deduplicated     : {self._scan_stats['findings_deduplicated']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  URLs crawled     : {self._scan_stats['urls_crawled']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Targets tested   : {self._scan_stats['targets_tested']}{Style.RESET_ALL}")

        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            n = summary.get(sev, 0)
            if n:
                color = (
                    Fore.RED if sev == "Critical"
                    else Fore.YELLOW if sev in ("High", "Medium")
                    else Fore.WHITE
                )
                print(f"{color}  {sev:<17s}: {n}{Style.RESET_ALL}")

        if self.chains:
            print(f"\n{Fore.RED}  Exploit chains   : {len(self.chains)}{Style.RESET_ALL}")
            for c in self.chains:
                print(f"{Fore.RED}    → {c['chain']}{Style.RESET_ALL}")

        print()
