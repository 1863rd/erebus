"""Open Redirect detection module."""
import re
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Optional, Set

from core.vuln_types import VT
import logging

logger = logging.getLogger(__name__)

_CANARY = "https://evil.erebus-scanner.internal"


class OpenRedirectFinding:
    def __init__(self, vuln_type, url, parameter, payload, evidence,
                 severity="Medium", confidence=0.95, exploitable=True):
        self.vuln_type   = vuln_type
        self.url         = url
        self.parameter   = parameter
        self.payload     = payload
        self.evidence    = evidence
        self.severity    = severity
        self.confidence  = confidence
        self.exploitable = exploitable
        self.category    = VT.OPEN_REDIRECT

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


class OpenRedirectModule:
    """
    Detect open redirect vulnerabilities including HTTP redirects,
    meta refresh, and JavaScript-based redirects.
    """

    _REDIRECT_PARAMS: frozenset = frozenset({
        'redirect', 'url', 'next', 'return', 'returnurl', 'goto',
        'dest', 'destination', 'ref', 'redir', 'redirect_uri',
        'continue', 'forward', 'callback', 'target', 'link',
        'location', 'redirect_to', 'to', 'back',
    })

    _CANARY_HOST = "evil.erebus-scanner.internal"

    _PAYLOADS: List[str] = [
        _CANARY,
        f"//{_CANARY_HOST}",
        f"/{_CANARY_HOST}",
        f"\\\\{_CANARY_HOST}",
        f"@{_CANARY_HOST}",
        f"%2F%2F{_CANARY_HOST}",
        f"https:/{_CANARY_HOST}",
        f"http://{_CANARY_HOST}",
    ]

    _META_REFRESH_RE = re.compile(
        r'<meta[^>]+http-equiv[^>]*refresh[^>]*content\s*=\s*["\'][^"\']*url\s*=\s*([^"\'>\s]+)',
        re.I,
    )
    _JS_REDIRECT_RE = re.compile(
        r'(?:window\.location|location\.href|location\.replace)\s*[=(]\s*["\']([^"\']+)["\']',
        re.I,
    )

    def __init__(self, http_engine, evasion_engine=None):
        self.http    = http_engine
        self.evasion = evasion_engine
        self._seen: Set[tuple] = set()

    def scan(self, url: str, method: str = "GET", data: Optional[Dict] = None) -> List[OpenRedirectFinding]:
        results: List[OpenRedirectFinding] = []

        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)
        params = {k: v[0] for k, v in qs.items()}

        if method == "POST" and data:
            params.update(data)

        for param in params:
            if param.lower() not in self._REDIRECT_PARAMS:
                continue

            key = (url, param)
            if key in self._seen:
                continue
            self._seen.add(key)

            finding = self._probe(url, param, params)
            if finding:
                results.append(finding)

        return results

    def _probe(self, url: str, param: str, params: Dict) -> Optional[OpenRedirectFinding]:
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload in self._PAYLOADS:
            try:
                test_params        = dict(params)
                test_params[param] = payload
                test_url           = f"{base}?{urlencode(test_params)}"

                resp = self.http.get(test_url, allow_redirects=False)
                if not resp:
                    continue

                # HTTP-level redirect
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if self._CANARY_HOST in loc:
                        return OpenRedirectFinding(
                            vuln_type="Open Redirect",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"HTTP {resp.status_code} → Location: {loc}",
                            severity="Medium",
                            confidence=0.97,
                            exploitable=True,
                        )

                # Meta refresh in body
                m = self._META_REFRESH_RE.search(resp.text)
                if m and self._CANARY_HOST in m.group(1):
                    return OpenRedirectFinding(
                        vuln_type="Open Redirect (Meta Refresh)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"<meta refresh> → {m.group(1)[:120]}",
                        severity="Medium",
                        confidence=0.90,
                        exploitable=True,
                    )

                # JavaScript redirect in body
                m = self._JS_REDIRECT_RE.search(resp.text)
                if m and self._CANARY_HOST in m.group(1):
                    return OpenRedirectFinding(
                        vuln_type="Open Redirect (JavaScript)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"JS redirect → {m.group(1)[:120]}",
                        severity="Medium",
                        confidence=0.88,
                        exploitable=True,
                    )

            except Exception:
                pass

        return None
