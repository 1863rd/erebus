"""
Advanced HTTP Engine for Offensive Security Operations
Professional-grade client with enterprise features
"""

import base64
import json
import hashlib
import os
import random
import socket
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import logging
logger = logging.getLogger(__name__)


class DNSResolver:
    def __init__(self, cache_ttl=3600, max_cache_size=10000):
        self._cache = {}
        self._ttl = cache_ttl
        self._max_size = max_cache_size
        self._lock = threading.RLock()
        self._custom_dns = {}
        
    def resolve(self, hostname: str) -> Optional[str]:
        with self._lock:
            if hostname in self._custom_dns:
                return self._custom_dns[hostname]
            
            if hostname in self._cache:
                ip, timestamp = self._cache[hostname]
                if time.time() - timestamp < self._ttl:
                    return ip
                del self._cache[hostname]
            
            try:
                ip = socket.gethostbyname(hostname)
                
                if len(self._cache) >= self._max_size:
                    oldest = min(self._cache.items(), key=lambda x: x[1][1])
                    del self._cache[oldest[0]]
                
                self._cache[hostname] = (ip, time.time())
                return ip
            except socket.gaierror:
                return None
    
    def set_custom_dns(self, hostname: str, ip: str):
        with self._lock:
            self._custom_dns[hostname] = ip
    
    def flush(self):
        with self._lock:
            self._cache.clear()


class AdaptiveRateLimiter:
    def __init__(self, initial_rate=50, min_rate=1, max_rate=500):
        self._rate = initial_rate
        self._min_rate = min_rate
        self._max_rate = max_rate
        self._tokens = initial_rate
        self._last_update = time.time()
        self._lock = threading.Lock()
        self._failure_count = 0
        self._success_count = 0
        self._last_adjustment = time.time()
        
    def acquire(self, tokens=1, blocking=True) -> bool:
        while True:
            with self._lock:
                now = time.time()
                elapsed = now - self._last_update
                self._tokens = min(self._rate * 2, self._tokens + elapsed * self._rate)
                self._last_update = now
                
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
                
                if not blocking:
                    return False
            
            time.sleep(0.01)
    
    def record_failure(self):
        with self._lock:
            self._failure_count += 1
            if self._failure_count >= 5:
                self._adjust_rate(0.7)
                self._failure_count = 0
    
    def record_success(self):
        with self._lock:
            self._success_count += 1
            if self._success_count >= 50:
                self._adjust_rate(1.2)
                self._success_count = 0
    
    def _adjust_rate(self, factor: float):
        now = time.time()
        if now - self._last_adjustment < 5:
            return
        
        new_rate = self._rate * factor
        self._rate = max(self._min_rate, min(self._max_rate, new_rate))
        self._last_adjustment = now
        logger.debug(f"Rate adjusted to {self._rate:.2f} req/s")


class _CachedResponse:
    """Lightweight stand-in for requests.Response returned from the cache."""

    __slots__ = ("status_code", "headers", "text", "content", "url", "cookies")

    def __init__(self, status_code: int, headers: Dict, text: str,
                 content: bytes, url: str = "") -> None:
        self.status_code = status_code
        self.headers     = headers
        self.text        = text
        self.content     = content
        self.url         = url
        self.cookies: Dict = {}

    def json(self, **_) -> Any:
        return json.loads(self.text)

    def __bool__(self) -> bool:
        return True


class ResponseCache:
    def __init__(self, max_size=5000, ttl=300, enable_compression=True,
                 max_entry_bytes: int = 2 * 1024 * 1024):
        self._cache: Dict[str, Any] = {}
        self._max_size = max_size
        self._ttl = ttl
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._compression = enable_compression
        self._max_entry_bytes = max_entry_bytes

    def _make_key(self, method: str, url: str, data: Any = None) -> str:
        key_parts = [method, url]
        if data:
            key_parts.append(json.dumps(data, sort_keys=True) if isinstance(data, dict) else str(data))
        return hashlib.sha256('|'.join(key_parts).encode()).hexdigest()

    def _serialize(self, response: Any) -> Optional[str]:
        try:
            payload = json.dumps({
                "status_code": response.status_code,
                "headers":     dict(response.headers),
                "text":        response.text,
                "content":     base64.b64encode(response.content).decode(),
                "url":         getattr(response, "url", "") or "",
            })
            if self._compression:
                import zlib
                return base64.b64encode(zlib.compress(payload.encode())).decode()
            return payload
        except Exception:
            return None

    def _deserialize(self, raw: str) -> Optional[_CachedResponse]:
        try:
            if self._compression:
                import zlib
                data = json.loads(zlib.decompress(base64.b64decode(raw)))
            else:
                data = json.loads(raw)
            return _CachedResponse(
                status_code=data["status_code"],
                headers=data["headers"],
                text=data["text"],
                content=base64.b64decode(data["content"]),
                url=data.get("url", ""),
            )
        except Exception:
            return None

    def get(self, method: str, url: str, data: Any = None) -> Optional[_CachedResponse]:
        key = self._make_key(method, url, data)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            raw, timestamp, access_count = entry
            if time.time() - timestamp > self._ttl:
                del self._cache[key]
                self._misses += 1
                return None
            self._cache[key] = (raw, timestamp, access_count + 1)
            self._hits += 1
        return self._deserialize(raw)

    def set(self, method: str, url: str, response: Any, data: Any = None) -> None:
        try:
            if len(response.content) > self._max_entry_bytes:
                return
        except Exception:
            pass
        serialized = self._serialize(response)
        if serialized is None:
            return
        key = self._make_key(method, url, data)
        with self._lock:
            if len(self._cache) >= self._max_size:
                lru_key = min(self._cache, key=lambda k: self._cache[k][2])
                del self._cache[lru_key]
            self._cache[key] = (serialized, time.time(), 0)

    def get_stats(self) -> Dict:
        with self._lock:
            total = self._hits + self._misses
            return {
                'size':     len(self._cache),
                'hits':     self._hits,
                'misses':   self._misses,
                'hit_rate': (self._hits / total * 100) if total else 0.0,
            }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


class CircuitBreaker:
    def __init__(self, failure_threshold=10, recovery_timeout=60, half_open_max_calls=3):
        self._states = {}
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._half_open_max = half_open_max_calls
        self._lock = threading.RLock()
        
    def _get_state(self, host: str) -> Dict:
        if host not in self._states:
            self._states[host] = {
                'failures': 0,
                'state': 'closed',
                'last_failure': 0,
                'half_open_calls': 0
            }
        return self._states[host]
    
    def can_proceed(self, host: str) -> bool:
        with self._lock:
            state = self._get_state(host)
            
            if state['state'] == 'closed':
                return True
            
            if state['state'] == 'open':
                if time.time() - state['last_failure'] > self._recovery_timeout:
                    state['state'] = 'half_open'
                    state['half_open_calls'] = 0
                    return True
                return False
            
            if state['state'] == 'half_open':
                if state['half_open_calls'] < self._half_open_max:
                    state['half_open_calls'] += 1
                    return True
                return False
            
            return True
    
    def record_success(self, host: str):
        with self._lock:
            state = self._get_state(host)
            
            if state['state'] == 'half_open':
                state['state'] = 'closed'
                state['failures'] = 0
            elif state['state'] == 'closed':
                state['failures'] = max(0, state['failures'] - 1)
    
    def record_failure(self, host: str):
        with self._lock:
            state = self._get_state(host)
            state['failures'] += 1
            state['last_failure'] = time.time()
            
            if state['failures'] >= self._failure_threshold:
                state['state'] = 'open'
            elif state['state'] == 'half_open':
                state['state'] = 'open'


class RequestMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._total = 0
        self._success = 0
        self._failed = 0
        self._bytes_sent = 0
        self._bytes_recv = 0
        self._response_times = deque(maxlen=1000)
        self._status_codes = defaultdict(int)
        self._errors = defaultdict(int)
        self._start_time = time.time()
        
    def record(self, response: Optional[requests.Response], elapsed: float, 
              bytes_sent: int = 0, error: Optional[Exception] = None):
        with self._lock:
            self._total += 1
            self._bytes_sent += bytes_sent
            self._response_times.append(elapsed)
            
            if response:
                self._success += 1
                self._status_codes[response.status_code] += 1
                self._bytes_recv += len(response.content)
            else:
                self._failed += 1
                if error:
                    self._errors[type(error).__name__] += 1
    
    def snapshot(self) -> Dict:
        with self._lock:
            uptime = time.time() - self._start_time
            
            stats = {
                'total_requests': self._total,
                'successful': self._success,
                'failed': self._failed,
                'success_rate': (self._success / self._total * 100) if self._total > 0 else 0,
                'bytes_sent': self._bytes_sent,
                'bytes_received': self._bytes_recv,
                'uptime_seconds': uptime,
                'requests_per_second': self._total / uptime if uptime > 0 else 0,
                'status_codes': dict(self._status_codes),
                'errors': dict(self._errors)
            }
            
            if self._response_times:
                sorted_times = sorted(self._response_times)
                stats.update({
                    'avg_response_time': sum(self._response_times) / len(self._response_times),
                    'min_response_time': sorted_times[0],
                    'max_response_time': sorted_times[-1],
                    'p50_response_time': sorted_times[len(sorted_times) // 2],
                    'p95_response_time': sorted_times[int(len(sorted_times) * 0.95)],
                    'p99_response_time': sorted_times[int(len(sorted_times) * 0.99)]
                })
            
            return stats


class UserAgentRotator:
    AGENTS = {
        'chrome_win': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
        ],
        'firefox_win': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0'
        ],
        'chrome_mac': [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        ],
        'safari': [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15'
        ],
        'chrome_linux': [
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        ],
        'mobile_chrome': [
            'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.66 Mobile Safari/537.36'
        ],
        'mobile_safari': [
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'
        ]
    }
    
    def __init__(self, mode='random', preferred_category=None):
        self._mode = mode
        self._category = preferred_category
        self._last_agent = None
        self._rotate_idx = 0
        self._agent_pool = self._build_pool()
        
    def _build_pool(self) -> List[str]:
        if self._category and self._category in self.AGENTS:
            return self.AGENTS[self._category]
        
        pool = []
        for agents in self.AGENTS.values():
            pool.extend(agents)
        return pool
    
    def get(self) -> str:
        if self._mode == 'random':
            return random.choice(self._agent_pool)
        elif self._mode == 'rotate':
            ua = self._agent_pool[self._rotate_idx % len(self._agent_pool)]
            self._rotate_idx += 1
            return ua
        elif self._mode == 'sticky':
            if not self._last_agent:
                self._last_agent = random.choice(self._agent_pool)
            return self._last_agent
        return self._agent_pool[0]


class _PoolPressureHandler(logging.Handler):
    """Watches urllib3's connectionpool logger for pool-full warnings and fires a callback."""

    def __init__(self, callback):
        super().__init__(level=logging.WARNING)
        self._cb = callback

    def emit(self, record):
        try:
            if 'Connection pool is full' in record.getMessage():
                self._cb()
        except Exception:
            pass


class _ConcurrencyController:
    """Adaptive in-flight request limiter.

    Uses a condition variable to cap simultaneous requests at `_limit`.
    On each pool-pressure signal the ceiling drops by 25% (floor: _MIN).
    After _RECOVER_AFTER consecutive successful requests it grows back 15% toward
    the original value, waking any waiting threads.
    """
    _MIN = 4
    _PRESSURE_REDUCE = 0.75
    _RECOVER_FACTOR  = 1.15
    _RECOVER_AFTER   = 50

    def __init__(self, initial: int):
        self._initial         = initial
        self._limit           = initial
        self._active          = 0
        self._ok_since_reduce = 0
        self._cond            = threading.Condition(threading.Lock())

    def acquire(self, timeout: float = 60.0) -> bool:
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._active >= self._limit:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(timeout=min(remaining, 1.0))
            self._active += 1
            return True

    def release(self):
        with self._cond:
            self._active = max(0, self._active - 1)
            self._cond.notify_all()

    def signal_pressure(self):
        with self._cond:
            if self._limit > self._MIN:
                self._limit = max(self._MIN, int(self._limit * self._PRESSURE_REDUCE))
                self._ok_since_reduce = 0
                logger.warning("Pool pressure: concurrency ceiling reduced to %d", self._limit)

    def signal_server_stress(self):
        """Aggressive reduction used when the remote server closes connections (overwhelmed)."""
        with self._cond:
            if self._limit > self._MIN:
                self._limit = max(self._MIN, self._limit // 2)
                self._ok_since_reduce = 0
                self._cond.notify_all()
                logger.warning("Server stress: concurrency halved to %d", self._limit)

    def signal_success(self):
        with self._cond:
            self._ok_since_reduce += 1
            if self._ok_since_reduce >= self._RECOVER_AFTER and self._limit < self._initial:
                self._limit = min(self._initial, int(self._limit * self._RECOVER_FACTOR))
                self._ok_since_reduce = 0
                self._cond.notify_all()
                logger.info("Pool pressure eased: concurrency ceiling recovered to %d", self._limit)

    @property
    def limit(self) -> int:
        return self._limit


class HTTPEngine:
    def __init__(self,
                 proxy: Optional[str] = None,
                 proxy_list: Optional[List[str]] = None,
                 timeout: int = 15,
                 max_retries: int = 3,
                 pool_size: int = 200,
                 rate_limit: int = 100,
                 enable_cache: bool = True,
                 enable_metrics: bool = True,
                 stealth_mode: bool = False,
                 cookie_jar_file: Optional[str] = None,
                 user_agent_mode: str = 'random',
                 verify_ssl: bool = False,
                 follow_redirects: bool = True,
                 max_redirects: int = 10):
        
        self._proxy = {'http': proxy, 'https': proxy} if proxy else None
        self._proxy_list = proxy_list or []
        self._proxy_index = 0
        self._timeout = timeout
        self._max_retries = max_retries
        self._stealth = stealth_mode
        self._cookie_file = cookie_jar_file
        self._verify_ssl = verify_ssl
        self._follow_redirects = follow_redirects
        self._max_redirects = max_redirects
        
        self._dns_resolver = DNSResolver()
        self._rate_limiter = AdaptiveRateLimiter(initial_rate=rate_limit)
        self._circuit_breaker = CircuitBreaker()
        self._cache = ResponseCache() if enable_cache else None
        self._metrics = RequestMetrics() if enable_metrics else None
        self._ua_rotator = UserAgentRotator(mode=user_agent_mode)
        
        self._session = self._init_session(pool_size)
        self._executor = ThreadPoolExecutor(max_workers=min(pool_size, 40))

        self._concurrency = _ConcurrencyController(initial=pool_size)
        _ph = _PoolPressureHandler(self._concurrency.signal_pressure)
        logging.getLogger('urllib3.connectionpool').addHandler(_ph)

        self._disconnect_count = 0
        self._disconnect_lock  = threading.Lock()

        self._request_count = 0
        self._last_request = 0
        
        if cookie_jar_file and os.path.exists(cookie_jar_file):
            self._load_cookies()
        
        logger.info(f"HTTPEngine initialized (pool={pool_size}, rate={rate_limit}/s)")
    
    def _init_session(self, pool_size: int) -> requests.Session:
        session = requests.Session()
        
        retry = urllib3.util.Retry(
            total=self._max_retries,
            backoff_factor=0.3,
            # Only retry on infrastructure/proxy errors — 5xx application responses
            # (500, 507, 509) are intentional and must reach the caller for analysis.
            status_forcelist=[429, 502, 503, 504],
            allowed_methods=frozenset(['HEAD', 'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH'])
        )
        
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry,
            pool_connections=min(pool_size, 10),  # rarely hit >10 distinct hosts
            pool_maxsize=pool_size,               # matches concurrency ceiling exactly
            pool_block=True                       # wait for a free slot, never discard
        )
        
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.verify = self._verify_ssl
        
        return session

    @property
    def session(self) -> requests.Session:
        """Public accessor for the underlying requests.Session."""
        return self._session

    def _select_proxy(self) -> Optional[Dict]:
        if self._proxy:
            return self._proxy
        
        if self._proxy_list:
            proxy = self._proxy_list[self._proxy_index]
            self._proxy_index = (self._proxy_index + 1) % len(self._proxy_list)
            return {'http': proxy, 'https': proxy}
        
        return None
    
    def _construct_headers(self, custom: Optional[Dict] = None, referer: Optional[str] = None) -> Dict:
        ua = self._ua_rotator.get()
        
        headers = {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        
        if 'Chrome' in ua and 'Edg' not in ua and 'OPR' not in ua:
            headers.update({
                'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"'
            })
        
        if referer:
            headers['Referer'] = referer
        elif random.random() > 0.4:
            headers['Referer'] = random.choice([
                'https://www.google.com/',
                'https://www.bing.com/',
                'https://duckduckgo.com/'
            ])
        
        if random.random() > 0.8:
            headers['DNT'] = '1'
        
        if custom:
            headers.update(custom)
        
        return headers
    
    def _enforce_rate_limit(self):
        self._rate_limiter.acquire()
        
        if self._stealth:
            self._request_count += 1
            
            if self._request_count % 100 == 0:
                time.sleep(random.uniform(3, 7))
            elif self._request_count % 20 == 0:
                time.sleep(random.uniform(1, 2))
            elif self._request_count % 5 == 0:
                time.sleep(random.uniform(0.3, 0.8))
            else:
                time.sleep(random.uniform(0.05, 0.2))
    
    def _save_cookies(self) -> None:
        if not self._cookie_file:
            return
        try:
            cookies = {c.name: c.value for c in self._session.cookies}
            with open(self._cookie_file, 'w', encoding='utf-8') as f:
                json.dump(cookies, f)
        except Exception as e:
            logger.error("Cookie save failed: %s", e)

    def _load_cookies(self) -> None:
        if not self._cookie_file or not os.path.exists(self._cookie_file):
            return
        try:
            with open(self._cookie_file, 'r', encoding='utf-8') as f:
                cookies = json.load(f)
            if isinstance(cookies, dict):
                self._session.cookies.update(cookies)
        except (json.JSONDecodeError, TypeError, OSError) as e:
            logger.error("Cookie load failed: %s", e)
    
    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        parsed = urlparse(url)
        host = parsed.netloc
        
        if not self._circuit_breaker.can_proceed(host):
            return None
        
        if self._cache and method.upper() == 'GET':
            cached = self._cache.get(method, url, kwargs.get('data'))
            if cached:
                return cached
        
        self._enforce_rate_limit()

        if not self._concurrency.acquire(timeout=60.0):
            return None

        kwargs.setdefault('headers', self._construct_headers(kwargs.get('headers')))
        kwargs.setdefault('timeout', self._timeout)
        kwargs.setdefault('proxies', self._select_proxy())
        kwargs.setdefault('allow_redirects', self._follow_redirects)
        
        self._session.max_redirects = self._max_redirects
        
        start = time.time()
        response = None
        error = None
        
        try:
            response = self._session.request(method, url, **kwargs)
            self._circuit_breaker.record_success(host)
            self._rate_limiter.record_success()
            self._concurrency.signal_success()
            with self._disconnect_lock:
                self._disconnect_count = 0

            if self._cache and method.upper() == 'GET' and response.status_code == 200:
                self._cache.set(method, url, response, kwargs.get('data'))

            if self._cookie_file:
                self._save_cookies()

            return response

        except Exception as e:
            error = e
            self._circuit_breaker.record_failure(host)
            self._rate_limiter.record_failure()
            err_str = str(e)
            if any(s in err_str for s in ('RemoteDisconnected', 'ConnectionReset', 'Broken pipe', 'ConnectionAbortedError')):
                self._on_server_disconnect()
            return None

        finally:
            self._concurrency.release()
            if self._metrics:
                elapsed = time.time() - start
                bytes_sent = len(kwargs.get('data', b'')) if 'data' in kwargs else 0
                self._metrics.record(response, elapsed, bytes_sent, error)
    
    def _on_server_disconnect(self):
        with self._disconnect_lock:
            self._disconnect_count += 1
            if self._disconnect_count >= 3:
                self._concurrency.signal_server_stress()
                self._rate_limiter.record_failure()
                self._rate_limiter.record_failure()
                self._disconnect_count = 0
                time.sleep(random.uniform(1.5, 3.0))

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request('POST', url, **kwargs)
    
    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request('PUT', url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request('DELETE', url, **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request('HEAD', url, **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request('OPTIONS', url, **kwargs)
    
    def patch(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request('PATCH', url, **kwargs)
    
    def parallel_get(self, urls: List[str]) -> Dict[str, Optional[requests.Response]]:
        if not urls:
            return {}
        # Always use the shared, bounded executor.
        # _ConcurrencyController is the real concurrency limiter; max_workers is ignored.
        # This prevents throwaway ThreadPoolExecutors from spawning hundreds of threads
        # that all block on acquire() simultaneously.
        futures = {self._executor.submit(self.get, url): url for url in urls}
        results = {}
        for future in as_completed(futures):
            url = futures[future]
            try:
                results[url] = future.result()
            except Exception:
                results[url] = None
        return results
    
    def stats(self) -> Dict:
        stats = {}
        
        if self._metrics:
            stats['requests'] = self._metrics.snapshot()
        
        if self._cache:
            stats['cache'] = self._cache.get_stats()
        
        return stats
    
    def print_stats(self):
        stats = self.stats()
        
        if not stats:
            print("No statistics available")
            return
        
        print("\n" + "="*70)
        print("HTTP ENGINE STATISTICS")
        print("="*70)
        
        if 'requests' in stats:
            req = stats['requests']
            print(f"\nRequests:")
            print(f"  Total:              {req['total_requests']}")
            print(f"  Success:            {req['successful']} ({req['success_rate']:.1f}%)")
            print(f"  Failed:             {req['failed']}")
            print(f"  Rate:               {req['requests_per_second']:.2f} req/s")
            print(f"  Data Sent:          {req['bytes_sent'] / 1024:.2f} KB")
            print(f"  Data Received:      {req['bytes_received'] / 1024:.2f} KB")
            
            if 'avg_response_time' in req:
                print(f"\nResponse Times:")
                print(f"  Average:            {req['avg_response_time']:.3f}s")
                print(f"  Min:                {req['min_response_time']:.3f}s")
                print(f"  Max:                {req['max_response_time']:.3f}s")
                print(f"  P50:                {req['p50_response_time']:.3f}s")
                print(f"  P95:                {req['p95_response_time']:.3f}s")
                print(f"  P99:                {req['p99_response_time']:.3f}s")
            
            if req['status_codes']:
                print(f"\nStatus Codes:")
                for code, count in sorted(req['status_codes'].items()):
                    print(f"  {code}: {count}")
        
        if 'cache' in stats:
            cache = stats['cache']
            print(f"\nCache:")
            print(f"  Size:               {cache['size']}")
            print(f"  Hits:               {cache['hits']}")
            print(f"  Misses:             {cache['misses']}")
            print(f"  Hit Rate:           {cache['hit_rate']:.1f}%")
        
        print("="*70 + "\n")
    
    def clear_cache(self):
        if self._cache:
            self._cache.clear()

    def clear_cookies(self):
        self._session.cookies.clear()
        if self._cookie_file and os.path.exists(self._cookie_file):
            os.remove(self._cookie_file)

    def shutdown(self):
        if self._cookie_file:
            self._save_cookies()
        self._executor.shutdown(wait=False)
        self._session.close()