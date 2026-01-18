from __future__ import annotations

"""SSH host key resolver plugin.

Brief:
  - Periodically or at startup, fetch SSH host keys for a configured set of
    IPs, CIDR ranges, and hostnames using ``foghorn.utils.ssh_keys``.
  - Store discovered keys in a small sqlite database keyed by subject
    (hostname or IP).
  - Answer SSHFP pre_resolve queries from the database when a matching
    subject is present.
"""

import concurrent.futures
import hashlib
import ipaddress
import logging
import os
import socket
import sqlite3
import threading
import time
from typing import Iterable, List, Optional, Sequence, Tuple

from dnslib import QTYPE, RR, DNSHeader, DNSRecord
from pydantic import BaseModel, Field

from foghorn.plugins.resolve.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)
from foghorn.utils.ssh_keys import fetch_ssh_host_key_hex

logger = logging.getLogger(__name__)


class SshKeysConfig(BaseModel):
    """Brief: Typed configuration model for SshKeys.

    Inputs:
      - targets: List of IPs, CIDR ranges, and/or hostnames to scan.
      - scan_threads: Maximum number of concurrent SSH probes.
      - ttl: DNS TTL to apply to synthesized SSHFP answers.
      - db_path: Filesystem path to the sqlite database storing SSH keys.
      - port: SSH TCP port used when probing hosts.
      - timeout_seconds: Socket/handshake timeout when fetching keys.

    Outputs:
      - SshKeysConfig instance with normalized field types.
    """

    targets: List[str] = Field(default_factory=list)
    scan_threads: int = Field(default=4, ge=1)
    ttl: int = Field(default=300, ge=0)
    db_path: str = Field(default="./config/var/ssh_keys.db")
    port: int = Field(default=22, ge=1, le=65535)
    timeout_seconds: float = Field(default=5.0, ge=0.1)

    class Config:
        extra = "allow"


@plugin_aliases("ssh_keys")
class SshKeys(BasePlugin):
    """Brief: Resolve SSHFP records from a local sqlite-backed SSH host key cache.

    Behaviour:
      - On setup(), walk configured targets (IPs, CIDRs, hostnames) and
        populate a sqlite database with SSH host keys fetched via
        ``fetch_ssh_host_key_hex``.
      - For each probed subject, attempt to discover both hostname and IP and
        store entries for both when available.
      - During pre_resolve(), answer SSHFP queries whose qname matches a
        cached subject by synthesizing SSHFP RRs with SHA-1 and SHA-256
        fingerprints derived from the stored public key.
    """

    # Restrict this plugin to SSHFP by default.
    target_qtypes: Sequence[str] = ("SSHFP",)

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - SshKeysConfig class for use by the core config loader.
        """

        return SshKeysConfig

    def __init__(self, **config: object) -> None:
        """Brief: Initialize SshKeys plugin and normalize configuration.

        Inputs:
          - **config: Arbitrary keyword configuration compatible with
            ``SshKeysConfig``.

        Outputs:
          - None; prepares database path and scan parameters but does not
            touch the network until ``setup()`` runs.
        """

        super().__init__(**config)

        cfg = SshKeysConfig(**(self.config or {}))
        self._targets: List[str] = list(cfg.targets or [])
        self._scan_threads: int = int(cfg.scan_threads)
        self._ttl: int = int(cfg.ttl)
        self._db_path: str = str(cfg.db_path)
        self._port: int = int(cfg.port)
        self._timeout: float = float(cfg.timeout_seconds)

        self._db_lock: threading.RLock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None

    # ---------------------- setup and database helpers ----------------------

    def setup(self) -> None:
        """Brief: Initialize sqlite database and perform initial SSH key scan.

        Inputs:
          - None (uses configuration stored on the instance).

        Outputs:
          - None; creates the sqlite database on disk when needed, ensures the
            schema exists, and performs a best-effort scan of configured
            targets using up to ``scan_threads`` worker threads.
        """

        self._init_db()

        # Empty target list is allowed and results in a no-op scan.
        if not self._targets:
            return

        self._run_initial_scan(self._targets)

    def _init_db(self) -> None:
        """Brief: Create sqlite connection and ensure ssh_keys table exists.

        Inputs:
          - None (uses self._db_path).

        Outputs:
          - None; populates self._conn with an open sqlite3.Connection and
            creates the required table and index if they do not already exist.
        """

        db_path = os.path.abspath(os.path.expanduser(self._db_path))
        dir_path = os.path.dirname(db_path) or "."
        try:
            os.makedirs(dir_path, exist_ok=True)
        except (
            Exception
        ):  # pragma: no cover - defensive; directory creation best-effort
            logger.warning("SshKeys: failed to create directory %s", dir_path)

        conn = sqlite3.connect(db_path, check_same_thread=False)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception:  # pragma: no cover - environment-specific
            pass

        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ssh_keys (
                    subject    TEXT PRIMARY KEY,
                    hostname   TEXT,
                    ip         TEXT,
                    port       INTEGER NOT NULL,
                    key_type   TEXT NOT NULL,
                    key_hex    TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen  REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ssh_keys_hostname ON ssh_keys(hostname)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ssh_keys_ip ON ssh_keys(ip)")

        self._conn = conn

    def _db_subject_exists(self, subject: str) -> bool:
        """Brief: Check whether a subject already has a cached SSH key.

        Inputs:
          - subject: Normalized hostname or IP string.

        Outputs:
          - bool: True when a row exists for this subject; False otherwise.
        """

        conn = self._conn
        if conn is None or not subject:
            return False

        with self._db_lock:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM ssh_keys WHERE subject = ? LIMIT 1", (subject,))
            row = cur.fetchone()
        return bool(row)

    def _db_get_row(self, subject: str) -> Optional[Tuple[str, str]]:
        """Brief: Return (key_type, key_hex) for a subject when present.

        Inputs:
          - subject: Normalized hostname or IP string.

        Outputs:
          - (key_type, key_hex) tuple when present; otherwise None.
        """

        conn = self._conn
        if conn is None or not subject:
            return None

        with self._db_lock:
            cur = conn.cursor()
            cur.execute(
                "SELECT key_type, key_hex FROM ssh_keys WHERE subject = ? LIMIT 1",
                (subject,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return str(row[0]), str(row[1])

    def _db_upsert_pair(
        self,
        hostname: Optional[str],
        ip: Optional[str],
        key_type: str,
        key_hex: str,
    ) -> None:
        """Brief: Upsert SSH key rows for hostname and IP subjects.

        Inputs:
          - hostname: Canonical hostname string or None.
          - ip: Canonical IP string or None.
          - key_type: SSH public key algorithm name (e.g. ``ssh-ed25519``).
          - key_hex: Hex-encoded public key blob.

        Outputs:
          - None; ensures rows exist for the hostname and IP subjects (when
            provided), updating last_seen and metadata when a row already
            exists.
        """

        conn = self._conn
        if conn is None:
            return

        now = float(time.time())
        subjects = {s for s in (hostname, ip) if s}
        if not subjects:
            return

        with self._db_lock:
            cur = conn.cursor()
            for subject in subjects:
                cur.execute(
                    """
                    INSERT INTO ssh_keys (subject, hostname, ip, port, key_type, key_hex, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(subject) DO UPDATE SET
                        hostname=excluded.hostname,
                        ip=excluded.ip,
                        port=excluded.port,
                        key_type=excluded.key_type,
                        key_hex=excluded.key_hex,
                        last_seen=excluded.last_seen
                    """,
                    (
                        subject,
                        hostname,
                        ip,
                        int(self._port),
                        key_type,
                        key_hex.lower(),
                        now,
                        now,
                    ),
                )
            conn.commit()

    # ---------------------- scanning helpers ----------------------

    def _run_initial_scan(self, entries: Iterable[str]) -> None:
        """Brief: Perform a best-effort parallel scan of configured targets.

        Inputs:
          - entries: Iterable of raw target strings (IPs, CIDRs, hostnames).

        Outputs:
          - None; populates the sqlite database with any successfully fetched
            SSH host keys. Errors are logged but do not abort startup.
        """

        work_items: List[Tuple[str, str]] = list(self._iter_scan_items(entries))
        if not work_items:
            return

        # Filter out subjects that already exist in the database so we do not
        # re-probe them on every restart.
        pending: List[Tuple[str, str]] = []
        for kind, value in work_items:
            subject = self._normalize_subject(value)
            if not subject:
                continue
            if self._db_subject_exists(subject):
                continue
            pending.append((kind, value))

        if not pending:
            return

        max_workers = max(1, int(self._scan_threads))
        logger.info(
            "SshKeys: starting initial scan of %d targets with %d threads",
            len(pending),
            max_workers,
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [
                pool.submit(self._scan_single, kind, value) for kind, value in pending
            ]
            for fut in futures:
                try:
                    fut.result()
                except Exception as exc:  # pragma: no cover - defensive logging only
                    logger.warning("SshKeys: scan worker error: %s", exc, exc_info=True)

    def _iter_scan_items(self, entries: Iterable[str]) -> Iterable[Tuple[str, str]]:
        """Brief: Expand raw config entries into concrete scan tasks.

        Inputs:
          - entries: Iterable of configured target strings.

        Outputs:
          - Iterator of (kind, value) tuples where kind is "ip" or
            "hostname" and value is the concrete subject string. CIDR ranges
            are expanded into one "ip" entry per host address.
        """

        for raw in entries:
            text = str(raw or "").strip()
            if not text:
                continue

            # CIDR range.
            if "/" in text:
                try:
                    net = ipaddress.ip_network(text, strict=False)
                except Exception:
                    logger.warning("SshKeys: invalid CIDR target %r", text)
                    continue
                for addr in net.hosts():
                    yield "ip", str(addr)
                continue

            # Bare IP address.
            try:
                ip_obj = ipaddress.ip_address(text)
            except Exception:
                # Treat as hostname.
                yield "hostname", text
                continue

            yield "ip", str(ip_obj)

    def _scan_single(self, kind: str, value: str) -> None:
        """Brief: Probe a single IP or hostname and store its SSH host key.

        Inputs:
          - kind: Either "ip" or "hostname".
          - value: IP string or hostname string.

        Outputs:
          - None; on success, inserts or updates rows in the sqlite database
            for both hostname and IP (when discoverable).
        """

        if kind == "ip":
            ip = value
            hostname: Optional[str]
            try:
                host, _aliases, _addrs = socket.gethostbyaddr(ip)
                hostname = host.rstrip(".") or None
            except Exception:
                hostname = None

            try:
                info = fetch_ssh_host_key_hex(
                    ip, port=self._port, timeout=self._timeout
                )
            except Exception as exc:
                logger.info("SshKeys: failed to fetch SSH key for IP %s: %s", ip, exc)
                return

            if hostname is None:
                hostname = str(info.hostname or "").rstrip(".") or None

            self._db_upsert_pair(hostname, ip, info.key_type, info.key_hex)
            return

        # Hostname path.
        hostname = value.rstrip(".")
        ip: Optional[str] = None
        try:
            # Prefer IPv4/IPv6 addresses that are likely to succeed for SSH.
            addrinfos = socket.getaddrinfo(
                hostname,
                self._port,
                proto=socket.IPPROTO_TCP,
                type=socket.SOCK_STREAM,
            )
            for family, _socktype, _proto, _canonname, sockaddr in addrinfos:
                if family in (socket.AF_INET, socket.AF_INET6):
                    ip = str(sockaddr[0])
                    break
        except Exception:
            ip = None

        try:
            info = fetch_ssh_host_key_hex(
                hostname, port=self._port, timeout=self._timeout
            )
        except Exception as exc:
            logger.info(
                "SshKeys: failed to fetch SSH key for hostname %s: %s", hostname, exc
            )
            return

        self._db_upsert_pair(hostname, ip, info.key_type, info.key_hex)

    # ---------------------- SSHFP answer helpers ----------------------

    @staticmethod
    def _normalize_subject(subject: str) -> str:
        """Brief: Normalize a subject string for database lookups.

        Inputs:
          - subject: Raw hostname or IP string (may include a trailing dot).

        Outputs:
          - Lowercased subject without trailing dot, or empty string on error.
        """

        text = str(subject or "").strip()
        if not text:
            return ""
        return text.rstrip(".").lower()

    @staticmethod
    def _sshfp_algorithm_for_key_type(key_type: str) -> Optional[int]:
        """Brief: Map an SSH key_type string to an SSHFP algorithm number.

        Inputs:
          - key_type: SSH public key algorithm name (e.g. ``ssh-ed25519``).

        Outputs:
          - Integer SSHFP algorithm number (1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519,
            6=Ed448) or None when the key type is unknown.
        """

        t = str(key_type or "").strip().lower()
        if not t:
            return None

        if t in {"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}:
            return 1
        if t in {"ssh-dss"}:
            return 2
        if t.startswith("ecdsa-sha2-") or t == "ssh-ecdsa":
            return 3
        if t == "ssh-ed25519":
            return 4
        if t == "ssh-ed448":
            return 6
        return None

    def pre_resolve(
        self,
        qname: str,
        qtype: int,
        req: bytes,
        ctx: PluginContext,
    ) -> Optional[PluginDecision]:
        """Brief: Intercept SSHFP queries and answer from the local key cache.

        Inputs:
          - qname: Query name string.
          - qtype: Numeric DNS qtype code.
          - req: Raw DNS request bytes.
          - ctx: PluginContext for the current request.

        Outputs:
          - PluginDecision("override") with an SSHFP DNS response when a
            cached entry exists, otherwise None to fall through to normal
            resolution.
        """

        if not self.targets(ctx):
            return None

        try:
            if int(qtype) != int(QTYPE.SSHFP):
                return None
        except Exception:
            return None

        subject = self._normalize_subject(qname)
        if not subject:
            return None

        row = self._db_get_row(subject)
        if not row:
            return None

        key_type, key_hex = row
        alg = self._sshfp_algorithm_for_key_type(key_type)
        if alg is None:
            logger.debug(
                "SshKeys: unsupported key_type %r for subject %s", key_type, subject
            )
            return None

        try:
            key_bytes = bytes.fromhex(str(key_hex))
        except Exception:
            logger.warning("SshKeys: invalid key_hex for subject %s", subject)
            return None

        sha1_hex = hashlib.sha1(key_bytes).hexdigest()
        sha256_hex = hashlib.sha256(key_bytes).hexdigest()

        try:
            request = DNSRecord.parse(req)
        except Exception as exc:  # pragma: no cover - defensive parsing
            logger.warning("SshKeys: failed to parse request for %s: %s", qname, exc)
            return None

        owner = str(request.q.qname).rstrip(".") + "."
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        had_rr = False
        for fp_type, fp_hex in ((1, sha1_hex), (2, sha256_hex)):
            line = f"{owner} {self._ttl} IN SSHFP {alg} {fp_type} {fp_hex}"
            try:
                rrs = RR.fromZone(line)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "SshKeys: failed to build SSHFP RR for %s: %s", owner, exc
                )
                continue
            for rr in rrs:
                reply.add_answer(rr)
                had_rr = True

        if not had_rr:
            return None

        return PluginDecision(action="override", response=reply.pack())
