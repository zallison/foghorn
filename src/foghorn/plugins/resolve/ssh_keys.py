from __future__ import annotations

"""SSH host key resolver plugin.

Brief:
  - During setup() (and optional lazy scans), fetch SSH host keys for a configured set of
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
from pydantic import BaseModel, Field, ConfigDict

from foghorn.plugins.resolve.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)
from foghorn.utils import dns_names, ip_networks
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
      - scan_allowlist: Optional list of CIDR/IP strings allowed for scanning.
      - scan_blocklist: Optional list of CIDR/IP strings excluded from scanning.
      - allow_public_scan: When false, skip targets resolving to public IPs unless
        they are explicitly allowed.
      - max_targets: Maximum number of scan targets processed per startup scan.
      - max_cidr_hosts: Maximum number of hosts to expand per CIDR target.
      - lazy_scan: When true, allow on-demand single-host scans for CIDR targets.
      - max_lazy_scans: Maximum number of concurrent lazy scans.
      - response_allowlist: Optional list of client CIDR/IPs allowed to receive
        SSHFP responses.
      - response_blocklist: Optional list of client CIDR/IPs excluded from SSHFP
        responses.
      - allow_public_responses: When false, only respond to non-public clients
        unless explicitly allowlisted.
      - include_sha1: When true, include SHA-1 SSHFP records (fp_type=1).
      - retention_seconds: Age threshold for pruning stale DB rows.
      - max_rows: Maximum number of rows to retain in the DB (oldest evicted).
      - prune_interval_seconds: Minimum time between DB prune passes.
      - db_path_allowlist: Allowed base directories for db_path.

    Outputs:
      - SshKeysConfig instance with normalized field types.
    """

    targets: List[str] = Field(default_factory=list)
    scan_threads: int = Field(default=4, ge=1)
    ttl: int = Field(default=300, ge=0)
    db_path: str = Field(default="./config/var/ssh_keys.db")
    port: int = Field(default=22, ge=1, le=65535)
    timeout_seconds: float = Field(default=5.0, ge=0.1)
    scan_allowlist: List[str] = Field(default_factory=list)
    scan_blocklist: List[str] = Field(default_factory=list)
    allow_public_scan: bool = Field(default=False)
    max_targets: int = Field(default=4096, ge=0)
    max_cidr_hosts: int = Field(default=1024, ge=0)
    lazy_scan: bool = Field(default=True)
    max_lazy_scans: int = Field(default=32, ge=0)
    response_allowlist: List[str] = Field(default_factory=list)
    response_blocklist: List[str] = Field(default_factory=list)
    allow_public_responses: bool = Field(default=False)
    include_sha1: bool = Field(default=True)
    retention_seconds: float = Field(default=0.0, ge=0.0)
    max_rows: int = Field(default=0, ge=0)
    prune_interval_seconds: float = Field(default=300.0, ge=0.0)
    db_path_allowlist: List[str] = Field(
        default_factory=lambda: ["./config/var", "./var", "./data", "."]
    )

    model_config = ConfigDict(extra="allow")


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
        cached subject by synthesizing SSHFP RRs with SHA-256 (and optional
        SHA-1) fingerprints derived from the stored public key.
    """

    # Restrict this plugin to SSHFP by default.
    target_qtypes: Sequence[str] = ("SSHFP",)
    setup_requires_dns = True

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
        self._scan_allowlist = self._parse_networks(
            cfg.scan_allowlist, label="scan_allowlist"
        )
        self._scan_blocklist = self._parse_networks(
            cfg.scan_blocklist, label="scan_blocklist"
        )
        self._allow_public_scan: bool = bool(cfg.allow_public_scan)
        self._max_targets: int = int(cfg.max_targets)
        self._max_cidr_hosts: int = int(cfg.max_cidr_hosts)
        self._lazy_scan_enabled: bool = bool(cfg.lazy_scan)
        self._max_lazy_scans: int = int(cfg.max_lazy_scans)
        self._response_allowlist = self._parse_networks(
            cfg.response_allowlist, label="response_allowlist"
        )
        self._response_blocklist = self._parse_networks(
            cfg.response_blocklist, label="response_blocklist"
        )
        self._allow_public_responses: bool = bool(cfg.allow_public_responses)
        self._include_sha1: bool = bool(cfg.include_sha1)
        self._retention_seconds: float = float(cfg.retention_seconds)
        self._max_rows: int = int(cfg.max_rows)
        self._prune_interval_seconds: float = float(cfg.prune_interval_seconds)
        self._db_path_allowlist: List[str] = list(cfg.db_path_allowlist or [])
        self._cidr_networks = self._parse_cidr_targets(self._targets)
        self._last_prune: float = 0.0

        self._db_lock: threading.RLock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._lazy_scan_lock: threading.Lock = threading.Lock()
        self._lazy_scans: set[str] = set()

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
        self._maybe_prune_db(force=True)

    def _parse_networks(
        self, entries: Iterable[str], *, label: str
    ) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Brief: Parse CIDR/IP strings into ipaddress network objects.

        Inputs:
          - entries: Iterable of CIDR/IP strings.
          - label: Configuration label used for warning messages.

        Outputs:
          - List of ipaddress network objects (IPv4Network/IPv6Network).
        """

        networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw in entries or []:
            text = str(raw or "").strip()
            if not text:
                continue
            net = ip_networks.parse_network(text, strict=False)
            if net is None:
                logger.warning("SshKeys: invalid %s entry %r", label, text)
                continue
            networks.append(net)
        return networks

    def _parse_cidr_targets(
        self, entries: Iterable[str]
    ) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Brief: Extract CIDR targets for membership checks without expansion.

        Inputs:
          - entries: Iterable of target strings (IPs, CIDRs, hostnames).

        Outputs:
          - List of ipaddress network objects for CIDR targets.
        """

        networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw in entries or []:
            text = str(raw or "").strip()
            if not text or "/" not in text:
                continue
            net = ip_networks.parse_network(text, strict=False)
            if net is None:
                logger.warning("SshKeys: invalid CIDR target %r", text)
                continue
            networks.append(net)
        return networks

    def _resolve_db_path(self, db_path: str) -> str:
        """Brief: Resolve and validate db_path against configured allowlist.

        Inputs:
          - db_path: Raw db_path string from configuration.

        Outputs:
          - Absolute filesystem path to the sqlite database.
        """

        resolved = os.path.abspath(os.path.expanduser(str(db_path or "")))
        allowlist = [d for d in (self._db_path_allowlist or []) if str(d).strip()]
        if not allowlist:
            logger.warning(
                "SshKeys: db_path_allowlist is empty; allowing db_path %s",
                resolved,
            )
            return resolved

        allowed_dirs = [os.path.abspath(os.path.expanduser(str(d))) for d in allowlist]
        for root in allowed_dirs:
            try:
                if os.path.commonpath([resolved, root]) == root:
                    return resolved
            except Exception:
                continue

        fallback_root = allowed_dirs[0]
        safe_name = os.path.basename(resolved) or "ssh_keys.db"
        fallback = os.path.join(fallback_root, safe_name)
        fallback_dir = os.path.dirname(fallback) or "."
        if not os.access(fallback_dir, os.W_OK | os.X_OK):
            logger.warning(
                "SshKeys: fallback db_path %s is not writable; using %s",
                fallback,
                resolved,
            )
            return resolved
        logger.warning(
            "SshKeys: db_path %s is outside allowlist; using %s instead",
            resolved,
            fallback,
        )
        return fallback

    def _init_db(self) -> None:
        """Brief: Create sqlite connection and ensure ssh_keys table exists.

        Inputs:
          - None (uses self._db_path).

        Outputs:
          - None; populates self._conn with an open sqlite3.Connection and
            creates the required table and index if they do not already exist.
        """

        db_path = self._resolve_db_path(self._db_path)
        self._db_path = db_path
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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ssh_keys_last_seen ON ssh_keys(last_seen)"
            )

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
        self._maybe_prune_db()

    def _maybe_prune_db(self, *, force: bool = False) -> None:
        """Brief: Prune stale/overflow DB rows on a configurable interval.

        Inputs:
          - force: When true, run pruning regardless of interval timing.

        Outputs:
          - None; deletes stale rows and/or trims to max_rows when configured.
        """

        if self._retention_seconds <= 0 and self._max_rows <= 0:
            return

        now = float(time.time())
        if not force and (now - self._last_prune) < self._prune_interval_seconds:
            return

        self._last_prune = now
        self._prune_db(now)

    def _prune_db(self, now: float) -> None:
        """Brief: Delete stale or excess rows from the sqlite cache.

        Inputs:
          - now: Current timestamp (seconds since epoch).

        Outputs:
          - None; mutates the sqlite database in-place.
        """

        conn = self._conn
        if conn is None:
            return

        with self._db_lock:
            cur = conn.cursor()
            if self._retention_seconds > 0:
                cutoff = float(now) - float(self._retention_seconds)
                cur.execute("DELETE FROM ssh_keys WHERE last_seen < ?", (cutoff,))
            if self._max_rows > 0:
                cur.execute("SELECT COUNT(*) FROM ssh_keys")
                row = cur.fetchone()
                total = int(row[0]) if row else 0
                if total > self._max_rows:
                    excess = total - self._max_rows
                    cur.execute(
                        """
                        DELETE FROM ssh_keys
                        WHERE subject IN (
                            SELECT subject FROM ssh_keys
                            ORDER BY last_seen ASC
                            LIMIT ?
                        )
                        """,
                        (excess,),
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

        # Filter out subjects that already exist in the database so we do not
        # re-probe them on every restart.
        pending: List[Tuple[str, str]] = []
        scanned = 0
        for kind, value in self._iter_scan_items(entries):
            if self._max_targets > 0 and scanned >= self._max_targets:
                logger.warning(
                    "SshKeys: scan target cap reached (%d); skipping remaining entries",
                    self._max_targets,
                )
                break
            scanned += 1
            subject = self._normalize_subject(value)
            if not subject:
                continue
            if kind == "ip" and not self._is_scan_ip_allowed(value):
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
            are expanded into one "ip" entry per host address up to
            ``max_cidr_hosts`` when that cap is configured.
        """

        for raw in entries:
            text = str(raw or "").strip()
            if not text:
                continue

            # CIDR range.
            if "/" in text:
                net = ip_networks.parse_network(text, strict=False)
                if net is None:
                    logger.warning("SshKeys: invalid CIDR target %r", text)
                    continue
                emitted = 0
                for addr in net.hosts():
                    if self._max_cidr_hosts > 0 and emitted >= self._max_cidr_hosts:
                        logger.warning(
                            "SshKeys: CIDR %s exceeds max_cidr_hosts=%d; truncating",
                            text,
                            self._max_cidr_hosts,
                        )
                        break
                    emitted += 1
                    yield "ip", str(addr)
                continue

            # Bare IP address.
            ip_obj = ip_networks.parse_ip(text)
            if ip_obj is None:
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
            if not self._is_scan_ip_allowed(ip):
                logger.info("SshKeys: scan target %s blocked by policy", ip)
                return
            hostname: Optional[str]
            try:
                host, _aliases, _addrs = socket.gethostbyaddr(ip)
                hostname = dns_names.normalize_name(host) or None
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
                hostname = dns_names.normalize_name(info.hostname or "") or None

            self._db_upsert_pair(hostname, ip, info.key_type, info.key_hex)
            return

        # Hostname path.
        hostname = dns_names.normalize_name(value)
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
        if ip is None:
            logger.info(
                "SshKeys: unable to resolve hostname %s to an IP; skipping", hostname
            )
            return
        if not self._is_scan_ip_allowed(ip):
            logger.info("SshKeys: scan target %s (%s) blocked by policy", hostname, ip)
            return

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

        return dns_names.normalize_name(subject)

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

    def _is_scan_ip_allowed(self, ip_text: str) -> bool:
        """Brief: Determine whether a scan target IP is allowed by policy.

        Inputs:
          - ip_text: IP address string.

        Outputs:
          - bool indicating whether scanning this IP is permitted.
        """

        addr = ip_networks.parse_ip(ip_text)
        if addr is None:
            return False

        if ip_networks.ip_in_any_network(addr, self._scan_blocklist):
            return False
        if self._scan_allowlist:
            return ip_networks.ip_in_any_network(addr, self._scan_allowlist)
        if self._allow_public_scan:
            return True
        return not addr.is_global

    def _is_response_allowed(self, ctx: PluginContext) -> bool:
        """Brief: Determine whether a client may receive SSHFP responses.

        Inputs:
          - ctx: PluginContext containing client_ip.

        Outputs:
          - bool indicating whether this client is authorized.
        """

        client_ip = str(getattr(ctx, "client_ip", "") or "")
        if not client_ip:
            return False
        addr = ip_networks.parse_ip(client_ip)
        if addr is None:
            return False

        if ip_networks.ip_in_any_network(addr, self._response_blocklist):
            return False
        if self._response_allowlist:
            return ip_networks.ip_in_any_network(addr, self._response_allowlist)
        if self._allow_public_responses:
            return True
        return not addr.is_global

    def _enqueue_lazy_scan(self, kind: str, value: str) -> None:
        """Brief: Launch a background lazy scan for a single target.

        Inputs:
          - kind: Either "ip" or "hostname".
          - value: Target value string.

        Outputs:
          - None; spawns a daemon thread when under concurrency limits.
        """

        subject = self._normalize_subject(value)
        if not subject:
            return

        with self._lazy_scan_lock:
            if subject in self._lazy_scans:
                return
            if self._max_lazy_scans > 0 and (
                len(self._lazy_scans) >= self._max_lazy_scans
            ):
                logger.debug(
                    "SshKeys: lazy scan limit reached (%d); skipping %s",
                    self._max_lazy_scans,
                    subject,
                )
                return
            self._lazy_scans.add(subject)

        def _run() -> None:
            try:
                self._scan_single(kind, value)
            finally:
                with self._lazy_scan_lock:
                    self._lazy_scans.discard(subject)

        threading.Thread(
            target=_run,
            name=f"SshKeysLazyScan:{subject}",
            daemon=True,
        ).start()

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
        if not self._is_response_allowed(ctx):
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
            if self._lazy_scan_enabled and self._cidr_networks:
                addr = ip_networks.parse_ip(subject)
                if addr is not None and any(addr in net for net in self._cidr_networks):
                    self._enqueue_lazy_scan("ip", subject)
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

        sha1_hex = hashlib.sha1(key_bytes).hexdigest() if self._include_sha1 else ""
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
        fingerprints = []
        if self._include_sha1:
            fingerprints.append((1, sha1_hex))
        fingerprints.append((2, sha256_hex))
        for fp_type, fp_hex in fingerprints:
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
