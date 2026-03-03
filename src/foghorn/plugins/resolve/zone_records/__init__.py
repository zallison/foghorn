"""ZoneRecords plugin: Zone-based DNS record management with AXFR and DNSSEC support.

Main entry point that orchestrates record loading, query resolution, and file watching.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional, Tuple

from dnslib import QTYPE
from pydantic import BaseModel, Field

from foghorn.plugins.resolve.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

from . import (
    axfr_polling,
    dnssec,
    helpers,
    loader,
    notify,
    resolver,
    transfer,
    update_processor,
    update_helpers,
    watchdog,
)

logger = logging.getLogger(__name__)


class UpdateTsigKeyConfig(BaseModel):
    """Brief: Configuration for a TSIG key for DNS UPDATE authentication.

    Inputs:
      - name: Key name (domain name). Used as TSIG key owner name.
      - algorithm: HMAC algorithm (hmac-md5, hmac-sha256, hmac-sha512).
      - secret: Base64-encoded shared secret.

    Outputs:
      - UpdateTsigKeyConfig instance.
    """

    name: str = Field(..., description="TSIG key name (domain name).")
    algorithm: str = Field(
        default="hmac-sha256",
        description="HMAC algorithm: 'hmac-md5', 'hmac-sha256', or 'hmac-sha512'.",
    )
    secret: str = Field(
        ...,
        description="Base64-encoded shared secret.",
    )

    # Per-key authorization scopes
    allow_names: Optional[List[str]] = Field(
        default=None, description="Hostnames this key can update (wildcards supported)."
    )
    allow_names_files: Optional[List[str]] = Field(
        default=None, description="File paths containing allowed names for this key."
    )
    block_names: Optional[List[str]] = Field(
        default=None, description="Hostnames this key cannot update."
    )
    block_names_files: Optional[List[str]] = Field(
        default=None, description="File paths containing blocked names for this key."
    )
    allow_update_ips: Optional[List[str]] = Field(
        default=None, description="IP addresses this key can set in A/AAAA records."
    )
    allow_update_ips_files: Optional[List[str]] = Field(
        default=None, description="File paths containing allowed IPs for this key."
    )
    block_update_ips: Optional[List[str]] = Field(
        default=None, description="Blocked IPs for this key."
    )
    block_update_ips_files: Optional[List[str]] = Field(
        default=None, description="File paths containing blocked IPs."
    )

    class Config:
        extra = "forbid"


class UpdatePskTokenConfig(BaseModel):
    """Brief: Configuration for a PSK token for DNS UPDATE authentication.

    Inputs:
      - token: Pre-shared token (hashed).

    Outputs:
      - UpdatePskTokenConfig instance.
    """

    token: str = Field(
        ...,
        description="Pre-shared token (hashed).",
    )

    # Per-token authorization scopes
    allow_names: Optional[List[str]] = Field(
        default=None,
        description="Hostnames this token can update (wildcards supported).",
    )
    allow_names_files: Optional[List[str]] = Field(
        default=None, description="File paths containing allowed names for this token."
    )
    block_names: Optional[List[str]] = Field(
        default=None, description="Hostnames this token cannot update."
    )
    block_names_files: Optional[List[str]] = Field(
        default=None, description="File paths containing blocked names for this token."
    )
    allow_update_ips: Optional[List[str]] = Field(
        default=None, description="IP addresses this token can set in A/AAAA records."
    )
    allow_update_ips_files: Optional[List[str]] = Field(
        default=None, description="File paths containing allowed IPs for this token."
    )
    block_update_ips: Optional[List[str]] = Field(
        default=None, description="Blocked IPs for this token."
    )
    block_update_ips_files: Optional[List[str]] = Field(
        default=None, description="File paths containing blocked IPs."
    )

    class Config:
        extra = "forbid"


class UpdateZoneApexConfig(BaseModel):
    """Brief: DNS UPDATE configuration for a specific zone.

    Inputs:
      - zone: Zone apex (e.g. "example.com").
      - tsig: TSIG configuration.
      - psk: PSK configuration.
      - allow_names: List of allowed name patterns (wildcards supported).
      - allow_names_files: File paths containing allowed names.
      - block_names: List of blocked names.
      - block_names_files: File paths containing blocked names.
      - allow_clients: CIDR list of clients allowed to send UPDATE.
      - allow_clients_files: File paths containing allowed client CIDRs.
      - allow_update_ips: CIDR list of IPs allowed in A/AAAA record values.
      - allow_update_ips_files: File paths containing allowed update IPs.
      - block_update_ips: CIDR list of IPs blocked from A/AAAA record values.
      - block_update_ips_files: File paths containing blocked update IPs.

    Outputs:
      - UpdateZoneApexConfig instance.
    """

    zone: str = Field(..., description="Zone apex (e.g. 'example.com').")
    tsig: Optional[dict] = Field(
        default=None,
        description="TSIG authentication configuration.",
    )
    psk: Optional[dict] = Field(
        default=None,
        description="PSK authentication configuration.",
    )
    allow_names: Optional[List[str]] = Field(
        default=None,
        description="Allowed name patterns (wildcards supported).",
    )
    allow_names_files: Optional[List[str]] = Field(
        default=None,
        description="File paths containing allowed names.",
    )
    block_names: Optional[List[str]] = Field(
        default=None,
        description="Blocked names.",
    )
    block_names_files: Optional[List[str]] = Field(
        default=None,
        description="File paths containing blocked names.",
    )
    allow_clients: Optional[List[str]] = Field(
        default=None,
        description="CIDR list of clients allowed to send UPDATE.",
    )
    allow_clients_files: Optional[List[str]] = Field(
        default=None,
        description="File paths containing allowed client CIDRs.",
    )
    allow_update_ips: Optional[List[str]] = Field(
        default=None,
        description="CIDR list of IPs allowed in A/AAAA record values.",
    )
    allow_update_ips_files: Optional[List[str]] = Field(
        default=None,
        description="File paths containing allowed update IPs.",
    )
    block_update_ips: Optional[List[str]] = Field(
        default=None,
        description="CIDR list of IPs blocked from A/AAAA record values.",
    )
    block_update_ips_files: Optional[List[str]] = Field(
        default=None,
        description="File paths containing blocked update IPs.",
    )

    class Config:
        extra = "forbid"


class DnsUpdateConfig(BaseModel):
    """Brief: DNS UPDATE configuration for ZoneRecords.

    Inputs:
      - enabled: Whether DNS UPDATE is enabled.
      - zones: Per-zone UPDATE configuration.

    Outputs:
      - DnsUpdateConfig instance.
    """

    enabled: bool = Field(
        default=False,
        description="Enable DNS UPDATE support.",
    )
    zones: Optional[List[UpdateZoneApexConfig]] = Field(
        default=None,
        description="Per-zone DNS UPDATE configuration.",
    )

    class Config:
        extra = "forbid"


class AxfrUpstreamConfig(BaseModel):
    """Brief: Configuration for a single AXFR upstream server.

    Inputs:
      - host: Upstream authoritative server hostname or IP.
      - port: TCP port (default 53).
      - timeout_ms: Transfer timeout in milliseconds (default 5000).
      - transport: "tcp" (default) or "dot" for DNS-over-TLS.
      - server_name: Optional TLS SNI name for DoT.
      - verify: TLS certificate verification for DoT (default True).
      - ca_file: Optional CA bundle path for DoT.

    Outputs:
      - AxfrUpstreamConfig instance.
    """

    host: str = Field(..., description="Upstream authoritative server hostname or IP.")
    port: int = Field(default=53, ge=1, le=65535, description="TCP port.")
    timeout_ms: int = Field(
        default=5000, ge=0, description="Transfer timeout in milliseconds."
    )
    transport: str = Field(default="tcp", description="Transport: 'tcp' or 'dot'.")
    server_name: Optional[str] = Field(
        default=None, description="TLS SNI name for DoT."
    )
    verify: bool = Field(
        default=True, description="TLS certificate verification for DoT."
    )
    ca_file: Optional[str] = Field(default=None, description="CA bundle path for DoT.")

    class Config:
        extra = "forbid"


class AxfrZoneConfig(BaseModel):
    """Brief: Configuration for a single AXFR-backed zone.

    Inputs:
      - zone: Zone apex (e.g. "example.com").
      - upstreams: List of upstream servers to transfer from.
      - masters: Legacy alias for upstreams (deprecated).
      - allow_no_dnssec: Accept transfer even if DNSSEC is missing or invalid
        (default True). When False, zones without valid DNSSEC will be rejected
        once DNSSEC validation for AXFR is implemented.
      - minimum_reload_time: Minimum seconds between AXFR reloads. Reloads will
        only occur after this time has elapsed since the original load or since
        the last NOTIFY was received for the zone.

    Outputs:
      - AxfrZoneConfig instance.
    """

    zone: str = Field(..., description="Zone apex (e.g. 'example.com').")
    upstreams: Optional[List[AxfrUpstreamConfig]] = Field(
        default=None, description="List of upstream servers to transfer from."
    )
    masters: Optional[List[AxfrUpstreamConfig]] = Field(
        default=None, description="Legacy alias for upstreams (deprecated)."
    )
    allow_no_dnssec: bool = Field(
        default=True,
        description=(
            "Accept transfer even if DNSSEC is missing or invalid. When False, "
            "zones without valid DNSSEC will be rejected once DNSSEC validation "
            "for AXFR is implemented."
        ),
    )
    minimum_reload_time: float = Field(
        default=0,
        ge=0,
        description=(
            "Minimum seconds between AXFR reloads. Reloads only occur after "
            "this time has elapsed since the original load or since the last "
            "NOTIFY was received for the zone. A value of 0 reloads on every load."
        ),
    )

    class Config:
        extra = "forbid"


class ZoneDnssecNsec3Config(BaseModel):
    """Brief: NSEC3 parameters for DNSSEC negative proofs in ZoneRecords.

    Inputs:
      - salt: Salt in zonefile presentation format ("-" for empty, otherwise hex).
      - iterations: NSEC3 iterations parameter (RFC 5155).

    Outputs:
      - ZoneDnssecNsec3Config instance.
    """

    salt: str = Field(
        default="-",
        description=(
            "NSEC3 salt in zonefile presentation form: '-' for empty salt, "
            "otherwise a hex string (e.g. 'A1B2C3')."
        ),
    )
    iterations: int = Field(
        default=10,
        ge=0,
        description="NSEC3 iterations value (RFC 5155).",
    )

    class Config:
        extra = "forbid"


class ZoneDnssecSigningConfig(BaseModel):
    """Brief: DNSSEC auto-signing configuration for ZoneRecords.

    Inputs:
      - enabled: Enable automatic DNSSEC signing for authoritative zones.
      - keys_dir: Optional base directory for per-zone key files.
      - algorithm: DNSSEC algorithm name (e.g. "ECDSAP256SHA256").
      - generate: Key generation policy ("yes", "no", or "maybe").
      - validity_days: Signature validity window in days.
      - nsec3: Optional NSEC3 parameters (salt/iterations) used for signed
        NXDOMAIN/NODATA proofs.
      - use_tld: Optional single-label TLD (e.g. "zaa", "corp") to treat as
        an inferred apex for SSHFP-only zones when synthesizing SOA records.

    Outputs:
      - Parsed ZoneDnssecSigningConfig instance used by the config schema.
    """

    enabled: bool = Field(
        default=False,
        description="Enable automatic DNSSEC signing for authoritative zones.",
    )
    keys_dir: Optional[str] = Field(
        default=None,
        description="Directory to read/write DNSSEC keys; defaults to the working directory when omitted.",
    )
    algorithm: str = Field(
        default="ECDSAP256SHA256",
        description="DNSSEC algorithm name (e.g. 'ECDSAP256SHA256', 'RSASHA256').",
    )
    generate: str = Field(
        default="maybe",
        description="Key generation policy: 'yes' (always new), 'no' (never), 'maybe' (generate when missing).",
    )
    validity_days: int = Field(
        default=30,
        ge=1,
        description="Signature validity window in days.",
    )
    nsec3: Optional[ZoneDnssecNsec3Config] = Field(
        default=None,
        description="Optional NSEC3 parameters used for negative-answer proofs.",
    )
    use_tld: Optional[str] = Field(
        default=None,
        description=(
            "Optional single-label TLD (e.g. 'zaa', 'corp') that ZoneRecords "
            "may treat as an inferred zone apex when synthesizing SOA records "
            "for SSHFP-only data."
        ),
    )

    class Config:
        extra = "forbid"


class BindZoneFileConfig(BaseModel):
    """Brief: Configuration for a single BIND zone file entry.

    Inputs:
      - path: Filesystem path to an RFC-1035 style zonefile.
      - origin: Optional override for the zonefile base domain ($ORIGIN).
      - ttl: Optional override for the zonefile default TTL ($TTL).

    Outputs:
      - BindZoneFileConfig instance.
    """

    path: str = Field(..., description="Path to an RFC-1035 style zonefile.")
    origin: Optional[str] = Field(
        default=None,
        description=(
            "Optional override for the zonefile base domain ($ORIGIN). When set, "
            "ZoneRecords ignores any $ORIGIN lines found in the file and uses this value."
        ),
    )
    ttl: Optional[int] = Field(
        default=None,
        ge=0,
        description=(
            "Optional override for the zonefile default TTL ($TTL). When set, "
            "ZoneRecords ignores any $TTL lines found in the file and uses this value "
            "as the default TTL for records which omit TTL."
        ),
    )

    class Config:
        extra = "forbid"


class ZoneRecordsConfig(BaseModel):
    """Brief: Typed configuration model for ZoneRecords.

    Inputs:
      - file_paths: Preferred list of records file paths.
      - bind_paths: Optional list of RFC-1035 style BIND zone files. Entries may
        be plain strings (paths) or objects with per-file origin/ttl overrides.
      - records: Optional list of inline records using
        ``<domain>|<qtype>|<ttl>|<value>`` format.
      - load_mode: Controls load/reload behaviour:
        - "merge" (default): preserve existing records and overlay newly loaded ones.
        - "replace": rebuild records from configured sources on each load.
        - "first": use the first configured source group in this order:
          records (inline) → axfr_zones → file_paths → bind_paths, and ignore the others.
      - merge_policy: "add" (default) to append unique values into existing
        RRsets, or "overwrite" to replace RRsets when the same (name,qtype)
        appears in a later source.
      - watchdog_enabled: Enable watchdog-based reloads.
      - watchdog_min_interval_seconds: Minimum seconds between reloads.
      - watchdog_poll_interval_seconds: Optional polling interval.
      - ttl: Default TTL in seconds.
      - nxdomain_zones: Optional list of zone suffixes for which ZoneRecords
        should return NXDOMAIN/NODATA instead of falling through to upstream.
      - axfr_zones: Optional list of AXFR-backed zones.

    Outputs:
      - ZoneRecordsConfig instance with normalized field types.
    """

    file_paths: Optional[List[str]] = None
    bind_paths: Optional[List[str | BindZoneFileConfig]] = None
    records: Optional[List[str]] = None
    load_mode: str = Field(
        default="merge",
        description=(
            "Controls record loading strategy: 'merge' preserves existing records "
            "and overlays new data; 'replace' rebuilds the in-memory mapping each "
            "time; 'first' uses the first configured source group and ignores the rest."
        ),
    )
    merge_policy: str = Field(
        default="add",
        description=(
            "Controls conflict behaviour when the same (name,qtype) appears more "
            "than once: 'add' appends unique values (keeping the earlier TTL); "
            "'overwrite' replaces the RRset using the later source."
        ),
    )
    watchdog_enabled: Optional[bool] = None
    watchdog_min_interval_seconds: float = Field(default=1.0, ge=0)
    watchdog_poll_interval_seconds: float = Field(default=60.0, ge=0)
    ttl: int = Field(default=300, ge=0)
    nxdomain_zones: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional list of zone suffixes for which ZoneRecords should return "
            "NXDOMAIN/NODATA for names under that suffix which are not present in "
            "the internal mapping, instead of falling through to upstream resolution."
        ),
    )
    axfr_zones: Optional[List[AxfrZoneConfig]] = None
    axfr_notify: Optional[List[AxfrUpstreamConfig]] = Field(
        default=None,
        description=(
            "Optional list of NOTIFY recipients for AXFR-backed zones. Each "
            "entry uses the same host/port/transport/server_name/verify/ca_file "
            "shape as axfr_zones[].upstreams. Only 'tcp' and 'dot' transports "
            "are supported for outbound NOTIFY."
        ),
    )
    axfr_notify_all: bool = Field(
        default=False,
        description=(
            "When true, automatically learn NOTIFY targets from AXFR/IXFR "
            "clients by recording their source IPs as downstream secondaries."
        ),
    )
    axfr_notify_scheduled: Optional[int] = Field(
        default=None,
        ge=0,
        description=(
            "Optional delay in seconds after serving AXFR/IXFR to a client "
            "before sending a follow-up NOTIFY for the transferred zone. "
            "Ignored when null or zero."
        ),
    )
    dnssec_signing: Optional[ZoneDnssecSigningConfig] = None
    dns_update: Optional[DnsUpdateConfig] = None

    class Config:
        extra = "allow"


@plugin_aliases("zone", "zone_records", "custom", "records")
class ZoneRecords(BasePlugin):
    """DNS zone records plugin with AXFR, DNSSEC, and DNS UPDATE support."""

    target_opcodes = ("NOTIFY", "UPDATE")

    def handle_opcode(
        self, opcode: int, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Handle NOTIFY opcode by validating sender and triggering AXFR refresh.

        Inputs:
          - opcode: Numeric opcode (expected to be NOTIFY = 4).
          - qname: Normalized zone name from the query.
          - qtype: Query type (typically SOA for NOTIFY).
          - req: Raw wire-format request bytes.
          - ctx: PluginContext with client_ip, listener, etc.

        Outputs:
          - PluginDecision with override action and NOERROR response when NOTIFY is
            valid and processed. Returns None to skip NOTIFY handling.
        """
        return resolver.handle_opcode(self, opcode, qname, qtype, req, ctx)

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - ZoneRecordsConfig class for use by the core config loader.
        """
        return ZoneRecordsConfig

    def setup(self) -> None:
        """Brief: Initialize the plugin, load record mappings, and configure watchers.

        Inputs:
          - None (uses self.config for configuration).

        Outputs:
          - None
        """
        # Normalize and validate paths
        provided_paths = self.config.get("file_paths")
        legacy_path = self.config.get("file_path")
        bind_paths_cfg = self.config.get("bind_paths")
        inline_records_cfg = self.config.get("records")
        axfr_cfg = self.config.get("axfr_zones")

        self.file_paths = []
        self.bind_paths: List[object] = []

        if provided_paths is not None or legacy_path is not None:
            self.file_paths = helpers.normalize_paths(provided_paths, legacy_path)

        if bind_paths_cfg is not None:
            self.bind_paths = helpers.normalize_bind_paths(bind_paths_cfg)

        if not self.file_paths and not self.bind_paths:
            if inline_records_cfg or axfr_cfg:
                self.file_paths = []
                self.bind_paths = []
            else:
                self.file_paths = helpers.normalize_paths(None, None)

        # Cache inline records
        try:
            self._inline_records = list(inline_records_cfg or [])
        except Exception:  # pragma: no cover - defensive
            self._inline_records = []

        # Normalize zone suffix list for NXDOMAIN behaviour.
        self._nxdomain_zones = helpers.normalize_zone_suffixes(
            self.config.get("nxdomain_zones")
        )

        # Normalize AXFR and NOTIFY configuration
        self._axfr_zones = helpers.normalize_axfr_config(axfr_cfg)
        self._axfr_loaded_once = False
        # Track AXFR zone metadata for reload timing
        self._axfr_zone_metadata: Dict[str, Dict[str, object]] = {}

        self._axfr_notify_static_targets = helpers.normalize_axfr_notify_targets(
            self.config.get("axfr_notify")
        )
        self._axfr_notify_all = bool(self.config.get("axfr_notify_all", False))
        notify_delay_raw = self.config.get("axfr_notify_scheduled")
        try:
            notify_delay = (
                int(notify_delay_raw) if notify_delay_raw is not None else None
            )
        except (TypeError, ValueError):
            notify_delay = None
        if notify_delay is not None and notify_delay < 0:
            notify_delay = None
        self._axfr_notify_delay = notify_delay
        self._axfr_notify_learned: Dict[str, Dict[str, Dict[str, object]]] = {}
        self._axfr_notify_health: Dict[str, Dict[str, object]] = {}
        self._axfr_notify_lock = threading.RLock()

        # Normalize DNS UPDATE configuration
        dns_update_cfg = self.config.get("dns_update")
        self._dns_update_config = dns_update_cfg
        if dns_update_cfg:
            self._dns_update_file_paths = update_helpers.collect_update_file_paths(
                dns_update_cfg
            )
        else:
            self._dns_update_file_paths = []
        self._dns_update_timestamps: Dict[str, float] = {}
        self._dns_update_lists_cache: Dict[str, List[str]] = {}
        self._dns_update_cache_lock = threading.RLock()

        # Initialize state and locks
        self._records_lock = threading.RLock()
        self.records: Dict[Tuple[str, int], Tuple[int, List[str]]] = {}
        self._observer = None
        self._axfr_poll_stop = None
        self._axfr_poll_thread = None
        self._axfr_poll_interval = 0.0

        # Watchdog configuration
        self._watchdog_min_interval = float(
            self.config.get("watchdog_min_interval_seconds", 1.0)
        )
        self._last_watchdog_reload_ts = 0.0
        self._reload_debounce_timer = None
        self._reload_timer_lock = threading.Lock()

        # Polling configuration
        self._poll_interval = float(
            self.config.get("watchdog_poll_interval_seconds", 60.0)
        )
        self._last_stat_snapshot = None
        self._poll_stop = None
        self._poll_thread = None

        # Initial load
        loader.load_records(self)
        self._ttl = self.config.get("ttl", 300)

        # Start watchdog if enabled
        watchdog_cfg = self.config.get("watchdog_enabled")
        if watchdog_cfg is not None:
            watchdog_enabled = bool(watchdog_cfg)
        else:
            watchdog_enabled = True

        if watchdog_enabled:
            watchdog.start_watchdog(self)

        # Optional polling fallback
        if self._poll_interval > 0.0:
            logger.info(
                "ZoneRecords polling enabled (interval_seconds=%s)",
                self._poll_interval,
            )
            self._poll_stop = threading.Event()
            watchdog.start_polling(self)

        # Optional AXFR polling
        axfr_polling.start_axfr_polling(self)

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Decide whether to override resolution for a query.

        Inputs:
          - qname: Queried domain name.
          - qtype: DNS record type (numeric code).
          - req: Raw DNS request bytes.
          - ctx: Plugin context.

        Outputs:
          - PluginDecision("override") with an authoritative DNS response when
            this plugin should answer the query, or None to allow normal processing.
        """
        return resolver.pre_resolve(self, qname, qtype, req, ctx)

    def get_http_snapshot(self) -> Dict[str, object]:
        """Brief: Summarize current ZoneRecords state for the admin web UI.

        Inputs:
          - None (uses in-memory zone mappings populated by setup()/reload).

        Outputs:
          - dict with keys:
              * summary: High-level counts.
              * zones: list of zone descriptors.
              * records: flattened list of record rows including per-value sources.

        Notes:
          - Sources are best-effort and currently derived from configured file_paths,
            bind_paths, and inline-config records.
        """

        def _parse_qtype_code(raw: object) -> Optional[int]:
            if raw is None:
                return None
            text = str(raw).strip()
            if not text:
                return None
            if text.isdigit():
                try:
                    return int(text)
                except Exception:
                    return None
            name = text.upper()
            try:
                attr_val = getattr(QTYPE, name)
            except Exception:
                attr_val = None
            if isinstance(attr_val, int):
                return int(attr_val)
            try:
                qtype_val = QTYPE.get(name, None)
            except Exception:
                qtype_val = None
            return int(qtype_val) if isinstance(qtype_val, int) else None

        def _iter_pipe_records(
            source_label: str, lines: List[str]
        ) -> List[tuple[str, int, str]]:
            out: List[tuple[str, int, str]] = []
            for raw_line in lines or []:
                try:
                    line = str(raw_line)
                except Exception:
                    continue
                # Strip inline comments and whitespace.
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) != 4:
                    continue
                owner_raw, qtype_raw, _ttl_raw, value_raw = parts
                if not owner_raw or not qtype_raw or not value_raw:
                    continue
                owner = owner_raw.rstrip(".").lower()
                qcode = _parse_qtype_code(qtype_raw)
                if qcode is None:
                    continue
                out.append((owner, int(qcode), str(value_raw)))
            return out

        # Snapshot configured sources into (owner,qtype,value)->set(source_labels).
        sources_map: Dict[tuple[str, int, str], set[str]] = {}

        # File-based records.
        file_paths = list(getattr(self, "file_paths", []) or [])
        for fp in file_paths:
            try:
                with open(str(fp), "r", encoding="utf-8") as f:
                    lines = [ln.rstrip("\n") for ln in f.readlines()]
            except Exception:
                continue
            for owner, qcode, value in _iter_pipe_records(str(fp), lines):
                sources_map.setdefault((owner, qcode, value), set()).add(str(fp))

        # Inline records.
        inline = list(getattr(self, "_inline_records", []) or [])
        for owner, qcode, value in _iter_pipe_records(
            "inline-config-records", [str(x) for x in inline]
        ):
            sources_map.setdefault((owner, qcode, value), set()).add(
                "inline-config-records"
            )

        # Safe concurrent read from mappings when a watcher may be reloading.
        lock = getattr(self, "_records_lock", None)
        if lock is None:
            records_map = dict(getattr(self, "records", {}) or {})
            name_index = dict(getattr(self, "_name_index", {}) or {})
            zone_soa = dict(getattr(self, "_zone_soa", {}) or {})
        else:
            with lock:
                records_map = dict(getattr(self, "records", {}) or {})
                name_index = dict(getattr(self, "_name_index", {}) or {})
                zone_soa = dict(getattr(self, "_zone_soa", {}) or {})

        zones: List[Dict[str, object]] = []
        for apex, entry in sorted(zone_soa.items(), key=lambda kv: str(kv[0])):
            ttl = entry[0]
            values = entry[1]
            zones.append(
                {
                    "zone": str(apex),
                    "soa_ttl": int(ttl),
                    "soa_values": list(values or []),
                }
            )

        rows: List[Dict[str, object]] = []
        for (owner, qcode), entry in sorted(
            records_map.items(), key=lambda kv: (str(kv[0][0]), int(kv[0][1]))
        ):
            ttl = entry[0]
            values = entry[1]

            owner_norm = str(owner).rstrip(".").lower()
            zone = helpers.find_zone_for_name(owner_norm, zone_soa)
            try:
                qtype_name = QTYPE.get(int(qcode), str(qcode))
            except Exception:
                qtype_name = str(qcode)

            for v in list(values or []):
                value_text = str(v)
                sources = sorted(
                    list(sources_map.get((owner_norm, int(qcode), value_text), set()))
                )
                rows.append(
                    {
                        "zone": str(zone) if zone is not None else None,
                        "owner": owner_norm,
                        "qtype": str(qtype_name),
                        "ttl": int(ttl),
                        "value": value_text,
                        "sources": sources,
                    }
                )

        summary: Dict[str, object] = {
            "zones": int(len(zones)),
            "rrsets": int(len(records_map)),
            "records": int(
                sum(len(entry[1] or []) for _k, entry in records_map.items())
            ),
            "owners": int(len(name_index)),
        }

        return {
            "summary": summary,
            "zones": zones,
            "records": rows,
        }

    def iter_zone_rrs_for_transfer(
        self, zone_apex: str, client_ip: Optional[str] = None
    ) -> Optional[list]:
        """Brief: Export authoritative RRsets for a zone for AXFR/IXFR.

        Inputs:
          - zone_apex: Zone apex name (with or without trailing dot), case-insensitive.
          - client_ip: Optional IP address of the AXFR/IXFR client.

        Outputs:
          - list[RR]: All RRs in the zone suitable for AXFR/IXFR transfer, or
            None when this plugin is not authoritative for the requested apex.
        """
        return transfer.iter_zone_rrs_for_transfer(self, zone_apex, client_ip)

    def _load_records(self) -> None:
        """Brief: Internal wrapper for record loading (called by watchdog/polling).

        Inputs:
          - None

        Outputs:
          - None
        """
        loader.load_records(self)

    def _reload_records_from_watchdog(self) -> None:
        """Brief: Internal wrapper for watchdog reload (called by watchdog handlers).

        Inputs:
          - None

        Outputs:
          - None
        """
        watchdog.reload_records_from_watchdog(self)

    def close(self) -> None:
        """Brief: Stop any background watchers and release resources.

        Inputs:
          - None

        Outputs:
          - None
        """
        observer = getattr(self, "_observer", None)
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=2.0)
            except Exception:  # pragma: no cover - defensive
                pass
            self._observer = None

        # Stop polling loop
        stop_event = getattr(self, "_poll_stop", None)
        if stop_event is not None:
            try:
                stop_event.set()
            except Exception:  # pragma: no cover - defensive
                pass

        poll_thread = getattr(self, "_poll_thread", None)
        if poll_thread is not None:
            try:
                poll_thread.join(timeout=2.0)
            except Exception:  # pragma: no cover - defensive
                pass
            self._poll_thread = None

        # Stop AXFR polling loop
        axfr_stop = getattr(self, "_axfr_poll_stop", None)
        if axfr_stop is not None:
            try:
                axfr_stop.set()
            except Exception:  # pragma: no cover - defensive
                pass

        axfr_thread = getattr(self, "_axfr_poll_thread", None)
        if axfr_thread is not None:
            try:
                axfr_thread.join(timeout=2.0)
            except Exception:  # pragma: no cover - defensive
                pass
            self._axfr_poll_thread = None

        # Cancel deferred reload timer
        timer = getattr(self, "_reload_debounce_timer", None)
        if timer is not None:
            try:
                timer.cancel()
            except Exception:  # pragma: no cover - defensive
                pass
            self._reload_debounce_timer = None


# Re-export config models for public API
__all__ = [
    "ZoneRecords",
    "ZoneRecordsConfig",
    "AxfrUpstreamConfig",
    "AxfrZoneConfig",
    "ZoneDnssecSigningConfig",
    "DnsUpdateConfig",
    "UpdateTsigKeyConfig",
    "UpdatePskTokenConfig",
    "UpdateZoneApexConfig",
]
