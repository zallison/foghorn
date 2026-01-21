from __future__ import annotations

import logging
import os
import pathlib
import threading
import time
import ipaddress
from typing import Dict, Iterable, List, Optional, Tuple

from dnslib import QTYPE, RCODE, RR, DNSHeader, DNSRecord
from pydantic import BaseModel, Field

from foghorn.servers.transports.axfr import AXFRError, axfr_transfer

try:  # watchdog is used for cross-platform file watching
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:  # pragma: no cover - defensive fallback when watchdog is unavailable
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = None  # type: ignore[assignment]

from foghorn.plugins.resolve.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

logger = logging.getLogger(__name__)


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


class ZoneRecordsConfig(BaseModel):
    """Brief: Typed configuration model for ZoneRecords.

    Inputs:
      - file_paths: Preferred list of records file paths.
      - bind_paths: Optional list of RFC-1035 style BIND zone files.
      - records: Optional list of inline records using
        ``<domain>|<qtype>|<ttl>|<value>`` format.
      - watchdog_enabled: Enable watchdog-based reloads.
      - watchdog_min_interval_seconds: Minimum seconds between reloads.
      - watchdog_poll_interval_seconds: Optional polling interval.
      - ttl: Default TTL in seconds.
      - axfr_zones: Optional list of AXFR-backed zones.

    Example:
      Minimal AXFR-only configuration (YAML):

        plugins:
          - type: zone
            hooks:
              pre_resolve: { priority: 60 }
            config:
              axfr_zones:
                - zone: example.com
                  allow_no_dnssec: false
                  upstreams:
                    - host: 192.0.2.10
                      port: 53
                      timeout_ms: 5000

    Outputs:
      - ZoneRecordsConfig instance with normalized field types.
    """

    file_paths: Optional[List[str]] = None
    bind_paths: Optional[List[str]] = None
    records: Optional[List[str]] = None
    watchdog_enabled: Optional[bool] = None
    watchdog_min_interval_seconds: float = Field(default=1.0, ge=0)
    watchdog_poll_interval_seconds: float = Field(default=0.0, ge=0)
    ttl: int = Field(default=300, ge=0)
    # Typed AXFR zones configuration with allow_no_dnssec support.
    # Runtime normalization in _normalize_axfr_config() handles both typed
    # and untyped dict inputs for backwards compatibility.
    axfr_zones: Optional[List[AxfrZoneConfig]] = None
    # Optional DNSSEC auto-signing configuration. When enabled, ZoneRecords
    # attempts to synthesize DNSKEY/RRSIG material for authoritative zones at
    # load time using foghorn.dnssec.zone_signer.
    dnssec_signing: Optional[ZoneDnssecSigningConfig] = None

    class Config:
        # Allow BasePlugin-level options (targets, targets_domains, logging, etc.)
        # to flow through this typed config model without validation errors.
        extra = "allow"


@plugin_aliases("zone", "zone_records", "custom", "records")
class ZoneRecords(BasePlugin):

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
        """
        Brief: Initialize the plugin, load record mappings, and configure watchers.

        Inputs:
          - file_paths (list[str], optional): List of records file paths
            to load and merge in order (later overrides earlier).
          - records (list[str], optional): Inline records using
            ``<domain>|<qtype>|<ttl>|<value>`` format; merged after any
            file-backed records.
          - watchdog_enabled (bool, optional): When True (default), start a
            watchdog-based observer to reload files automatically on change.
          - watchdog_poll_interval_seconds (float, optional): When greater than
            zero, enable a stat-based polling loop to detect changes even when
            filesystem events are not delivered (for example in some container
            or read-only bind-mount setups).

        Outputs:
          - None

        Example:
          Multiple files:
            ZoneRecords(file_paths=["/foghorn/conf/var/records.txt", "/etc/records.d/extra.txt"], watchdog_enabled=True)
        """

        # Normalize configuration into lists of paths, allowing either
        # file_paths/legacy file_path (custom pipe-delimited format) and/or
        # bind_paths (RFC-1035 style BIND zone files). When no filesystem
        # sources are provided but inline records are configured, file-backed
        # paths remain empty.
        provided_paths = self.config.get("file_paths")
        legacy_path = self.config.get("file_path")
        bind_paths_cfg = self.config.get("bind_paths")
        inline_records_cfg = self.config.get("records")
        axfr_cfg = self.config.get("axfr_zones")

        self.file_paths = []
        self.bind_paths: List[str] = []

        if provided_paths is not None or legacy_path is not None:
            self.file_paths = self._normalize_paths(provided_paths, legacy_path)

        if bind_paths_cfg is not None:
            # bind_paths uses the same normalisation rules as file_paths but has
            # no legacy single-path equivalent.
            self.bind_paths = self._normalize_paths(bind_paths_cfg, None)

        if not self.file_paths and not self.bind_paths:
            if inline_records_cfg or axfr_cfg:
                # Inline-only or AXFR-only configuration; no file-backed records.
                self.file_paths = []
                self.bind_paths = []
            else:
                # Preserve historical behaviour: fail fast when no sources are
                # set at all.
                self.file_paths = self._normalize_paths(None, None)

        # Cache inline records (if any) for use by _load_records().
        try:
            self._inline_records = list(inline_records_cfg or [])
        except Exception:  # pragma: no cover - defensive: config may be non-iterable
            self._inline_records = []

        # Normalize any AXFR-backed zones once; these are loaded during the
        # initial _load_records() call and intentionally skipped on subsequent
        # reloads so watchdog and polling remain file-based.
        self._axfr_zones = self._normalize_axfr_config(axfr_cfg)
        self._axfr_loaded_once = False

        # Internal synchronization and state
        self._records_lock = threading.RLock()
        # Mapping of (domain, qtype) -> (ttl, ordered list of unique values)
        self.records: Dict[Tuple[str, int], Tuple[int, List[str]]] = {}
        self._observer = None

        # Watchdog reload debouncing: avoid tight reload loops when a single
        # change event causes additional filesystem notifications (e.g. from
        # our own reload reads).
        self._watchdog_min_interval = float(
            self.config.get("watchdog_min_interval_seconds", 1.0)
        )
        self._last_watchdog_reload_ts = 0.0
        # Timer used to coalesce multiple rapid watchdog events into a single
        # deferred reload while still guaranteeing that no change is lost.
        self._reload_debounce_timer = None
        self._reload_timer_lock = threading.Lock()

        # Polling-based fallback reload behaviour (useful when filesystem
        # events are not delivered, such as in certain container or bind-mount
        # environments).
        self._poll_interval = float(
            self.config.get("watchdog_poll_interval_seconds", 0.0)
        )
        self._last_stat_snapshot = None
        self._poll_stop = None
        self._poll_thread = None

        # Initial load
        self._load_records()

        self._ttl = self.config.get("ttl", 300)

        # Optionally start watchdog-based reloads
        watchdog_cfg = self.config.get("watchdog_enabled")
        if watchdog_cfg is not None:
            watchdog_enabled = bool(watchdog_cfg)
        else:
            watchdog_enabled = True

        if watchdog_enabled:
            self._start_watchdog()

        # Optional polling-based fallback for environments where filesystem
        # events are not reliably delivered (for example some Docker or
        # network filesystems). When enabled, this runs alongside watchdog and
        # is further rate-limited by the reload debouncing in
        # _reload_records_from_watchdog.
        if self._poll_interval > 0.0:
            logger.warning(
                "ZoneRecords Watchdog falling back to polling every {self._poll_interval}"
            )
            self._poll_stop = threading.Event()
            self._start_polling()

    def _normalize_paths(
        self, file_paths: Optional[Iterable[str]], legacy: Optional[str]
    ) -> List[str]:
        """Brief: Coerce provided file path inputs into an ordered, de-duplicated list.

        Inputs:
          - file_paths: iterable of file path strings (may be None)
          - legacy: single legacy file path string (may be None)

        Outputs: - list[str]: Non-empty list of unique paths (order preserved).
        If both file_paths and legacy file_path are given, the legacy path is included in the set of file paths.

        Example:
          _normalize_paths(["/a", "/b"], None) -> ["/a", "/b"]
          _normalize_paths(["/a", "/b"], "/a") -> ["/a", "/b"]
          _normalize_paths(None, "/a") -> ["/a"]
          _normalize_paths(None, None) -> []

        """
        paths: List[str] = []
        if file_paths:
            for p in file_paths:
                paths.append(os.path.expanduser(str(p)))
        if legacy:
            # legacy is kept only for the internal API; external configs must use
            # file_paths and should never set legacy.
            paths.append(os.path.expanduser(str(legacy)))
        if not paths:
            raise ValueError(f"No paths given {self.config}")
        # De-duplicate while preserving order
        paths = list(dict.fromkeys(paths))
        return paths

    def _normalize_axfr_config(self, raw: object) -> List[Dict[str, object]]:
        """Brief: Normalize raw axfr_zones config into a list of zones.

        Inputs:
          - raw: Value from self.config.get("axfr_zones"). Expected to be a
            list of mappings, each with a "zone" key and an "upstreams" key.
            For backward compatibility a legacy "masters" key is also
            accepted and treated as "upstreams".

        Outputs:
          - list[dict]: Each entry contains:
              - "zone": lowercased apex without trailing dot.
              - "allow_no_dnssec": boolean (default True) controlling whether
                to accept transfers from zones that are unsigned or fail DNSSEC
                validation. When True (the default), transfers are accepted
                even without valid DNSSEC, matching current behaviour. When
                False, once DNSSEC validation for AXFR is implemented, zones
                without valid DNSSEC will be rejected.
              - "upstreams": list of mappings with at least:
                  - "host": upstream authoritative host/IP string.
                  - "port": integer port (default 53).
                  - "timeout_ms": integer timeout in milliseconds (default 5000).
                  - "transport": "tcp" (default) or "dot" for DNS-over-TLS.
                  - "server_name": optional TLS SNI name for DoT.
                  - "verify": boolean TLS verification flag for DoT.
                  - "ca_file": optional CA bundle path for DoT.
        """

        if raw is None:
            return []

        zones: List[Dict[str, object]] = []

        if not isinstance(raw, list):
            logger.warning(
                "ZoneRecords axfr_zones ignored: expected list, got %r", type(raw)
            )
            return zones

        for idx, entry in enumerate(raw):
            if not isinstance(entry, dict):
                logger.warning(
                    "ZoneRecords axfr_zones[%d] ignored: expected mapping, got %r",
                    idx,
                    type(entry),
                )
                continue

            zone_val = entry.get("zone")
            # Prefer the new "upstreams" key, but continue to accept legacy
            # "masters" for backwards compatibility with existing configs.
            masters_val = entry.get("upstreams")
            if masters_val is None and "masters" in entry:
                masters_val = entry.get("masters")

            zone_text = (
                str(zone_val).rstrip(".").lower() if zone_val is not None else ""
            )
            if not zone_text:
                logger.warning(
                    "ZoneRecords axfr_zones[%d] ignored: missing or empty 'zone'", idx
                )
                continue

            upstreams: List[Dict[str, object]] = []
            if isinstance(masters_val, dict):
                masters_val = [masters_val]
            if isinstance(masters_val, list):
                for midx, m in enumerate(masters_val):
                    if not isinstance(m, dict):
                        logger.warning(
                            "ZoneRecords axfr_zones[%d].upstreams[%d] ignored: expected mapping, got %r",
                            idx,
                            midx,
                            type(m),
                        )
                        continue
                    host = m.get("host")
                    if not host:
                        logger.warning(
                            "ZoneRecords axfr_zones[%d].upstreams[%d] ignored: missing 'host'",
                            idx,
                            midx,
                        )
                        continue
                    port = m.get("port", 53)
                    timeout_ms = m.get("timeout_ms", 5000)
                    transport = str(m.get("transport", "tcp")).lower()
                    if transport not in {"tcp", "dot"}:
                        logger.warning(
                            "ZoneRecords axfr_zones[%d].upstreams[%d] ignored: unsupported transport %r",
                            idx,
                            midx,
                            transport,
                        )
                        continue
                    server_name = m.get("server_name")
                    verify_flag = m.get("verify", True)
                    ca_file = m.get("ca_file")
                    try:
                        port_i = int(port)
                        timeout_i = int(timeout_ms)
                    except (TypeError, ValueError):
                        logger.warning(
                            "ZoneRecords axfr_zones[%d].upstreams[%d] ignored: invalid port/timeout %r/%r",
                            idx,
                            midx,
                            port,
                            timeout_ms,
                        )
                        continue
                    upstreams.append(
                        {
                            "host": str(host),
                            "port": port_i,
                            "timeout_ms": timeout_i,
                            "transport": transport,
                            "server_name": (
                                str(server_name) if server_name is not None else None
                            ),
                            "verify": bool(verify_flag),
                            "ca_file": str(ca_file) if ca_file is not None else None,
                        }
                    )

            if not upstreams:
                logger.warning(
                    "ZoneRecords axfr_zones[%d] for %s ignored: no usable upstreams",
                    idx,
                    zone_text,
                )
                continue

            # allow_no_dnssec controls whether to accept an AXFR even when DNSSEC
            # is missing or invalid. Default True preserves current behaviour.
            allow_no_dnssec_val = entry.get("allow_no_dnssec")
            if allow_no_dnssec_val is None:
                allow_no_dnssec = True
            else:
                allow_no_dnssec = bool(allow_no_dnssec_val)

            zones.append(
                {
                    "zone": zone_text,
                    "upstreams": upstreams,
                    "allow_no_dnssec": allow_no_dnssec,
                }
            )

        return zones

    def _load_records(self) -> None:
        """Brief: Read custom records files and build lookup structures.

        Inputs:
          - None (uses self.file_paths, any inline records from config, and,
            on the first call after setup(), any configured AXFR-backed zones).

        Outputs:
          - None (populates:
              - self.records: Dict[(domain, qtype), (ttl, [values])]
              - self._name_index: Dict[domain, Dict[qtype, (ttl, [values])]]
              - self._zone_soa: Dict[zone_apex, (ttl, [soa_values])]
            )
        """
        # Build fresh mappings so that reloads are atomic when swapped in.
        #
        # For each (domain, qtype) key we:
        #   - preserve the order in which values appear across files
        #   - de-duplicate values, keeping the first occurrence
        #   - keep the TTL from the first occurrence (later duplicates are
        #     ignored entirely)
        mapping: Dict[Tuple[str, int], Tuple[int, List[str]]] = {}
        name_index: Dict[str, Dict[int, Tuple[int, List[str]]]] = {}
        zone_soa: Dict[str, Tuple[int, List[str]]] = {}
        # Track which zone apexes have already had DNSSEC classification applied
        # via the AXFR path so that we can avoid duplicate logging when we later
        # classify zones built from local files/BIND/inline data.
        dnssec_classified_axfr: set[str] = set()

        # AXFR-backed zones are loaded only once, during the initial
        # _load_records() following setup(). Watchdog and polling reloads keep
        # using on-disk sources.
        axfr_zones = getattr(self, "_axfr_zones", None) or []
        do_axfr = bool(axfr_zones) and not getattr(self, "_axfr_loaded_once", False)

        # Resolve the SOA type code using getattr with a safe default and fall
        # back to QTYPE.get so that tests which monkeypatch QTYPE continue to
        # work as expected, without relying on QTYPE.SOA being present.
        try:
            raw = getattr(QTYPE, "SOA", None)
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            raw = None
        if raw is None:
            try:
                raw = QTYPE.get("SOA", None)
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                raw = None
        try:
            soa_code: Optional[int] = int(raw) if raw is not None else None
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            soa_code = None

        def _process_line(raw_line: str, source_label: str, lineno: int) -> None:
            """Brief: Parse a single record line and merge it into mappings.

            Inputs:
              - raw_line: Original line text including any comments.
              - source_label: Human-readable source identifier (file path or
                inline config label).
              - lineno: 1-based line number within the source.

            Outputs:
              - None; updates mapping, name_index, and zone_soa in-place.
            """
            # Remove inline comments and surrounding whitespace
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                return

            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 4:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"expected <domain>|<qtype>|<ttl>|<value>, got {raw_line!r}"
                )

            domain_raw, qtype_raw, ttl_raw, value_raw = parts
            if not domain_raw or not qtype_raw or not ttl_raw or not value_raw:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"empty field in {raw_line!r}"
                )

            domain = domain_raw.rstrip(".").lower()

            # Parse qtype as number or mnemonic (e.g., "A", "AAAA").
            qtype_code: Optional[int]
            if qtype_raw.isdigit():
                qtype_code = int(qtype_raw)
            else:
                name = qtype_raw.upper()
                # Map mnemonic qtype names to numeric codes in a way that avoids
                # dnslib raising its own DNSError (for example, "QTYPE: Invalid reverse lookup")
                # for unknown or class-like tokens such as "IN". We prefer
                # getattr(QTYPE, name) when it returns an int, and fall back to
                # QTYPE.get(name, None). Any exception or non-int result is
                # treated as an unknown qtype and turned into a clean ValueError
                # below.
                qtype_code = None
                try:
                    attr_val = getattr(QTYPE, name)
                except Exception:
                    attr_val = None
                if isinstance(attr_val, int):
                    qtype_code = int(attr_val)
                else:
                    try:
                        qtype_val = QTYPE.get(name, None)
                    except Exception:
                        qtype_val = None
                    if isinstance(qtype_val, int):
                        qtype_code = int(qtype_val)

            if qtype_code is None:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"unknown qtype {qtype_raw!r}"
                )

            try:
                ttl = int(ttl_raw)
            except ValueError as exc:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"invalid ttl {ttl_raw!r}"
                ) from exc
            if ttl < 0:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"negative ttl {ttl}"
                )

            value = value_raw

            key = (domain, int(qtype_code))
            existing = mapping.get(key)

            if existing is None:
                # First occurrence for this (domain, qtype): start a new
                # ordered list of values and remember its TTL.
                stored_ttl = ttl
                values: List[str] = []
            else:
                # Subsequent occurrences: extend the list, but only with
                # values we have not seen before. The TTL from the first
                # occurrence is retained and later duplicates are
                # dropped entirely.
                stored_ttl, values = existing

            if value not in values:
                values.append(value)

            mapping[key] = (stored_ttl, values)

            # Populate per-name index for authoritative semantics.
            per_name = name_index.setdefault(domain, {})
            per_name[int(qtype_code)] = (stored_ttl, values)

            # Track SOA records as zone apexes for authoritative zones.
            if (
                soa_code is not None
                and int(qtype_code) == int(soa_code)
                and domain not in zone_soa
            ):
                zone_soa[domain] = (stored_ttl, values)

        # First, merge custom pipe-delimited files. Earlier sources keep
        # precedence for TTL; existing values are preserved with new ones
        # appended.
        for fp in self.file_paths:
            logger.debug("reading recordfile: %s", fp)
            records_path = pathlib.Path(fp)
            with records_path.open("r", encoding="utf-8") as f:
                for lineno, raw_line in enumerate(f, start=1):
                    _process_line(raw_line, str(records_path), lineno)

        # Next, merge any RFC-1035 BIND-style zone files.
        bind_paths = getattr(self, "bind_paths", None) or []
        for fp in bind_paths:
            logger.debug("reading bind zonefile: %s", fp)
            zone_path = pathlib.Path(fp)
            try:
                text = zone_path.read_text(encoding="utf-8")
            except Exception as exc:
                raise ValueError(
                    f"Failed to read BIND zone file {zone_path}: {exc}"
                ) from exc

            try:
                rrs = RR.fromZone(text)
            except Exception as exc:
                raise ValueError(
                    f"Failed to parse BIND zone file {zone_path}: {exc}"
                ) from exc

            for rr in rrs:
                try:
                    owner = str(rr.rname).rstrip(".").lower()
                    qtype_code = int(rr.rtype)
                    ttl = int(rr.ttl)
                    value = str(rr.rdata)
                except Exception as exc:  # pragma: no cover - defensive parsing
                    logger.warning(
                        "Skipping RR %r from BIND zone %s due to parse error: %s",
                        rr,
                        zone_path,
                        exc,
                    )
                    continue

                key = (owner, int(qtype_code))
                existing = mapping.get(key)

                if existing is None:
                    stored_ttl = ttl
                    values: List[str] = []
                else:
                    stored_ttl, values = existing

                if value not in values:
                    values.append(value)

                mapping[key] = (stored_ttl, values)

                per_name = name_index.setdefault(owner, {})
                per_name[int(qtype_code)] = (stored_ttl, values)

                if (
                    soa_code is not None
                    and int(qtype_code) == int(soa_code)
                    and owner not in zone_soa
                ):
                    zone_soa[owner] = (stored_ttl, values)

        # After file- and BIND-backed zones, optionally overlay any
        # AXFR-backed zones on top. Inline records are merged last so that
        # per-instance overrides still win over transferred data.
        if do_axfr:
            for zone_cfg in axfr_zones:
                zone_name = zone_cfg.get("zone")
                upstreams = zone_cfg.get("upstreams") or []
                if not zone_name or not isinstance(upstreams, list):
                    continue
                zone_text = str(zone_name).rstrip(".").lower()
                if not zone_text:
                    continue

                transferred: Optional[List[RR]] = None
                last_error: Optional[Exception] = None

                for m in upstreams:
                    if not isinstance(m, dict):
                        continue
                    host = m.get("host")
                    port = m.get("port", 53)
                    timeout_ms = m.get("timeout_ms", 5000)
                    transport = str(m.get("transport", "tcp")).lower()
                    server_name = m.get("server_name")
                    verify_flag = m.get("verify", True)
                    ca_file = m.get("ca_file")
                    if not host:
                        continue
                    try:
                        port_i = int(port)
                        timeout_i = int(timeout_ms)
                    except (TypeError, ValueError):
                        continue

                    try:
                        logger.info(
                            "ZoneRecords AXFR: transferring %s from %s:%d via %s",
                            zone_text,
                            host,
                            port_i,
                            transport,
                        )
                        transferred = axfr_transfer(
                            str(host),
                            port_i,
                            zone_text,
                            transport=transport,
                            server_name=(
                                str(server_name) if server_name is not None else None
                            ),
                            verify=bool(verify_flag),
                            ca_file=str(ca_file) if ca_file is not None else None,
                            connect_timeout_ms=timeout_i,
                            read_timeout_ms=timeout_i,
                        )
                        break
                    except AXFRError as exc:
                        last_error = exc
                        logger.warning(
                            "ZoneRecords AXFR: failed transfer for %s from %s:%d via %s: %s",
                            zone_text,
                            host,
                            port_i,
                            transport,
                            exc,
                        )

                if not transferred:
                    if last_error is not None:
                        logger.warning(
                            "ZoneRecords AXFR: giving up on %s after error: %s",
                            zone_text,
                            last_error,
                        )
                    continue

                # Minimal DNSSEC classification for AXFR-backed zones: check
                # whether apex DNSKEY and/or RRSIG RRsets are present. This does
                # not perform full cryptographic verification; it only
                # distinguishes between "no DNSSEC", "partial" (one of
                # DNSKEY/RRSIG missing), and "present".
                try:
                    apex_owner = zone_text.rstrip(".")
                    has_dnskey = False
                    has_rrsig = False
                    try:
                        dnskey_code = int(QTYPE.DNSKEY)
                    except Exception:  # pragma: no cover - defensive
                        dnskey_code = 48
                    try:
                        rrsig_code = int(QTYPE.RRSIG)
                    except Exception:  # pragma: no cover - defensive
                        rrsig_code = 46

                    for rr in transferred:
                        try:
                            owner_norm = str(rr.rname).rstrip(".").lower()
                        except Exception:  # pragma: no cover - defensive
                            owner_norm = str(rr.rname).lower()
                        if owner_norm != apex_owner:
                            continue
                        if int(rr.rtype) == int(dnskey_code):
                            has_dnskey = True
                        if int(rr.rtype) == int(rrsig_code):
                            has_rrsig = True

                    if has_dnskey and has_rrsig:
                        dnssec_state = "present"
                    elif has_dnskey or has_rrsig:
                        dnssec_state = "partial"
                    else:
                        dnssec_state = "none"

                    allow_no_dnssec = bool(zone_cfg.get("allow_no_dnssec", True))
                    if dnssec_state in {"none", "partial"}:
                        # For now we always load the zone but surface a warning
                        # when DNSSEC data is missing or incomplete. The
                        # allow_no_dnssec flag can be used by future callers to
                        # tighten this into a hard reject policy without
                        # changing config shape.
                        if not allow_no_dnssec:
                            logger.warning(
                                "ZoneRecords AXFR: zone %s has dnssec_state=%s with "
                                "allow_no_dnssec=False; loading anyway",
                                zone_text,
                                dnssec_state,
                            )
                        else:
                            logger.info(
                                "ZoneRecords AXFR: zone %s has dnssec_state=%s; "
                                "proceeding (allow_no_dnssec=True)",
                                zone_text,
                                dnssec_state,
                            )
                    else:
                        logger.info(
                            "ZoneRecords AXFR: zone %s has dnssec_state=present",
                            zone_text,
                        )
                    # Remember that we have classified this apex so that the
                    # later per-zone classification pass does not emit
                    # duplicate log lines for the same zone.
                    dnssec_classified_axfr.add(zone_text)
                except Exception:  # pragma: no cover - defensive logging only
                    logger.warning(
                        "ZoneRecords AXFR: failed to classify DNSSEC state for %s",
                        zone_text,
                        exc_info=True,
                    )

                for rr in transferred:
                    try:
                        owner = str(rr.rname).rstrip(".").lower()
                        qtype_code = int(rr.rtype)
                        ttl = int(rr.ttl)
                        value = str(rr.rdata)
                    except Exception as exc:  # pragma: no cover - defensive parsing
                        logger.warning(
                            "Skipping RR %r from AXFR zone %s due to parse error: %s",
                            rr,
                            zone_text,
                            exc,
                        )
                        continue

                    key = (owner, int(qtype_code))
                    existing = mapping.get(key)

                    if existing is None:
                        stored_ttl = ttl
                        values_ax: List[str] = []
                    else:
                        stored_ttl, values_ax = existing

                    if value not in values_ax:
                        values_ax.append(value)

                    mapping[key] = (stored_ttl, values_ax)

                    per_name_ax = name_index.setdefault(owner, {})
                    per_name_ax[int(qtype_code)] = (stored_ttl, values_ax)

                    if (
                        soa_code is not None
                        and int(qtype_code) == int(soa_code)
                        and owner not in zone_soa
                    ):
                        zone_soa[owner] = (stored_ttl, values_ax)

            # Mark that we have attempted AXFR loading so subsequent reloads do
            # not re-transfer zones.
            self._axfr_loaded_once = True

        # Finally, merge any inline records from plugin configuration. These
        # are processed last so that per-instance overrides win over file-,
        # BIND-, and AXFR-backed data.
        inline_records = getattr(self, "_inline_records", None) or []
        for lineno, raw_line in enumerate(inline_records, start=1):
            try:
                text = str(raw_line)
            except Exception as exc:  # pragma: no cover - defensive: log and skip
                logger.warning(
                    "Skipping non-string inline record at index %d: %r (%s)",
                    lineno,
                    raw_line,
                    exc,
                )
                continue
            _process_line(text, "inline-config-records", lineno)

        # If no SOA records were explicitly defined but we have at least one
        # RRset, attempt to infer a reasonable zone apex from owner names and
        # synthesize a minimal SOA there. This makes it easier to use
        # ZoneRecords for small zones without hand-writing SOA records, while
        # still enabling DNSSEC auto-signing and authoritative behaviour.
        if not zone_soa:
            try:
                # Prefer SSHFP owner names when present (historical behaviour);
                # otherwise fall back to all non-SOA owner names.
                candidate_names: List[str] = []

                for (owner_name, qcode), (_ttl_val, _vals) in mapping.items():
                    # Skip any explicit SOA owner; those already define an
                    # authoritative apex when present.
                    if soa_code is not None and int(qcode) == int(soa_code):
                        continue
                    candidate_names.append(str(owner_name))

                if candidate_names:
                    # Compute a common suffix across candidate owner names and
                    # use that as the synthesized apex when it has at least two
                    # labels (to avoid creating an apex like "com").
                    label_lists = [
                        str(n).rstrip(".").lower().split(".") for n in candidate_names
                    ]
                    common_suffix_rev: List[str] = list(reversed(label_lists[0]))
                    for labels in label_lists[1:]:
                        rev = list(reversed(labels))
                        i = 0
                        while (
                            i < len(common_suffix_rev)
                            and i < len(rev)
                            and common_suffix_rev[i] == rev[i]
                        ):
                            i += 1
                        common_suffix_rev = common_suffix_rev[:i]
                        if not common_suffix_rev:
                            break

                    # Decide whether this common suffix is an acceptable
                    # synthesized apex. We always accept suffixes with two or
                    # more labels (e.g. "sshfp.test"). When the suffix is a
                    # single label, we only accept it when it matches the
                    # configured use_tld option (for example, "zaa" or
                    # "corp"), allowing private TLD-style zones.
                    accept_suffix = False
                    if len(common_suffix_rev) >= 2:
                        accept_suffix = True
                    elif len(common_suffix_rev) == 1:
                        # For single-label suffixes (e.g. ".lan", ".corp"), only
                        # accept them as an apex when explicitly configured via
                        # dnssec_signing.use_tld so operators can opt in to
                        # private TLD-style zones.
                        try:
                            cfg = getattr(self, "config", {})  # type: ignore[union-attr]
                            dnssec_cfg = (
                                cfg.get("dnssec_signing")
                                if isinstance(cfg, dict)
                                else None
                            )
                            cfg_tld = None
                            if isinstance(dnssec_cfg, dict):
                                cfg_tld = dnssec_cfg.get("use_tld")
                        except Exception:  # pragma: no cover - defensive
                            cfg_tld = None
                        if cfg_tld:
                            suffix_label = common_suffix_rev[0].lower()
                            if suffix_label == str(cfg_tld).rstrip(".").lower():
                                accept_suffix = True

                    if accept_suffix:
                        inferred_apex = ".".join(reversed(common_suffix_rev))
                        if inferred_apex not in zone_soa:
                            # Use the plugin-level default TTL for the SOA when
                            # available; fall back to 300s.
                            try:
                                default_ttl = int(self.config.get("ttl", 300))  # type: ignore[union-attr]
                            except Exception:  # pragma: no cover - defensive
                                default_ttl = 300
                            # Construct a very simple SOA with a fixed serial
                            # and conservative timers; operators can override by
                            # adding an explicit SOA line if needed.
                            soa_rdata = (
                                f"ns1.{inferred_apex}. hostmaster.{inferred_apex}. "
                                "1 3600 600 604800 300"
                            )
                            synthetic_line = (
                                f"{inferred_apex}|SOA|{default_ttl}|{soa_rdata}"
                            )
                            _process_line(synthetic_line, "auto-soa", 0)
            except Exception:  # pragma: no cover - defensive logging only
                logger.warning(
                    "ZoneRecords: failed to synthesize SOA for inferred zone apex",
                    exc_info=True,
                )

        # Auto-generate reverse PTR records for A and AAAA RRsets only.
        #
        # For each owner with A/AAAA records whose rdata parses as an IP
        # address, synthesize a PTR RR in the corresponding in-addr.arpa or
        # ip6.arpa zone, pointing back to the owner name. Explicit PTR records
        # from any source are preserved: they determine the TTL and initial
        # values; generated PTR targets are only appended when not already
        # present.
        try:
            try:
                a_code = int(QTYPE.A)
            except Exception:  # pragma: no cover - defensive
                a_code = 1
            try:
                aaaa_code = int(QTYPE.AAAA)
            except Exception:  # pragma: no cover - defensive
                aaaa_code = 28
            try:
                ptr_code = int(QTYPE.PTR)
            except Exception:  # pragma: no cover - defensive
                ptr_code = 12

            for owner_name, rrsets in list(name_index.items()):
                # owner_name is already normalized (no trailing dot, lowercased).
                owner_norm = str(owner_name).rstrip(".").lower()

                for rr_qtype in (a_code, aaaa_code):
                    if rr_qtype not in rrsets:
                        continue
                    ttl_val, vals = rrsets[rr_qtype]
                    for v in list(vals):
                        try:
                            ip_obj = ipaddress.ip_address(str(v))
                        except ValueError:
                            # Not a literal IP; do not attempt to synthesize PTR.
                            continue

                        # Only generate PTR when the RR type matches the IP
                        # family (A+IPv4, AAAA+IPv6).
                        if ip_obj.version == 4 and rr_qtype != a_code:
                            continue
                        if ip_obj.version == 6 and rr_qtype != aaaa_code:
                            continue

                        reverse_owner = ip_obj.reverse_pointer.rstrip(".").lower()
                        ptr_target = owner_norm + "."
                        key_ptr = (reverse_owner, int(ptr_code))
                        existing_ptr = mapping.get(key_ptr)
                        if existing_ptr is None:
                            stored_ttl = int(ttl_val)
                            ptr_vals: List[str] = []
                        else:
                            stored_ttl, ptr_vals = existing_ptr

                        if ptr_target not in ptr_vals:
                            ptr_vals.append(ptr_target)

                        mapping[key_ptr] = (stored_ttl, ptr_vals)
                        per_name_ptr = name_index.setdefault(reverse_owner, {})
                        per_name_ptr[int(ptr_code)] = (stored_ttl, ptr_vals)
        except Exception:  # pragma: no cover - defensive logging only
            logger.warning(
                "ZoneRecords: failed to auto-generate PTR records from A/AAAA",
                exc_info=True,
            )

        # After building mappings from all sources, classify DNSSEC state for
        # each authoritative zone apex derived from local sources (file_paths,
        # bind_paths, inline records). Zones that were already classified via
        # the AXFR path above are skipped to avoid duplicate log messages.
        try:
            try:
                dnskey_code_all = int(QTYPE.DNSKEY)
            except Exception:  # pragma: no cover - defensive
                dnskey_code_all = 48
            try:
                rrsig_code_all = int(QTYPE.RRSIG)
            except Exception:  # pragma: no cover - defensive
                rrsig_code_all = 46

            for apex_owner in list(zone_soa.keys()):
                if apex_owner in dnssec_classified_axfr:
                    continue
                owner_rrsets = name_index.get(apex_owner, {}) or {}
                has_dnskey = int(dnskey_code_all) in owner_rrsets
                has_rrsig = int(rrsig_code_all) in owner_rrsets
                if has_dnskey and has_rrsig:
                    dnssec_state = "present"
                elif has_dnskey or has_rrsig:
                    dnssec_state = "partial"
                else:
                    dnssec_state = "none"
                logger.info(
                    "ZoneRecords zone %s has dnssec_state=%s (file/bind/inline)",
                    apex_owner,
                    dnssec_state,
                )
        except Exception:  # pragma: no cover - defensive logging only
            logger.warning(
                "ZoneRecords: failed to classify DNSSEC state for local zones",
                exc_info=True,
            )

        # Optional DNSSEC auto-signing of authoritative zones when configured.
        dnssec_cfg_raw = (
            self.config.get("dnssec_signing") if hasattr(self, "config") else None
        )
        enabled = False
        if isinstance(dnssec_cfg_raw, dict):
            enabled = bool(dnssec_cfg_raw.get("enabled", False))
        if enabled:
            try:
                import datetime as _dt

                import dns.name as _dns_name
                import dns.rdata as _dns_rdata
                import dns.rdataclass as _dns_rdataclass
                import dns.rdatatype as _dns_rdatatype
                import dns.rrset as _dns_rrset
                import dns.zone as _dns_zone

                from foghorn.dnssec import zone_signer as _zs

                keys_dir_cfg = dnssec_cfg_raw.get("keys_dir")
                algorithm = dnssec_cfg_raw.get("algorithm") or "ECDSAP256SHA256"
                generate_policy = dnssec_cfg_raw.get("generate") or "maybe"
                validity_days = int(dnssec_cfg_raw.get("validity_days") or 30)

                for apex_owner in list(zone_soa.keys()):
                    origin_text = apex_owner.rstrip(".").lower() + "."
                    origin = _dns_name.from_text(origin_text)

                    zone_obj = _dns_zone.Zone(origin)

                    for owner, rrsets in name_index.items():
                        try:
                            owner_norm = str(owner).rstrip(".").lower()
                        except Exception:  # pragma: no cover - defensive
                            owner_norm = str(owner).lower()

                        if owner_norm != apex_owner and not owner_norm.endswith(
                            "." + apex_owner
                        ):
                            continue

                        owner_name = _dns_name.from_text(owner_norm + ".")
                        node_obj = zone_obj.find_node(owner_name, create=True)

                        for qtype_code, (ttl_val, vals) in rrsets.items():
                            if int(qtype_code) == int(rrsig_code_all):
                                continue
                            if int(qtype_code) == int(dnskey_code_all):
                                continue

                            rr_type_name = QTYPE.get(qtype_code, str(qtype_code))
                            try:
                                rdtype = _dns_rdatatype.from_text(str(rr_type_name))
                            except Exception:  # pragma: no cover - defensive
                                continue

                            rrset_obj = _dns_rrset.RRset(
                                owner_name,
                                _dns_rdataclass.IN,
                                rdtype,
                            )
                            for v in list(vals):
                                try:
                                    rdata_obj = _dns_rdata.from_text(
                                        _dns_rdataclass.IN, rdtype, str(v)
                                    )
                                except Exception:  # pragma: no cover - defensive
                                    continue
                                rrset_obj.add(rdata_obj, int(ttl_val))

                            node_obj.replace_rdataset(rrset_obj)

                    if keys_dir_cfg is not None:
                        keys_dir_path = pathlib.Path(str(keys_dir_cfg)).expanduser()
                    else:
                        keys_dir_path = pathlib.Path(".")

                    try:
                        (
                            ksk_private,
                            zsk_private,
                            ksk_dnskey,
                            zsk_dnskey,
                        ) = _zs.ensure_zone_keys(
                            origin_text,
                            keys_dir_path,
                            algorithm=algorithm,
                            generate_policy=generate_policy,
                        )
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning(
                            "ZoneRecords DNSSEC auto-sign skipped for %s: %s",
                            apex_owner,
                            exc,
                        )
                        continue

                    now = _dt.datetime.utcnow()
                    inception = now - _dt.timedelta(hours=1)
                    expiration = now + _dt.timedelta(days=validity_days)
                    alg_enum = _zs.ALGORITHM_MAP[algorithm][0]

                    _zs.sign_zone(
                        zone_obj,
                        origin,
                        ksk_private,
                        zsk_private,
                        ksk_dnskey,
                        zsk_dnskey,
                        alg_enum,
                        inception,
                        expiration,
                    )

                    for owner_name, node_obj in zone_obj.items():
                        try:
                            # Normalise owner names to absolute DNS names before
                            # deriving the internal key so that apex records are
                            # stored under the real zone apex (e.g. "zaa")
                            # rather than BIND-style relative forms such as
                            # "@". This ensures later lookups using the
                            # authoritative apex string can find DNSKEY/RRSIG
                            # RRsets correctly.
                            if isinstance(owner_name, _dns_name.Name):
                                owner_abs = owner_name
                            else:
                                owner_abs = _dns_name.from_text(str(owner_name))
                            if not owner_abs.is_absolute():
                                owner_abs = owner_abs.derelativize(origin)
                            owner_norm = owner_abs.to_text().rstrip(".").lower()
                        except Exception:  # pragma: no cover - defensive
                            owner_norm = str(owner_name).rstrip(".").lower()

                        for rdataset in node_obj:
                            if rdataset.rdtype not in (
                                _dns_rdatatype.DNSKEY,
                                _dns_rdatatype.RRSIG,
                            ):
                                continue

                            if rdataset.rdtype == _dns_rdatatype.DNSKEY:
                                qcode = int(dnskey_code_all)
                            else:
                                qcode = int(rrsig_code_all)

                            key = (owner_norm, qcode)
                            existing = mapping.get(key)
                            if existing is None:
                                stored_ttl = int(getattr(rdataset, "ttl", 0) or 0)
                                vals_list: List[str] = []
                            else:
                                stored_ttl, vals_list = existing

                            for rdata_obj in list(rdataset):
                                try:
                                    value_text = rdata_obj.to_text()
                                except Exception:  # pragma: no cover - defensive
                                    continue
                                if value_text not in vals_list:
                                    vals_list.append(value_text)

                            mapping[key] = (stored_ttl, vals_list)
                            per_name = name_index.setdefault(owner_norm, {})
                            per_name[qcode] = (stored_ttl, vals_list)

            except Exception:  # pragma: no cover - defensive logging only
                logger.warning(
                    "ZoneRecords: DNSSEC auto-signing failed; leaving zones unsigned",
                    exc_info=True,
                )

        # Build a helper mapping that groups RRsets by qtype and owner name
        # and, when RRSIGs exist for a particular RRset, associates the RRSIG
        # records with the covered qtype. This is used at query time to build
        # answer sections and attach the corresponding RRSIGs alongside their
        # covered RRsets without having to re-parse textual representations.
        try:
            try:
                rrsig_code_idx = int(QTYPE.RRSIG)
            except Exception:  # pragma: no cover - defensive
                rrsig_code_idx = 46

            # First, index RRSIG rdata by (owner, covered_type). We only track
            # the presentation text here; the TTL for signatures is derived from
            # the covered RRset's TTL when we build the per-qtype mapping so
            # that RRSIG TTLs match their RRset, defaulting to 300 when needed.
            rrsig_cover: Dict[Tuple[str, int], List[str]] = {}
            for (owner_name_idx, qcode_idx), (ttl_idx, vals_idx) in mapping.items():
                if int(qcode_idx) != int(rrsig_code_idx):
                    continue
                owner_norm_idx = str(owner_name_idx).rstrip(".").lower()
                for v_idx in list(vals_idx):
                    try:
                        parts = str(v_idx).split()
                    except Exception:  # pragma: no cover - defensive
                        continue
                    if not parts:
                        continue
                    covered_name = parts[0].upper()
                    covered_code: Optional[int] = None
                    try:
                        attr_val = getattr(QTYPE, covered_name)
                    except Exception:
                        attr_val = None
                    if isinstance(attr_val, int):
                        covered_code = int(attr_val)
                    else:
                        try:
                            qval = QTYPE.get(covered_name, None)
                        except Exception:
                            qval = None
                        if isinstance(qval, int):
                            covered_code = int(qval)
                    if covered_code is None:
                        continue
                    key_idx = (owner_norm_idx, covered_code)
                    bucket = rrsig_cover.setdefault(key_idx, [])
                    bucket.append(str(v_idx))

            # Next, pre-build dnslib.RR objects for each (qtype, owner) pair,
            # appending any matching RRSIGs for the covered type. The resulting
            # structure is stored on self.mapping as:
            #   self.mapping[qtype][owner_without_trailing_dot] -> List[RR]
            mapping_by_qtype: Dict[int, Dict[str, List[RR]]] = {}
            for (owner_name_idx, qcode_idx), (ttl_idx, vals_idx) in mapping.items():
                owner_norm_idx = str(owner_name_idx).rstrip(".").lower()
                qcode_int = int(qcode_idx)

                # Skip bare RRSIG RRsets here; they are attached to the covered
                # type's bucket using rrsig_cover above.
                if qcode_int == int(rrsig_code_idx):
                    continue

                rr_type_name_idx = QTYPE.get(qcode_int, str(qcode_int))
                rr_list: List[RR] = []

                # Base RRset for this owner/qtype.
                for v_idx in list(vals_idx):
                    zone_line_idx = f"{owner_norm_idx}. {int(ttl_idx)} IN {rr_type_name_idx} {v_idx}"
                    try:
                        built = RR.fromZone(zone_line_idx)
                    except Exception:  # pragma: no cover - defensive
                        continue
                    rr_list.extend(built)

                # Attach any RRSIGs that cover this RRset, if present. Use the
                # same TTL as the covered RRset (ttl_idx), falling back to 300
                # when the stored TTL is zero or missing.
                sig_entries = rrsig_cover.get((owner_norm_idx, qcode_int), [])
                for v_sig in sig_entries:
                    ttl_sig = int(ttl_idx) or 300
                    zone_line_sig = f"{owner_norm_idx}. {ttl_sig} IN RRSIG {v_sig}"
                    try:
                        built_sig = RR.fromZone(zone_line_sig)
                    except Exception:  # pragma: no cover - defensive
                        continue
                    rr_list.extend(built_sig)

                if not rr_list:
                    continue

                by_name = mapping_by_qtype.setdefault(qcode_int, {})
                by_name[owner_norm_idx] = rr_list
        except Exception:  # pragma: no cover - defensive logging only
            logger.warning(
                "ZoneRecords: failed to build DNSSEC helper mapping; falling back to per-query construction",
                exc_info=True,
            )
            mapping_by_qtype = {}

        lock = getattr(self, "_records_lock", None)

        if lock is None:
            self.records = mapping
            self._name_index = name_index
            self._zone_soa = zone_soa
            self.mapping = mapping_by_qtype
        else:
            with lock:
                self.records = mapping
                self._name_index = name_index
                self._zone_soa = zone_soa
                self.mapping = mapping_by_qtype

    def _find_zone_for_name(self, name: str) -> Optional[str]:
        """Brief: Find the longest-matching authoritative zone apex for a name.

        Inputs:
          - name: Lowercased domain name without trailing dot.

        Outputs:
          - The matching zone apex string, or None when no authoritative zone
            covers this name.

        Example:
          Given zones {"example.com", "sub.example.com"}:
            _find_zone_for_name("www.sub.example.com") -> "sub.example.com"
            _find_zone_for_name("other.example.com") -> "example.com"
            _find_zone_for_name("example.org") -> None
        """
        zones = getattr(self, "_zone_soa", None) or {}
        best: Optional[str] = None
        for apex in zones.keys():
            if name == apex or name.endswith("." + apex):
                if best is None or len(apex) > len(best):
                    best = apex
        return best

    def iter_zone_rrs_for_transfer(self, zone_apex: str) -> Optional[List[RR]]:
        """Brief: Export authoritative RRsets for a zone for AXFR/IXFR.

        Inputs:
          - zone_apex: Zone apex name (with or without trailing dot), case-
            insensitive.

        Outputs:
          - list[RR]: All RRs in the zone suitable for AXFR/IXFR transfer, or
            None when this plugin is not authoritative for the requested apex.

        Notes:
          - The returned list is a snapshot built under the records lock so
            mid-transfer reloads do not change the view.
          - DNSSEC-related RR types (for example, DNSKEY, RRSIG) are included
            when present in the zone data; AXFR-specific DNSSEC policy is
            intentionally out of scope for this helper.
        """

        # Normalize apex and check whether this plugin is authoritative.
        apex = str(zone_apex).rstrip(".").lower() if zone_apex is not None else ""
        if not apex:
            return None

        lock = getattr(self, "_records_lock", None)

        if lock is None:
            name_index = dict(getattr(self, "_name_index", {}) or {})
            zone_soa = dict(getattr(self, "_zone_soa", {}) or {})
        else:
            with lock:
                name_index = dict(getattr(self, "_name_index", {}) or {})
                zone_soa = dict(getattr(self, "_zone_soa", {}) or {})

        if apex not in zone_soa:
            return None

        rrs: List[RR] = []

        # Walk all owners inside this zone. An owner belongs to the zone when it
        # is equal to the apex or is a strict subdomain.
        for owner, rrsets in name_index.items():
            try:
                owner_norm = str(owner).rstrip(".").lower()
            except Exception:  # pragma: no cover - defensive
                owner_norm = str(owner).lower()

            if owner_norm != apex and not owner_norm.endswith("." + apex):
                continue

            for qtype_code, (ttl, values) in rrsets.items():
                rr_type_name = QTYPE.get(qtype_code, str(qtype_code))
                for value in values:
                    zone_line = f"{owner_norm}. {ttl} IN {rr_type_name} {value}"
                    try:
                        parsed = RR.fromZone(zone_line)
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning(
                            "ZoneRecords transfer: skipping RR %r for %s type %s: %s",
                            value,
                            owner_norm,
                            rr_type_name,
                            exc,
                        )
                        continue
                    rrs.extend(parsed)

        return rrs

    def _client_wants_dnssec(self, request: object) -> bool:
        """Brief: Detect whether the client wants DNSSEC records via EDNS(0) DO bit.

        Inputs:
          - request: Parsed DNSRecord or raw bytes from the client query.

        Outputs:
          - bool: True if the client sent an OPT RR with DO=1, False otherwise.
        """
        try:
            # Support both parsed DNSRecord and raw bytes.
            if isinstance(request, (bytes, bytearray)):
                request = DNSRecord.parse(request)

            for rr in getattr(request, "ar", None) or []:
                if getattr(rr, "rtype", None) != QTYPE.OPT:
                    continue
                # EDNS flags are encoded in the TTL field of the OPT RR.
                # DO bit is bit 15 (0x8000) of the flags portion (lower 16 bits).
                ttl_val = int(getattr(rr, "ttl", 0) or 0)
                flags = ttl_val & 0xFFFF
                if flags & 0x8000:
                    return True
        except Exception:  # pragma: no cover - defensive
            pass
        return False

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
            this plugin should answer the query, or None to allow normal cache
            and upstream processing.

        Behaviour:
          - For names inside an authoritative zone (identified by SOA records
            in the records files), act as an authoritative server: apply
            correct CNAME and QTYPE.ANY semantics and synthesize NODATA and
            NXDOMAIN responses with SOA in the authority section.
          - For names outside any authoritative zone, preserve the historical
            behaviour and only answer when there is an exact (name, qtype)
            entry, falling through to upstreams otherwise.
          - When the client advertises EDNS(0) with DO=1, include RRSIG and
            DNSKEY RRsets from the zone data in positive answers.
        """
        # Normalize domain to a consistent lookup key.
        try:
            name = str(qname).rstrip(".").lower()
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            name = str(qname).lower()

        qtype_int = int(qtype)
        type_name = QTYPE.get(qtype_int, str(qtype_int))

        # Attach qname to the context so BasePlugin can enforce domain-level
        # targeting (targets_domains/targets_domains_mode) via self.targets.
        try:
            if ctx is not None:
                setattr(ctx, "qname", qname)
        except Exception:  # pragma: no cover - defensive
            pass

        # Honour BasePlugin client/listener/domain targeting. When no targets
        # are configured, this is a cheap no-op and always returns True.
        try:
            if ctx is not None and not self.targets(ctx):
                return None
        except Exception:  # pragma: no cover - defensive
            # If targeting evaluation fails for any reason, fall back to the
            # historical behaviour of applying ZoneRecords globally.
            logger.warning(
                "ZoneRecords: targets() evaluation failed; applying globally",
                exc_info=True,
            )
        logger.debug("pre-resolve zone-records %s %s", name, type_name)

        # Safe concurrent read from mappings when a watcher may be reloading.
        lock = getattr(self, "_records_lock", None)
        if lock is None:
            records = getattr(self, "records", {})
            name_index = getattr(self, "_name_index", {})
            zone_soa = getattr(self, "_zone_soa", {})
        else:
            with lock:
                records = dict(getattr(self, "records", {}))
                name_index = dict(getattr(self, "_name_index", {}))
                zone_soa = dict(getattr(self, "_zone_soa", {}))

        zone_apex = self._find_zone_for_name(name)

        # Helper to build RRs from a single RRset, preferring the pre-built
        # self.mapping index when available so that RRSIGs can be attached
        # alongside their covered RRsets.
        def _add_rrset(
            reply: DNSRecord,
            owner_name: str,
            rr_qtype: int,
            ttl: int,
            values: List[str],
        ) -> bool:
            owner_key = str(owner_name).rstrip(".").lower()
            added_any = False

            # Determine the numeric RRSIG type code once so we can reliably
            # distinguish signature RRs from their covered RRsets when adding
            # them to the reply sections.
            try:
                rrsig_code_local = int(QTYPE.RRSIG)
            except Exception:  # pragma: no cover - defensive
                rrsig_code_local = 46

            def _add_rr_to_reply(rr: RR) -> None:
                """Route DNSSEC signatures to the additional section.

                Inputs:
                  - rr: Fully constructed dnslib.RR instance.

                Outputs:
                  - None; mutates ``reply`` in-place by appending either to the
                    answer or additional section.
                """

                try:
                    rr_type_int = int(getattr(rr, "rtype", 0))
                except Exception:  # pragma: no cover - defensive
                    rr_type_int = 0

                if rr_type_int == rrsig_code_local:
                    reply.add_ar(rr)
                else:
                    reply.add_answer(rr)

            # Prefer the helper mapping constructed at load time when present.
            try:
                mapping_by_qtype = getattr(self, "mapping", None)
            except Exception:  # pragma: no cover - defensive
                mapping_by_qtype = None

            if isinstance(mapping_by_qtype, dict):
                by_name = mapping_by_qtype.get(int(rr_qtype), {}) or {}
                rrs = by_name.get(owner_key)
                if rrs:
                    for rr in list(rrs):
                        _add_rr_to_reply(rr)
                        added_any = True

            if added_any:
                return True

            # Fallback: construct RRs from textual TTL/value pairs as before.
            rr_type_name = QTYPE.get(rr_qtype, str(rr_qtype))
            for value in values:
                zone_line = f"{owner_name} {ttl} IN {rr_type_name} {value}"
                try:
                    rrs = RR.fromZone(zone_line)
                except Exception as exc:  # pragma: no cover - invalid record value
                    logger.warning(
                        "ZoneRecords invalid value %r for qtype %s: %s",
                        value,
                        rr_type_name,
                        exc,
                    )
                    continue
                for rr in rrs:
                    _add_rr_to_reply(rr)
                    added_any = True
            return added_any

        # If this name is not covered by any authoritative zone, preserve the
        # legacy exact-match override behaviour keyed by (name, qtype).
        if zone_apex is None:
            key = (name, qtype_int)
            entry = records.get(key)
            if not entry:
                return None

            ttl, values = entry
            logger.info(
                "ZoneRecords got entry for %s %s -> %s", name, type_name, values
            )

            try:
                request = DNSRecord.parse(req)
            except Exception as e:  # pragma: no cover - defensive parsing
                logger.warning("ZoneRecords parse failure: %s", e)
                return None

            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, ad=1), q=request.q
            )
            owner = str(request.q.qname).rstrip(".") + "."

            added = _add_rrset(reply, owner, qtype_int, ttl, list(values))
            if not added:
                return None

            return PluginDecision(action="override", response=reply.pack())

        # Authoritative path: name is inside a zone managed by this plugin.
        try:
            request = DNSRecord.parse(req)
        except Exception as e:  # pragma: no cover - defensive parsing
            logger.warning("ZoneRecords parse failure (authoritative path): %s", e)
            return None

        # Detect whether the client wants DNSSEC records via EDNS(0) DO bit.
        want_dnssec = self._client_wants_dnssec(request)

        # When ZoneRecords DNSSEC auto-signing is enabled for authoritative
        # zones, treat DNSSEC material (RRSIG/DNSKEY) as always desired so that
        # A/AAAA and other answers include their covering signatures even when
        # stub resolvers do not explicitly set the DO bit. Keep track of this as
        # a separate flag so that legacy behaviour (RRSIGs only when DO=1) is
        # preserved for zones that are merely pre-signed via inline records.
        dnssec_signing_enabled = False
        try:
            dnssec_cfg = (
                self.config.get("dnssec_signing") if hasattr(self, "config") else None
            )
            if isinstance(dnssec_cfg, dict) and dnssec_cfg.get("enabled"):
                dnssec_signing_enabled = True
                want_dnssec = True
        except Exception:  # pragma: no cover - defensive: config inspection only
            dnssec_signing_enabled = False

        owner = str(request.q.qname).rstrip(".") + "."
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, ad=1), q=request.q
        )

        rrsets = name_index.get(name, {})
        cname_code = int(QTYPE.CNAME)

        # DNSSEC RR type codes for filtering and inclusion.
        try:
            dnskey_code = int(QTYPE.DNSKEY)
        except Exception:  # pragma: no cover - defensive
            dnskey_code = 48

        def _add_dnssec_rrsets(
            reply: DNSRecord,
            owner_name: str,
            owner_rrsets: Dict[int, Tuple[int, List[str]]],
            zone_apex_name: str,
        ) -> None:
            """Brief: Append DNSSEC RRsets when present.

            Inputs:
              - reply: DNSRecord being built.
              - owner_name: Owner name with trailing dot.
              - owner_rrsets: RRsets dict for this owner.
              - zone_apex_name: Apex of the authoritative zone (no trailing dot).

            Outputs:
              - None; mutates reply by adding DNSKEY answers when appropriate.

            Notes:
              - Per-RRset RRSIGs (for A, SSHFP, DNSKEY, etc.) are attached via
                the pre-built helper mapping in _add_rrset, so this helper must
                not blindly add all owner RRSIGs again.
            """
            owner_normalized = owner_name.rstrip(".").lower()

            # At the zone apex, include DNSKEY RRsets when present; their
            # signatures will be attached by _add_rrset using self.mapping
            # where available.
            if owner_normalized == zone_apex_name:
                apex_rrsets = name_index.get(zone_apex_name, {})
                if dnskey_code in apex_rrsets:
                    ttl_dk, vals_dk = apex_rrsets[dnskey_code]
                    _add_rrset(reply, owner_name, dnskey_code, ttl_dk, list(vals_dk))

        # CNAME at owner name: always answer with CNAME regardless of qtype.
        if cname_code in rrsets:
            ttl_cname, cname_values = rrsets[cname_code]
            # Ignore any other RRsets at this name to avoid illegal CNAME
            # coexistence; log once if there are extras.
            if len(rrsets) > 1:
                logger.warning(
                    "CustomRecords zone %s has CNAME and other RRsets at %s; "
                    "answering with CNAME only",
                    zone_apex,
                    name,
                )
            added = _add_rrset(reply, owner, cname_code, ttl_cname, list(cname_values))
            if not added:
                return None
            # When client wants DNSSEC, add RRSIG for the CNAME.
            if want_dnssec:
                _add_dnssec_rrsets(reply, owner, rrsets, zone_apex)
            return PluginDecision(action="override", response=reply.pack())

        # No CNAME at this owner; distinguish positive, NODATA, and NXDOMAIN.
        if rrsets:
            # Positive answers for specific qtypes.
            if qtype_int == int(QTYPE.ANY):
                added_any = False
                for rr_qtype, (ttl_rr, values_rr) in rrsets.items():
                    if _add_rrset(reply, owner, rr_qtype, ttl_rr, list(values_rr)):
                        added_any = True
                if not added_any:
                    return None
                # When client wants DNSSEC, add RRSIG/DNSKEY RRsets.
                if want_dnssec:
                    _add_dnssec_rrsets(reply, owner, rrsets, zone_apex)
                return PluginDecision(action="override", response=reply.pack())

            if qtype_int in rrsets:
                ttl_rr, values_rr = rrsets[qtype_int]
                if not _add_rrset(reply, owner, qtype_int, ttl_rr, list(values_rr)):
                    return None
                # For A answers in zones that this plugin has auto-signed via
                # dnssec_signing, always attach covering RRSIGs/DNSKEY when
                # available so that zonefiles behave like signed authoritative
                # zones even when stub resolvers do not explicitly request
                # DNSSEC. For other qtypes, or when dnssec_signing is not
                # enabled, we continue to honour the client's DO/"want DNSSEC"
                # preference to preserve existing behaviour.
                try:
                    a_code = int(QTYPE.A)
                except Exception:  # pragma: no cover - defensive
                    a_code = 1
                if qtype_int == a_code and dnssec_signing_enabled:
                    _add_dnssec_rrsets(reply, owner, rrsets, zone_apex)
                elif want_dnssec:
                    _add_dnssec_rrsets(reply, owner, rrsets, zone_apex)
                return PluginDecision(action="override", response=reply.pack())

            # NODATA: name exists in zone but requested type is absent.
            reply.header.rcode = RCODE.NOERROR
            # Add SOA from the authoritative zone, when available.
            soa_entry = zone_soa.get(zone_apex)
            if soa_entry is not None:
                soa_ttl, soa_values = soa_entry
                soa_owner = zone_apex.rstrip(".") + "."
                for value in list(soa_values):
                    zone_line = f"{soa_owner} {soa_ttl} IN SOA {value}"
                    try:
                        rrs = RR.fromZone(zone_line)
                    except (
                        Exception
                    ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                        logger.warning(
                            "ZoneRecords invalid SOA value %r for zone %s: %s",
                            value,
                            zone_apex,
                            exc,
                        )
                        continue
                    for rr in rrs:
                        reply.add_auth(rr)

            return PluginDecision(action="override", response=reply.pack())

        # NXDOMAIN: no RRsets at this owner name within the authoritative zone.
        reply.header.rcode = RCODE.NXDOMAIN
        soa_entry = zone_soa.get(zone_apex)
        if soa_entry is not None:
            soa_ttl, soa_values = soa_entry
            soa_owner = zone_apex.rstrip(".") + "."
            for value in list(soa_values):
                zone_line = f"{soa_owner} {soa_ttl} IN SOA {value}"
                try:
                    rrs = RR.fromZone(zone_line)
                except (
                    Exception
                ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    logger.warning(
                        "ZoneRecords invalid SOA value %r for zone %s: %s",
                        value,
                        zone_apex,
                        exc,
                    )
                    continue
                for rr in rrs:
                    reply.add_auth(rr)

        return PluginDecision(action="override", response=reply.pack())

    class _WatchdogHandler(FileSystemEventHandler):
        """Brief: Internal watchdog handler that reloads records on file changes.

        Inputs:
          - plugin: CustomRecords instance to notify on changes.
          - watched_files: Iterable of concrete records file paths to track.

        Outputs:
          - None (invokes plugin._reload_records_from_watchdog when a watched path changes).
        """

        def __init__(
            self,
            plugin: "ZoneRecords",
            watched_files: Iterable[pathlib.Path],
        ) -> None:
            super().__init__()
            self._plugin = plugin
            self._watched = {p.resolve() for p in watched_files}

        def _should_reload(
            self, src_path: Optional[str], dest_path: Optional[str] = None
        ) -> bool:
            if not src_path and not dest_path:
                return False

            candidates = []
            if src_path:
                candidates.append(src_path)
            if dest_path:
                candidates.append(dest_path)

            for raw in candidates:
                try:
                    p = pathlib.Path(raw).resolve()
                except Exception:  # pragma: no cover - extremely defensive
                    continue
                if p in self._watched:
                    return True
            return False

        def on_any_event(self, event) -> None:  # type: ignore[override]
            # Ignore directory-level events; we only care about concrete file writes.
            if getattr(event, "is_directory", False):
                return

            # Treat these event types as "writes". Many editors perform atomic
            # saves via create+move rather than in-place modification, so we
            # include "created" and "moved" in addition to "modified".
            event_type = getattr(event, "event_type", None)
            if event_type not in {"modified", "created", "moved"}:
                return

            src = getattr(event, "src_path", None)
            dest = getattr(event, "dest_path", None)
            if self._should_reload(src, dest):
                self._plugin._reload_records_from_watchdog()

    def _start_watchdog(self) -> None:
        """Brief: Start a watchdog observer to reload records files on change.

        Inputs:
          - None (uses self.file_paths)
        Outputs:
          - None
        """

        if Observer is None:
            logger.warning(
                "watchdog is not available; automatic ZoneRecords reload disabled",
            )
            self._observer = None
            return

        record_paths = [pathlib.Path(p).expanduser() for p in self.file_paths]
        watched_files = [p.resolve() for p in record_paths]
        directories = {p.parent.resolve() for p in record_paths}

        if not directories:
            self._observer = None
            return

        handler = self._WatchdogHandler(self, watched_files)
        observer = Observer()
        for directory in directories:
            try:
                observer.schedule(handler, str(directory), recursive=False)
                logger.debug("Watching %s", directory)
            except Exception as exc:  # pragma: no cover - log and continue
                logger.warning("Failed to watch directory %s: %s", directory, exc)

        observer.daemon = True
        observer.start()
        self._observer = observer

    def _start_polling(self) -> None:
        """Brief: Start a stat-based polling loop to detect records file changes.

        Inputs:
          - None (uses self.file_paths and self._poll_interval)
        Outputs:
          - None

        Example:
          Called from setup() when ``watchdog_poll_interval_seconds`` is > 0.
        """
        if self._poll_interval <= 0.0:
            return

        stop_event = getattr(self, "_poll_stop", None)
        if stop_event is None:
            # If no stop event is configured, do not start polling to avoid
            # leaking an unmanaged thread.
            return

        thread = threading.Thread(target=self._poll_loop, name="CustomRecordsPoller")
        thread.daemon = True
        thread.start()
        self._poll_thread = thread

    def _poll_loop(self) -> None:
        """Brief: Background loop that periodically checks for file changes.

        Inputs:
          - None
        Outputs:
          - None
        """
        stop_event = getattr(self, "_poll_stop", None)
        interval = getattr(self, "_poll_interval", 0.0)
        if stop_event is None or interval <= 0.0:
            return

        while not stop_event.is_set():
            try:
                if self._have_files_changed():
                    self._reload_records_from_watchdog()
            except Exception:  # pragma: no cover - defensive logging
                logger.warning("Error during records polling loop", exc_info=True)

            # Wait with wakeup on stop event or timeout.
            stop_event.wait(interval)

    def _have_files_changed(self) -> bool:
        """Brief: Detect whether any configured records files have changed on disk.

        Inputs:
          - None (uses self.file_paths)
        Outputs:
          - bool: True if the current stat snapshot differs from the last one.

        Example:
          First invocation after setup() returns True and records baseline
          snapshot; subsequent calls only return True when a file's inode,
          size, or mtime changes.
        """
        snapshot = []
        for fp in self.file_paths:
            try:
                st = os.stat(fp)
            except FileNotFoundError:
                snapshot.append((fp, None))
            except OSError:
                # Other OS-level errors are logged but do not crash the poller.
                logger.warning("Failed to stat records file %s", fp, exc_info=True)
                snapshot.append((fp, None))
            else:
                snapshot.append((fp, (st.st_ino, st.st_size, st.st_mtime)))

        last = getattr(self, "_last_stat_snapshot", None)
        if last is None or snapshot != last:
            self._last_stat_snapshot = snapshot
            return True
        return False

    def _schedule_debounced_reload(self, delay: float) -> None:
        """Brief: Schedule a one-shot deferred reload after a minimum interval.

        Inputs:
          - delay: Seconds to wait before attempting the reload.

        Outputs:
          - None

        Example:
          Called internally when multiple watchdog events arrive within
          ``watchdog_min_interval_seconds``; coalesces them into a single
          reload instead of dropping later changes.
        """
        if delay <= 0.0:
            # If there is effectively no delay, fall back to an immediate
            # reload attempt.
            self._reload_records_from_watchdog()
            return

        lock = getattr(self, "_reload_timer_lock", None)
        if lock is None:
            # During teardown ``close()`` may have removed timer state;
            # in that case we simply avoid scheduling new work.
            return

        with lock:
            timer = getattr(self, "_reload_debounce_timer", None)
            if timer is not None and getattr(timer, "is_alive", lambda: False)():
                # A timer is already scheduled; let it perform the reload.
                return

            def _timer_cb() -> None:
                # Re-enter the normal reload path; by the time this fires the
                # minimum interval will have elapsed, so the reload will be
                # performed.
                try:
                    self._reload_records_from_watchdog()
                except Exception:  # pragma: no cover - defensive logging
                    logger.warning(
                        "Error during deferred records reload from watchdog",
                        exc_info=True,
                    )

            timer = threading.Timer(delay, _timer_cb)
            timer.daemon = True
            self._reload_debounce_timer = timer
            timer.start()

    def _reload_records_from_watchdog(self) -> None:
        """Brief: Safely reload records mapping in response to watchdog events.

        Inputs:
          - None
        Outputs:
          - None

        Notes:
          - Applies a minimum interval between reloads (configurable via
            ``watchdog_min_interval_seconds``) to avoid continuous reload
            loops when the act of reading the records file itself generates
            further filesystem events.
          - When multiple events arrive within the minimum interval, schedules
            a single deferred reload instead of dropping the later events.
        """
        now = time.time()
        last_ts = getattr(self, "_last_watchdog_reload_ts", 0.0)
        min_interval = getattr(self, "_watchdog_min_interval", 1.0)
        elapsed = now - last_ts

        # Fast path: if we reloaded very recently, schedule a deferred reload
        # instead of skipping outright. This coalesces rapid events while still
        # ensuring that at least one reload happens after the interval.
        if elapsed < min_interval:
            remaining = max(min_interval - elapsed, 0.0)
            logger.debug(
                "Deferring records reload for %.3fs; last reload was %.3fs ago",
                remaining,
                elapsed,
            )
            self._schedule_debounced_reload(remaining)
            return

        self._last_watchdog_reload_ts = now
        logger.info("Reloading records mapping due to filesystem change")
        try:
            self._load_records()
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Failed to reload records from watchdog event: %s", exc)

    def close(self) -> None:
        """
        Brief: Stop any background watchers and release resources.

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
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
            self._observer = None

        # Stop polling loop, if configured.
        stop_event = getattr(self, "_poll_stop", None)
        if stop_event is not None:
            try:
                stop_event.set()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        poll_thread = getattr(self, "_poll_thread", None)
        if poll_thread is not None:
            try:
                poll_thread.join(timeout=2.0)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
            self._poll_thread = None

        # Cancel any outstanding deferred reload timer so it does not fire
        # after resources have been torn down.
        timer = getattr(self, "_reload_debounce_timer", None)
        if timer is not None:
            try:
                timer.cancel()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
            self._reload_debounce_timer = None
