"""ZoneRecords plugin: Zone-based DNS record management with AXFR and DNSSEC support.

Main entry point that orchestrates record loading, query resolution, and file watching.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import threading
import time
from typing import Dict, List, Optional, Set, Tuple
from cachetools import TTLCache

from dnslib import OPCODE, QTYPE, RCODE, DNSHeader, DNSRecord
from pydantic import BaseModel, ConfigDict, Field, field_validator

from foghorn.plugins.resolve.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)
from foghorn.servers.dns_runtime_state import DNSRuntimeState
from foghorn.utils import dns_names, ip_networks
from foghorn.utils.register_caches import registered_ttl_cache

from . import (
    axfr_polling,
    helpers,
    loader,
    resolver,
    transfer,
    update_helpers,
    watchdog,
)

logger = logging.getLogger(__name__)
_NOTIFY_LOGGER = logging.getLogger("foghorn.server")
_NOTIFY_BG_LOCK = threading.Lock()
_NOTIFY_REFRESH_INFLIGHT: set[str] = set()
_NOTIFY_REFRESH_STATE: Dict[str, Dict[str, object]] = {}
_NOTIFY_RESOLVE_CACHE_LOCK = threading.Lock()
_NOTIFY_RESOLVE_CACHE_TTL_SECONDS = 30.0
_NOTIFY_RESOLVE_CACHE_MAX_ENTRIES = 4096
_NOTIFY_RESOLVE_CACHE: TTLCache = TTLCache(
    maxsize=_NOTIFY_RESOLVE_CACHE_MAX_ENTRIES,
    ttl=_NOTIFY_RESOLVE_CACHE_TTL_SECONDS,
)
_NOTIFY_RATE_LIMIT_LOCK = threading.Lock()
_NOTIFY_RATE_LIMIT_STATE_IDLE_TTL_SECONDS = 300.0
_NOTIFY_RATE_LIMIT_STATE_MAX_SENDERS = 8192
_NOTIFY_RATE_LIMIT_STATE: TTLCache = TTLCache(
    maxsize=_NOTIFY_RATE_LIMIT_STATE_MAX_SENDERS,
    ttl=_NOTIFY_RATE_LIMIT_STATE_IDLE_TTL_SECONDS,
)
_NOTIFY_RATE_LIMIT_PER_SECOND = 1.0
_NOTIFY_RATE_LIMIT_BURST = 20.0


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

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")


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

    Notes:
      - Zone names are normalized by removing leading dots (e.g., ".zaa" becomes "zaa").
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

    @field_validator("zone")
    @classmethod
    def normalize_zone(cls, v: str) -> str:
        """Brief: Normalize zone name by removing leading dots.

        Inputs:
          - v: Raw zone name from config.

        Outputs:
          - str: Zone name without leading dots.
        """
        return str(v).lstrip(".")

    model_config = ConfigDict(extra="forbid")


class PersistenceConfig(BaseModel):
    """Brief: Persistence configuration for DNS UPDATE journaling.

    Inputs:
      - enabled: Whether persistence is enabled.
      - state_dir: Directory for journal files.
      - fsync_mode: Durability mode (always/interval).
      - fsync_interval_ms: Interval fsync mode threshold.
      - max_journal_bytes: Maximum journal size before compaction.
      - max_journal_entries: Maximum entry count before compaction.
      - compact_interval_seconds: Minimum time between compactions.
      - compact_tombstone_ratio: Tombstone ratio threshold.

    Outputs:
      - PersistenceConfig instance.
    """

    enabled: bool = Field(
        default=True,
        description="Enable persistence for DNS UPDATE journaling.",
    )
    state_dir: Optional[str] = Field(
        default=None,
        description="Directory for journal files. Defaults to runtime state directory.",
    )
    fsync_mode: str = Field(
        default="interval",
        description="Durability mode: 'always' (fsync every write) or 'interval' (periodic fsync).",
    )
    fsync_interval_ms: int = Field(
        default=5000,
        ge=0,
        description="Interval in ms for fsync when mode='interval'.",
    )
    max_journal_bytes: int = Field(
        default=10 * 1024 * 1024,
        ge=0,
        description="Maximum journal size in bytes before compaction.",
    )
    max_journal_entries: int = Field(
        default=10000,
        ge=0,
        description="Maximum number of entries before compaction.",
    )
    compact_interval_seconds: int = Field(
        default=3600,
        ge=0,
        description="Minimum seconds between compactions.",
    )
    compact_tombstone_ratio: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Tombstone ratio threshold for compaction.",
    )

    model_config = ConfigDict(extra="forbid")


class ReplicationConfig(BaseModel):
    """Brief: Replication configuration for DNS UPDATE.

    Inputs:
      - role: Node role for updates.
      - zone_owner_node_id: Owner node ID for zones.
      - notify_on_update: Send NOTIFY after successful UPDATE.
      - reject_direct_update_on_replica: Reject client updates on replicas.

    Outputs:
      - ReplicationConfig instance.
    """

    role: str = Field(
        default="primary",
        description="Node role: 'primary', 'replica', or 'peer'.",
    )
    zone_owner_node_id: Optional[str] = Field(
        default=None,
        description="Node ID that owns zones in peer mode.",
    )
    notify_on_update: bool = Field(
        default=True,
        description="Send NOTIFY after successful UPDATE commit.",
    )
    node_id: Optional[str] = Field(
        default=None,
        description=(
            "Stable node identity used in dynamic update journal origin metadata. "
            "Defaults to FOGHORN_NODE_ID when omitted."
        ),
    )
    reject_direct_update_on_replica: bool = Field(
        default=False,
        description="Reject client UPDATE on replica nodes (false=forward to owner).",
    )

    model_config = ConfigDict(extra="forbid")


class SecurityConfig(BaseModel):
    """Brief: Security limits for DNS UPDATE.

    Inputs:
      - max_updates_per_message: Max updates per DNS message.
      - max_rr_values_per_rrset: Max values per RRset.
      - max_owner_length: Max owner name length.
      - max_rdata_length: Max rdata string length.
      - max_ttl_range: Max TTL value.
      - max_transaction_bytes: Max journal transaction size.
      - rate_limit_per_client: Token bucket rate per client IP.
      - rate_limit_per_key: Token bucket rate per TSIG key.

    Outputs:
      - SecurityConfig instance.
    """

    max_updates_per_message: int = Field(
        default=100,
        ge=0,
        description="Maximum updates per DNS message.",
    )
    max_rr_values_per_rrset: int = Field(
        default=100,
        ge=0,
        description="Maximum RR values per RRset mutation.",
    )
    max_owner_length: int = Field(
        default=255,
        ge=0,
        description="Maximum owner name length.",
    )
    max_rdata_length: int = Field(
        default=65535,
        ge=0,
        description="Maximum rdata string length.",
    )
    max_ttl_range: int = Field(
        default=86400,
        ge=0,
        description="Maximum TTL value in seconds.",
    )
    max_transaction_bytes: int = Field(
        default=1024 * 1024,
        ge=0,
        description="Maximum journal transaction size in bytes.",
    )
    rate_limit_per_client: int = Field(
        default=10,
        ge=0,
        description="Token bucket rate limit per client IP (requests per minute).",
    )
    rate_limit_per_key: int = Field(
        default=100,
        ge=0,
        description="Token bucket rate limit per TSIG key (requests per minute).",
    )

    model_config = ConfigDict(extra="forbid")


class DnsUpdateConfig(BaseModel):
    """Brief: DNS UPDATE configuration for ZoneRecords.

    Inputs:
      - enabled: Whether DNS UPDATE is enabled.
      - zones: Per-zone UPDATE configuration.
      - persistence: Persistence and journaling configuration.
      - replication: Replication and clustering configuration.
      - security: Security limits and rate limiting.

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
    persistence: Optional[PersistenceConfig] = Field(
        default=None,
        description="Persistence and journaling configuration.",
    )
    replication: Optional[ReplicationConfig] = Field(
        default=None,
        description="Replication and clustering configuration.",
    )
    security: Optional[SecurityConfig] = Field(
        default=None,
        description="Security limits and rate limiting.",
    )

    model_config = ConfigDict(extra="forbid")


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
      - tsig: Optional TSIG credentials for AXFR authentication.

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
    tsig: Optional[Dict[str, str]] = Field(
        default=None,
        description=(
            "Optional TSIG credentials for AXFR requests " "(name/secret/algorithm)."
        ),
    )

    model_config = ConfigDict(extra="forbid")


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
      - poll_interval_seconds: Optional polling interval for periodic AXFR refreshes.
      - allow_private_upstreams: Allow non-public upstream addresses (default True).
      - allow_public_upstreams: Allow public upstream addresses (default True).
      - max_rrs_per_zone: Optional maximum RR count for a single AXFR transfer.
      - max_bytes_per_zone: Optional maximum total bytes for a single AXFR transfer.
      - max_retries_per_zone: Optional maximum consecutive transfer failures.
      - failure_backoff_initial_seconds: Initial backoff delay after failure.
      - failure_backoff_max_seconds: Maximum backoff delay after failures.

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
    poll_interval_seconds: Optional[int] = Field(
        default=None,
        ge=0,
        description="Optional polling interval in seconds for periodic AXFR refreshes.",
    )
    allow_private_upstreams: bool = Field(
        default=True,
        description=(
            "Allow non-public upstream addresses (private/loopback/link-local). "
            "Defaults to true; set false to block private upstreams."
        ),
    )
    allow_public_upstreams: bool = Field(
        default=True,
        description="Allow public upstream addresses (defaults to true).",
    )
    max_rrs_per_zone: Optional[int] = Field(
        default=None,
        ge=1,
        description="Optional maximum number of RRs allowed in a single AXFR transfer.",
    )
    max_bytes_per_zone: Optional[int] = Field(
        default=None,
        ge=1,
        description="Optional maximum total response bytes allowed per AXFR transfer.",
    )
    max_retries_per_zone: Optional[int] = Field(
        default=None,
        ge=1,
        description="Optional maximum consecutive AXFR failures before giving up.",
    )
    failure_backoff_initial_seconds: float = Field(
        default=0,
        ge=0,
        description="Initial backoff delay in seconds after an AXFR failure.",
    )
    failure_backoff_max_seconds: float = Field(
        default=0,
        ge=0,
        description="Maximum backoff delay in seconds after repeated failures.",
    )

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")


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
        default=True,
        description=(
            "Enable automatic DNSSEC signing for authoritative zones. "
            "Defaults to true when dnssec_signing is configured; set false "
            "to explicitly disable."
        ),
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

    @field_validator("generate", mode="before")
    @classmethod
    def normalize_generate_policy(cls, value: object) -> str:
        """Brief: Normalize dnssec_signing.generate into yes/no/maybe.

        Inputs:
          - value: Raw generate policy value from configuration.

        Outputs:
          - str: Normalized value in {'yes', 'no', 'maybe'}.
        """
        if value is None:
            return "maybe"
        if isinstance(value, bool):
            return "yes" if value else "no"

        normalized = str(value).strip().lower()
        if not normalized:
            return "maybe"

        alias_map = {
            "true": "yes",
            "false": "no",
            "on": "yes",
            "off": "no",
            "1": "yes",
            "0": "no",
        }
        normalized = alias_map.get(normalized, normalized)

        if normalized not in {"yes", "no", "maybe"}:
            raise ValueError(
                "dnssec_signing.generate must be one of: yes, no, maybe "
                "(aliases: true/false, on/off, 1/0)"
            )
        return normalized

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")


class ZoneRecordsConfig(BaseModel):
    """Brief: Typed configuration model for ZoneRecords.

    Inputs:
      - file_paths: Preferred list of records file paths.
      - path_allowlist: Optional list of allowed directory prefixes for file_paths
        and bind_paths; paths outside these prefixes are ignored with a warning.
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
      - max_file_size_bytes: Maximum bytes allowed for any file_path/bind_path.
      - max_records: Maximum total record values accepted during one load cycle.
      - max_record_value_length: Maximum allowed rdata value length in characters.
      - auto_ptr_enabled: Enables/disables automatic PTR synthesis from A/AAAA.
      - max_auto_ptr_records: Maximum number of auto-generated PTR values.
      - soa_synthesis_enabled: Enables/disables fallback SOA synthesis when absent.
      - watchdog_enabled: Enable watchdog-based reloads.
      - watchdog_min_interval_seconds: Minimum seconds between reloads.
      - watchdog_poll_interval_seconds: Optional polling interval.
      - watchdog_data_directories: Optional allowed directory prefixes used by
        watchdog/polling filesystem operations.
      - watchdog_reject_absolute_paths: Reject absolute paths for watcher files.
      - watchdog_max_files: Maximum number of watched files.
      - watchdog_max_directories: Maximum number of watched parent directories.
      - watchdog_snapshot_max_entries: Maximum stat snapshot entries retained.
      - ttl: Default TTL in seconds.
      - nxdomain_zones: Optional list of zone suffixes for which ZoneRecords
        should return NXDOMAIN/NODATA instead of falling through to upstream.
      - any_query_enabled: Allow QTYPE=ANY responses (default False).
      - any_answer_rrset_limit: Max RRsets returned for QTYPE=ANY responses.
      - any_answer_record_limit: Max total records returned for QTYPE=ANY responses.
      - axfr_zones: Optional list of AXFR-backed zones.
    - axfr_poll_min_interval_seconds: Minimum poll interval enforced for AXFR polling.

    Outputs:
      - ZoneRecordsConfig instance with normalized field types.
    """

    file_paths: Optional[List[str]] = None
    path_allowlist: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional list of allowed directory prefixes for file_paths and "
            "bind_paths. Paths outside these prefixes are ignored with a warning."
        ),
    )
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
    max_file_size_bytes: int = Field(
        default=16 * 1024 * 1024,
        ge=1,
        description=(
            "Maximum allowed file size in bytes for entries loaded from file_paths "
            "and bind_paths. Files larger than this limit are rejected."
        ),
    )
    max_records: int = Field(
        default=500000,
        ge=1,
        description=(
            "Maximum total record values accepted during a single load pass "
            "(across inline, file_paths, and bind_paths)."
        ),
    )
    max_record_value_length: int = Field(
        default=4096,
        ge=1,
        description="Maximum allowed length in characters for stored record values.",
    )
    auto_ptr_enabled: bool = Field(
        default=True,
        description="Enable automatic PTR generation from A/AAAA records.",
    )
    max_auto_ptr_records: int = Field(
        default=100000,
        ge=1,
        description="Maximum number of PTR values auto-generated in one load cycle.",
    )
    soa_synthesis_enabled: bool = Field(
        default=True,
        description=(
            "Enable fallback SOA synthesis from record-name suffix inference when "
            "no explicit SOA is present."
        ),
    )
    watchdog_enabled: Optional[bool] = None
    watchdog_min_interval_seconds: float = Field(default=1.0, ge=0)
    watchdog_poll_interval_seconds: float = Field(default=60.0, ge=0)
    watchdog_data_directories: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional directory prefixes allowed for watchdog/polling file "
            "operations. When omitted, path_allowlist is reused."
        ),
    )
    watchdog_reject_absolute_paths: bool = Field(
        default=False,
        description=(
            "Reject absolute configured watch paths. Set true to enforce "
            "relative, deployment-local record paths."
        ),
    )
    watchdog_max_files: int = Field(
        default=4096,
        ge=1,
        description="Maximum number of record files considered by watchdog/polling.",
    )
    watchdog_max_directories: int = Field(
        default=256,
        ge=1,
        description=(
            "Maximum number of parent directories watched by watchdog observers."
        ),
    )
    watchdog_snapshot_max_entries: int = Field(
        default=4096,
        ge=1,
        description=(
            "Maximum number of per-file stat entries stored in polling snapshots."
        ),
    )
    ttl: int = Field(default=300, ge=0)
    nxdomain_zones: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional list of zone suffixes for which ZoneRecords should return "
            "NXDOMAIN/NODATA for names under that suffix which are not present in "
            "the internal mapping, instead of falling through to upstream resolution."
        ),
    )
    any_query_enabled: bool = Field(
        default=False,
        description="Allow QTYPE=ANY responses from ZoneRecords.",
    )
    any_answer_rrset_limit: int = Field(
        default=16,
        ge=1,
        description="Maximum RRsets returned for QTYPE=ANY responses.",
    )
    any_answer_record_limit: int = Field(
        default=64,
        ge=1,
        description="Maximum total records returned for QTYPE=ANY responses.",
    )
    axfr_zones: Optional[List[AxfrZoneConfig]] = None
    axfr_poll_min_interval_seconds: float = Field(
        default=60.0,
        ge=0,
        description=(
            "Minimum poll interval in seconds for AXFR polling. "
            "Values below the hard floor are clamped."
        ),
    )
    axfr_notify: Optional[List[AxfrUpstreamConfig]] = Field(
        default=None,
        description=(
            "Optional list of NOTIFY recipients for AXFR-backed zones. Each "
            "entry uses the same host/port/transport/server_name/verify/ca_file "
            "shape as axfr_zones[].upstreams. Only 'tcp' and 'dot' transports "
            "are supported for outbound NOTIFY."
        ),
    )
    axfr_notify_allow_private_targets: bool = Field(
        default=False,
        description=(
            "When false (default), outbound NOTIFY targets that resolve to "
            "private/loopback/link-local/multicast/reserved addresses are blocked."
        ),
    )
    axfr_notify_target_allowlist: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional allowlist for outbound NOTIFY targets. Entries can be "
            "hostnames, IP literals, or CIDRs; when set, all NOTIFY targets "
            "must match."
        ),
    )
    axfr_notify_min_interval_seconds: float = Field(
        default=1.0,
        ge=0,
        description=(
            "Minimum elapsed seconds between consecutive NOTIFY sends to the "
            "same configured target."
        ),
    )
    axfr_notify_rate_limit_per_target_per_minute: int = Field(
        default=60,
        ge=1,
        description=(
            "Maximum NOTIFY messages sent to a single configured target in a "
            "rolling 60-second window."
        ),
    )
    axfr_notify_scheduled: Optional[int] = Field(
        default=None,
        ge=0,
        description=(
            "Deprecated compatibility field for legacy learned-target NOTIFY "
            "behavior. Parsed but ignored."
        ),
    )
    dnssec_signing: Optional[ZoneDnssecSigningConfig] = None
    dns_update: Optional[DnsUpdateConfig] = None

    model_config = ConfigDict(extra="allow")


def _upstream_fingerprint(upstreams: List[Dict]) -> str:
    """Brief: Build a deterministic fingerprint for candidate upstreams.

    Inputs:
      - upstreams: List of upstream configuration mappings.

    Outputs:
      - str: Stable fingerprint for short-lived auth cache keys.
    """
    items: List[str] = []
    for upstream in upstreams or []:
        if not isinstance(upstream, dict):
            continue
        host = str(upstream.get("host", "")).strip().lower()
        port = str(upstream.get("port", ""))
        transport = str(upstream.get("transport", "")).strip().lower()
        server_name = str(upstream.get("server_name", "")).strip().lower()
        items.append(f"{host}|{port}|{transport}|{server_name}")
    if not items:
        return ""
    return "||".join(sorted(items))


def _is_ip_literal(value: str) -> bool:
    """Brief: Check whether text is a valid IPv4/IPv6 literal.

    Inputs:
      - value: Hostname or IP text.

    Outputs:
      - bool: True when value parses as an IP literal.
    """
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except Exception:
        return False


def _resolve_host_ips(hostname: str) -> set[str]:
    """Brief: Resolve a hostname to IPv4/IPv6 addresses.

    Inputs:
      - hostname: DNS hostname to resolve.

    Outputs:
      - set[str]: Resolved IP addresses, empty set on lookup failure.
    """
    resolved: set[str] = set()
    try:
        info = socket.getaddrinfo(
            str(hostname),
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except Exception:
        return resolved

    for entry in info or []:
        try:
            sockaddr = entry[4]
            ip_text = str(sockaddr[0]).strip()
        except Exception:
            continue
        if ip_text:
            resolved.add(ip_text)
    return resolved


def _sender_matches_upstream(sender_ip: str, upstream: Dict) -> bool:
    """Brief: Validate sender IP against one upstream without PTR trust.

    Inputs:
      - sender_ip: Sender IPv4/IPv6 address string.
      - upstream: Upstream mapping with host metadata.

    Outputs:
      - bool: True when sender matches upstream by IP literal or forward DNS.
    """
    if not isinstance(upstream, dict):
        return False
    host = upstream.get("host")
    if not isinstance(host, str):
        return False

    sender = str(sender_ip).strip()
    host_text = host.strip()
    if not sender or not host_text:
        return False

    if _is_ip_literal(host_text):
        return host_text.lower() == sender.lower()
    return sender in _resolve_host_ips(host_text)


def _resolve_notify_sender_upstream_from_candidates(
    sender_ip: str,
    upstreams: List[Dict],
    cache_scope: str,
) -> Optional[Dict]:
    """Brief: Match sender to one upstream with TTL-bounded caching.

    Inputs:
      - sender_ip: Sender IPv4/IPv6 address text.
      - upstreams: Candidate upstream mappings.
      - cache_scope: Cache namespace (global vs per-zone).

    Outputs:
      - dict | None: Matching upstream mapping, or None when unauthorized.
    """
    if not sender_ip:
        return None
    try:
        sender = str(sender_ip).strip()
    except Exception:
        sender = str(sender_ip)
    if not sender:
        return None

    candidates = [u for u in (upstreams or []) if isinstance(u, dict)]
    if not candidates:
        return None

    cache_key = (sender, str(cache_scope), _upstream_fingerprint(candidates))
    with _NOTIFY_RESOLVE_CACHE_LOCK:
        if cache_key in _NOTIFY_RESOLVE_CACHE:
            return _NOTIFY_RESOLVE_CACHE[cache_key]

    match: Optional[Dict] = None
    for upstream in candidates:
        if _sender_matches_upstream(sender, upstream):
            match = upstream
            break

    with _NOTIFY_RESOLVE_CACHE_LOCK:
        _NOTIFY_RESOLVE_CACHE[cache_key] = match
    return match


def _resolve_notify_sender_upstream(sender_ip: str) -> Optional[Dict]:
    """Brief: Map a NOTIFY sender IP address to a configured global upstream.

    Inputs:
      - sender_ip: String IPv4/IPv6 address of the NOTIFY sender.

    Outputs:
      - dict | None: Matching upstream configuration mapping when sender is
        recognized among configured global upstreams, otherwise None.
    """
    if not sender_ip:
        return None

    try:
        from foghorn.runtime_config import get_runtime_snapshot

        snap = get_runtime_snapshot()
        upstreams = list(snap.upstream_addrs or [])
    except Exception:
        upstreams = []
    if not upstreams:
        return None
    return _resolve_notify_sender_upstream_from_candidates(
        sender_ip,
        upstreams,
        cache_scope="global-upstreams",
    )


def _resolve_notify_sender_for_zone(
    plugin: "ZoneRecords",
    zone_name: str,
    sender_ip: str,
) -> Optional[Dict]:
    """Brief: Resolve and authorize a NOTIFY sender for a specific AXFR zone.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - zone_name: NOTIFY qname interpreted as zone apex.
      - sender_ip: Sender IPv4/IPv6 address text.

    Outputs:
      - dict | None: Authorized upstream mapping for this zone, otherwise None.
    """
    zone_norm = dns_names.normalize_name(zone_name)
    if not zone_norm:
        return None

    zone_cfg = list(getattr(plugin, "_axfr_zones", []) or [])
    for entry in zone_cfg:
        if not isinstance(entry, dict):
            continue
        entry_zone = dns_names.normalize_name(entry.get("zone", ""))
        if entry_zone != zone_norm:
            continue
        upstreams = list(entry.get("upstreams") or [])
        return _resolve_notify_sender_upstream_from_candidates(
            sender_ip,
            upstreams,
            cache_scope=f"zone:{zone_norm}",
        )
    return None


@registered_ttl_cache(maxsize=1024, ttl=10)
def _zone_has_axfr_config(plugin: "ZoneRecords", zone_name: str) -> bool:
    """Brief: Determine whether AXFR config exists for a zone.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - zone_name: Zone name to check for AXFR configuration.

    Outputs:
      - bool: True when a matching AXFR zone configuration exists.
    """
    zone_norm = dns_names.normalize_name(zone_name)
    if not zone_norm:
        return False

    zone_cfg = list(getattr(plugin, "_axfr_zones", []) or [])
    for entry in zone_cfg:
        if not isinstance(entry, dict):
            continue
        entry_zone = dns_names.normalize_name(entry.get("zone", ""))
        if entry_zone == zone_norm:
            return True
    return False


def _get_zone_notify_min_refresh_seconds(
    plugin: "ZoneRecords",
    zone_norm: str,
) -> float:
    """Brief: Read the per-zone NOTIFY refresh cooldown from AXFR config.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - zone_norm: Lower-cased zone apex without trailing dot.

    Outputs:
      - float: Non-negative minimum seconds between NOTIFY-triggered refreshes.
    """
    zone_cfg = list(getattr(plugin, "_axfr_zones", []) or [])
    for entry in zone_cfg:
        if not isinstance(entry, dict):
            continue
        entry_zone = dns_names.normalize_name(entry.get("zone", ""))
        if entry_zone != zone_norm:
            continue
        try:
            return max(0.0, float(entry.get("minimum_reload_time", 0.0) or 0.0))
        except Exception:
            return 0.0
    return 0.0


def _notify_sender_is_rate_limited(sender_ip: str) -> bool:
    """Brief: Apply a token-bucket limiter for inbound NOTIFY sender IPs.

    Inputs:
      - sender_ip: Sender IPv4/IPv6 address string.

    Outputs:
      - bool: True when NOTIFY should be refused due to sender rate limit.
    """
    key = str(sender_ip or "").strip() or "unknown"
    now = time.time()
    with _NOTIFY_RATE_LIMIT_LOCK:
        state = _NOTIFY_RATE_LIMIT_STATE.get(key)
        if not isinstance(state, dict):
            state = {"tokens": _NOTIFY_RATE_LIMIT_BURST, "updated_at": now}
            _NOTIFY_RATE_LIMIT_STATE[key] = state

        last = float(state.get("updated_at", now))
        tokens = float(state.get("tokens", _NOTIFY_RATE_LIMIT_BURST))
        elapsed = max(0.0, now - last)
        tokens = min(
            _NOTIFY_RATE_LIMIT_BURST,
            tokens + elapsed * _NOTIFY_RATE_LIMIT_PER_SECOND,
        )
        if tokens < 1.0:
            state["tokens"] = tokens
            state["updated_at"] = now
            _NOTIFY_RATE_LIMIT_STATE[key] = state
            return True

        state["tokens"] = tokens - 1.0
        state["updated_at"] = now
        _NOTIFY_RATE_LIMIT_STATE[key] = state
        return False


def _schedule_notify_axfr_refresh(zone_name: str, upstream: Dict) -> None:
    """Brief: Best-effort AXFR reload for AXFR-backed plugins on NOTIFY.

    Inputs:
      - zone_name: QNAME from the NOTIFY question (typically the zone apex).
      - upstream: Mapping describing the matched upstream host entry that sent
        the NOTIFY.

    Outputs:
      - None; schedules background reloads for matching AXFR-backed ZoneRecords
        plugins. Errors are logged and do not affect NOTIFY acknowledgement.
    """
    zone_norm = dns_names.normalize_name(zone_name)
    if not zone_norm:
        return

    try:
        from foghorn.runtime_config import get_runtime_snapshot

        plugins = list(get_runtime_snapshot().plugins or [])
    except Exception:
        plugins = []
    if not plugins:
        return

    try:
        from foghorn.servers import server as server_mod

        submit_bg = getattr(server_mod, "_bg_submit", None)
    except Exception:
        submit_bg = None

    if not callable(submit_bg):

        def submit_bg(_key: object, fn) -> bool:
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            return True

    for plugin in plugins:
        cfg = getattr(plugin, "_axfr_zones", None)
        if not cfg:
            continue

        try:
            zones = [
                dns_names.normalize_name(entry.get("zone", ""))
                for entry in cfg
                if isinstance(entry, dict)
            ]
        except Exception:
            continue
        if zone_norm not in zones:
            continue

        zone_key = f"{id(plugin)}:{zone_norm}"
        zone_min_reload = _get_zone_notify_min_refresh_seconds(plugin, zone_norm)

        def _worker(p=plugin) -> None:
            """Brief: Background worker that re-runs AXFR-backed loads.

            Inputs:
              - p: Plugin instance whose AXFR-backed zones should be refreshed.

            Outputs:
              - None; logs and suppresses any exceptions.
            """
            try:
                setattr(p, "_axfr_loaded_once", False)
                loader_fn = getattr(p, "_load_records", None)
                if callable(loader_fn):
                    loader_fn()
            except Exception:  # pragma: no cover - defensive logging only
                logger.warning(
                    "Error refreshing AXFR-backed zones for NOTIFY %s via upstream %r",
                    zone_norm,
                    upstream,
                    exc_info=True,
                )

        def _schedule_coalesced_refresh(delay_seconds: float) -> None:
            """Brief: Schedule one deferred refresh for a zone after cooldown.

            Inputs:
              - delay_seconds: Delay before running the deferred refresh.

            Outputs:
              - None
            """

            def _timer_fire() -> None:
                with _NOTIFY_BG_LOCK:
                    state = _NOTIFY_REFRESH_STATE.setdefault(zone_key, {})
                    state["timer"] = None
                    if zone_key in _NOTIFY_REFRESH_INFLIGHT:
                        state["pending"] = True
                        return
                    _NOTIFY_REFRESH_INFLIGHT.add(zone_key)
                    state["pending"] = False
                    state["next_allowed_at"] = time.time() + float(zone_min_reload)

                def _wrapped() -> None:
                    try:
                        _worker()
                    finally:
                        with _NOTIFY_BG_LOCK:
                            _NOTIFY_REFRESH_INFLIGHT.discard(zone_key)
                            state = _NOTIFY_REFRESH_STATE.setdefault(zone_key, {})
                            pending = bool(state.get("pending", False))
                            if pending:
                                state["pending"] = False
                                now_inner = time.time()
                                next_allowed_at = float(
                                    state.get("next_allowed_at", now_inner)
                                )
                                delay_next = max(0.0, next_allowed_at - now_inner)
                            else:
                                delay_next = 0.0
                        if pending:
                            _schedule_coalesced_refresh(delay_next)

                try:
                    submit_result = submit_bg(zone_key, _wrapped)
                    submitted = submit_result is not False
                except Exception:  # pragma: no cover - defensive logging only
                    submitted = False
                if not submitted:
                    with _NOTIFY_BG_LOCK:
                        _NOTIFY_REFRESH_INFLIGHT.discard(zone_key)
                    logger.warning(
                        "Failed to schedule AXFR refresh for NOTIFY %s via upstream %r",
                        zone_norm,
                        upstream,
                        exc_info=True,
                    )

            timer = threading.Timer(max(0.0, float(delay_seconds)), _timer_fire)
            timer.daemon = True
            with _NOTIFY_BG_LOCK:
                state = _NOTIFY_REFRESH_STATE.setdefault(zone_key, {})
                if state.get("timer") is not None:
                    return
                state["timer"] = timer
            timer.start()

        with _NOTIFY_BG_LOCK:
            state = _NOTIFY_REFRESH_STATE.setdefault(zone_key, {})
            now = time.time()
            next_allowed_at = float(state.get("next_allowed_at", 0.0))
            if zone_key in _NOTIFY_REFRESH_INFLIGHT:
                state["pending"] = True
                continue
            if next_allowed_at > now:
                state["pending"] = True
                delay = next_allowed_at - now
            else:
                _NOTIFY_REFRESH_INFLIGHT.add(zone_key)
                state["pending"] = False
                state["next_allowed_at"] = now + float(zone_min_reload)
                delay = 0.0

        if delay > 0.0:
            _schedule_coalesced_refresh(delay)
            continue

        def _wrapped() -> None:
            try:
                _worker()
            finally:
                with _NOTIFY_BG_LOCK:
                    _NOTIFY_REFRESH_INFLIGHT.discard(zone_key)
                    state = _NOTIFY_REFRESH_STATE.setdefault(zone_key, {})
                    pending = bool(state.get("pending", False))
                    if pending:
                        state["pending"] = False
                        now_inner = time.time()
                        next_allowed_at = float(state.get("next_allowed_at", now_inner))
                        delay_next = max(0.0, next_allowed_at - now_inner)
                    else:
                        delay_next = 0.0
                if pending:
                    _schedule_coalesced_refresh(delay_next)

        try:
            submit_result = submit_bg(zone_key, _wrapped)
            submitted = submit_result is not False
        except Exception:  # pragma: no cover - defensive logging only
            submitted = False
        if not submitted:
            with _NOTIFY_BG_LOCK:
                _NOTIFY_REFRESH_INFLIGHT.discard(zone_key)
            logger.warning(
                "Failed to schedule AXFR refresh for NOTIFY %s via upstream %r",
                zone_norm,
                upstream,
                exc_info=True,
            )


def _build_notify_response(
    req_wire: bytes,
    rcode: int,
    *,
    ede_code: Optional[int] = None,
    ede_text: Optional[str] = None,
) -> bytes:
    """Brief: Build a NOTIFY response wire payload with optional EDE metadata.

    Inputs:
      - req_wire: Raw NOTIFY request wire bytes.
      - rcode: DNS RCODE integer for the response.
      - ede_code: Optional RFC 8914 EDE info-code.
      - ede_text: Optional EDE text.

    Outputs:
      - bytes: Packed DNS response wire payload.
    """
    try:
        req = DNSRecord.parse(req_wire)
    except Exception:
        req = None

    if req is not None:
        reply = req.reply()
        reply.header.rcode = int(rcode)
    else:
        req_id = 0
        try:
            if isinstance(req_wire, (bytes, bytearray)) and len(req_wire) >= 2:
                req_id = int.from_bytes(bytes(req_wire[:2]), "big")
        except Exception:
            req_id = 0
        reply = DNSRecord(
            DNSHeader(
                id=req_id,
                qr=1,
                aa=1,
                ra=0,
                rcode=int(rcode),
            )
        )

    try:
        from foghorn.servers import server as server_mod

        if req is not None:
            server_mod._echo_client_edns(req, reply)
        if req is not None and ede_code is not None:
            server_mod._attach_ede_option(
                req,
                reply,
                int(ede_code),
                str(ede_text) if ede_text is not None else None,
            )
    except Exception:
        pass

    wire = reply.pack()
    try:
        from foghorn.servers import server as server_mod

        if req is not None:
            wire = server_mod._set_response_id(wire, req.header.id)
    except Exception:
        pass
    return wire


def _handle_notify_opcode(
    plugin: "ZoneRecords",
    opcode: int,
    qname: str,
    qtype: int,
    req: bytes,
    ctx: PluginContext,
) -> Optional[PluginDecision]:
    """Brief: Handle inbound DNS NOTIFY requests for ZoneRecords.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - opcode: Numeric DNS opcode from the request header.
      - qname: Normalized qname from the opcode dispatch path.
      - qtype: Numeric qtype from the opcode dispatch path.
      - req: Raw DNS request wire bytes.
      - ctx: PluginContext with client_ip/listener metadata.

    Outputs:
      - PluginDecision override containing the final NOTIFY response when
        opcode is NOTIFY; None for non-NOTIFY opcodes.
    """
    if int(opcode) != int(getattr(OPCODE, "NOTIFY", 4)):
        return None

    try:
        req_parsed = DNSRecord.parse(req)
    except Exception:
        return PluginDecision(
            action="override",
            response=_build_notify_response(
                req,
                int(RCODE.FORMERR),
                ede_text="Malformed NOTIFY message",
            ),
        )
    if req_parsed.questions:
        q0 = req_parsed.questions[0]
        notify_qname = dns_names.normalize_name(q0.qname)
        notify_qtype = int(q0.qtype)
    else:
        notify_qname = dns_names.normalize_name(qname)
        notify_qtype = int(qtype)

    try:
        listener_label = str(getattr(ctx, "listener", "") or "").lower()
    except Exception:
        listener_label = ""

    # Preserve current server behavior: UDP listeners refuse NOTIFY.
    if listener_label == "udp":
        return PluginDecision(
            action="override",
            response=_build_notify_response(
                req,
                int(RCODE.REFUSED),
                ede_code=22,
                ede_text="NOTIFY not supported over UDP",
            ),
        )

    try:
        client_ip = str(getattr(ctx, "client_ip", "") or "")
    except Exception:
        client_ip = ""
    if _notify_sender_is_rate_limited(client_ip):
        return PluginDecision(
            action="override",
            response=_build_notify_response(
                req,
                int(RCODE.REFUSED),
                ede_code=15,
                ede_text="NOTIFY sender rate limited",
            ),
        )
    zone_has_axfr = _zone_has_axfr_config(plugin, notify_qname)

    try:
        upstream = _resolve_notify_sender_for_zone(plugin, notify_qname, client_ip)
    except Exception:
        upstream = None

    if upstream is None:
        if not zone_has_axfr:
            try:
                upstream = _resolve_notify_sender_upstream(client_ip)
            except Exception:
                upstream = None
        if upstream is None:
            return PluginDecision(
                action="override",
                response=_build_notify_response(
                    req,
                    int(RCODE.REFUSED),
                    ede_code=15,
                    ede_text="NOTIFY sender not authorized for zone upstreams",
                ),
            )

    try:
        upstream_id = DNSRuntimeState._upstream_id(upstream)
    except Exception:
        upstream_id = None

    _NOTIFY_LOGGER.critical(
        "Received DNS NOTIFY from %s (upstream=%s) for %s type %s via %s",
        client_ip,
        upstream_id or "unknown",
        notify_qname,
        QTYPE.get(notify_qtype, str(notify_qtype)),
        listener_label or "unknown",
    )

    try:
        _schedule_notify_axfr_refresh(notify_qname, upstream)
    except Exception:  # pragma: no cover - defensive logging only
        logger.warning(
            "Unexpected error while scheduling AXFR refresh for NOTIFY from %s",
            client_ip,
            exc_info=True,
        )

    zone_norm = dns_names.normalize_name(notify_qname)
    if zone_norm:
        try:
            zone_metadata = getattr(plugin, "_axfr_zone_metadata", None)
            if not isinstance(zone_metadata, dict):
                zone_metadata = {}
                setattr(plugin, "_axfr_zone_metadata", zone_metadata)
            if zone_norm not in zone_metadata:
                zone_metadata[zone_norm] = {}
            zone_metadata[zone_norm]["last_notify"] = time.time()
        except Exception:  # pragma: no cover - defensive
            pass

    return PluginDecision(
        action="override",
        response=_build_notify_response(req, int(RCODE.NOERROR)),
    )


@plugin_aliases("zone", "zone_records", "custom", "records")
class ZoneRecords(BasePlugin):
    """DNS zone records plugin with AXFR, DNSSEC, and DNS UPDATE support."""

    setup_provides_dns = True

    target_opcodes = ("NOTIFY", "UPDATE")

    def handle_opcode(
        self, opcode: int, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Handle NOTIFY and UPDATE opcodes for ZoneRecords.

        Inputs:
          - opcode: Numeric opcode from the request header.
          - qname: Normalized zone name from the query.
          - qtype: Query type (SOA for NOTIFY, zone qtype for UPDATE).
          - req: Raw wire-format request bytes.
          - ctx: PluginContext with client_ip, listener, and transport metadata.

        Outputs:
          - PluginDecision for handled NOTIFY/UPDATE operations, or None to
            skip opcode handling.
        """
        notify_decision = _handle_notify_opcode(self, opcode, qname, qtype, req, ctx)
        if notify_decision is not None:
            return notify_decision
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
        path_allowlist_cfg = self.config.get("path_allowlist")
        inline_records_cfg = self.config.get("records")
        axfr_cfg = self.config.get("axfr_zones")

        self.file_paths = []
        self.bind_paths: List[object] = []
        self._path_allowlist = helpers.normalize_path_allowlist(path_allowlist_cfg)

        if provided_paths is not None or legacy_path is not None:
            self.file_paths = helpers.normalize_paths(
                provided_paths,
                legacy_path,
                path_allowlist=self._path_allowlist,
            )

        if bind_paths_cfg is not None:
            self.bind_paths = helpers.normalize_bind_paths(
                bind_paths_cfg,
                path_allowlist=self._path_allowlist,
            )

        if not self.file_paths and not self.bind_paths:
            if inline_records_cfg or axfr_cfg:
                self.file_paths = []
                self.bind_paths = []
            else:
                self.file_paths = helpers.normalize_paths(
                    None,
                    None,
                    path_allowlist=self._path_allowlist,
                )

        # Cache inline records
        try:
            self._inline_records = list(inline_records_cfg or [])
        except Exception:  # pragma: no cover - defensive
            self._inline_records = []

        # Normalize zone suffix list for NXDOMAIN behaviour.
        self._nxdomain_zones = helpers.normalize_zone_suffixes(
            self.config.get("nxdomain_zones")
        )
        self._any_query_enabled = bool(self.config.get("any_query_enabled", False))
        try:
            self._any_answer_rrset_limit = max(
                1, int(self.config.get("any_answer_rrset_limit", 16))
            )
        except (TypeError, ValueError):
            self._any_answer_rrset_limit = 16
        try:
            self._any_answer_record_limit = max(
                1, int(self.config.get("any_answer_record_limit", 64))
            )
        except (TypeError, ValueError):
            self._any_answer_record_limit = 64

        # Normalize AXFR and NOTIFY configuration
        self._axfr_zones = helpers.normalize_axfr_config(axfr_cfg)
        self._axfr_loaded_once = False
        # Track AXFR zone metadata for reload timing
        self._axfr_zone_metadata: Dict[str, Dict[str, object]] = {}

        self._axfr_notify_static_targets = helpers.normalize_axfr_notify_targets(
            self.config.get("axfr_notify")
        )
        self._axfr_notify_allow_private_targets = bool(
            self.config.get("axfr_notify_allow_private_targets", False)
        )
        allowlist_cfg = self.config.get("axfr_notify_target_allowlist")
        allowlist_values: List[str] = []
        if isinstance(allowlist_cfg, list):
            for value in allowlist_cfg:
                try:
                    item = str(value or "").strip()
                except Exception:
                    item = ""
                if item:
                    allowlist_values.append(item)
        self._axfr_notify_target_allowlist = list(allowlist_values)
        self._axfr_notify_target_allowlist_hosts: Set[str] = set()
        self._axfr_notify_target_allowlist_networks: List[ipaddress._BaseNetwork] = []
        for item in allowlist_values:
            net = ip_networks.parse_network(item, strict=False)
            if net is not None:
                self._axfr_notify_target_allowlist_networks.append(net)
            else:
                self._axfr_notify_target_allowlist_hosts.add(item.lower().rstrip("."))
        try:
            self._axfr_notify_min_interval_seconds = max(
                0.0, float(self.config.get("axfr_notify_min_interval_seconds", 1.0))
            )
        except (TypeError, ValueError):
            self._axfr_notify_min_interval_seconds = 1.0
        try:
            self._axfr_notify_rate_limit_per_target_per_minute = max(
                1,
                int(
                    self.config.get(
                        "axfr_notify_rate_limit_per_target_per_minute",
                        60,
                    )
                ),
            )
        except (TypeError, ValueError):
            self._axfr_notify_rate_limit_per_target_per_minute = 60
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
        self._axfr_notify_lock = threading.RLock()
        self._axfr_notify_send_history: Dict[str, List[float]] = {}
        self._axfr_notify_last_sent: Dict[str, float] = {}
        if "axfr_notify_all" in self.config:
            logger.warning(
                "ZoneRecords: axfr_notify_all is deprecated and ignored; use axfr_notify targets only."
            )

        # Normalize DNS UPDATE configuration
        dns_update_cfg = self.config.get("dns_update")
        self._dns_update_config = dns_update_cfg
        self._dns_update_persistence_config = {}
        self._dns_update_journal_state_dir = None
        self._dns_update_node_id = str(os.getenv("FOGHORN_NODE_ID", "unknown"))
        self._dynamic_last_seq_by_zone: Dict[str, int] = {}
        self._dns_update_replay_duration_seconds: float = 0.0
        self._dns_update_replay_entries: int = 0
        self._dns_update_compact_count: int = 0
        self._dns_update_rate_limit_hits: int = 0
        self._dns_update_notify_sent: int = 0
        self._dns_update_notify_failed: int = 0
        if isinstance(dns_update_cfg, dict):
            persistence_cfg = dns_update_cfg.get("persistence")
            if isinstance(persistence_cfg, dict):
                self._dns_update_persistence_config = dict(persistence_cfg)
            replication_cfg = dns_update_cfg.get("replication")
            if isinstance(replication_cfg, dict):
                node_id = replication_cfg.get("node_id")
                if node_id:
                    self._dns_update_node_id = str(node_id)
        self._dns_update_tsig_key_source_loaders = (
            update_helpers.get_default_tsig_key_source_loaders()
        )
        if dns_update_cfg:
            self._dns_update_file_paths = update_helpers.collect_update_file_paths(
                dns_update_cfg
            )
        else:
            self._dns_update_file_paths = []
        self._dns_update_timestamps: Dict[str, float] = {}
        self._dns_update_lists_cache: Dict[str, List[str]] = {}
        self._dns_update_cache_lock = threading.RLock()
        # Track owners managed by DNS UPDATE (for source tracking)
        self._update_managed_owners: Set[str] = set()

        # Initialize state and locks
        self._records_lock = threading.RLock()
        self._reload_records_lock = threading.RLock()
        self.records: Dict[Tuple[str, int], Tuple[int, List[str], List[str]]] = {}
        self._observer = None
        self._axfr_poll_stop = None
        self._axfr_poll_thread = None
        self._axfr_poll_interval = 0.0
        self._axfr_poll_min_interval = float(
            self.config.get("axfr_poll_min_interval_seconds", 60.0)
        )

        # Watchdog configuration
        self._watchdog_min_interval = float(
            self.config.get("watchdog_min_interval_seconds", 1.0)
        )
        self._watchdog_reject_absolute_paths = bool(
            self.config.get("watchdog_reject_absolute_paths", False)
        )
        watcher_path_allowlist_cfg = self.config.get("watchdog_data_directories")
        if watcher_path_allowlist_cfg is not None:
            self._watchdog_path_allowlist = helpers.normalize_path_allowlist(
                watcher_path_allowlist_cfg
            )
        else:
            self._watchdog_path_allowlist = list(self._path_allowlist or [])
        try:
            self._watchdog_max_files = max(
                1, int(self.config.get("watchdog_max_files", 4096))
            )
        except (TypeError, ValueError):
            self._watchdog_max_files = 4096
        try:
            self._watchdog_max_directories = max(
                1, int(self.config.get("watchdog_max_directories", 256))
            )
        except (TypeError, ValueError):
            self._watchdog_max_directories = 256
        try:
            self._watchdog_snapshot_max_entries = max(
                1, int(self.config.get("watchdog_snapshot_max_entries", 4096))
            )
        except (TypeError, ValueError):
            self._watchdog_snapshot_max_entries = 4096
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
        self._apply_dns_update_journal_replay()
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
            logger.debug(
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
                owner = dns_names.normalize_name(owner_raw)
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
            zone_suffix_index = getattr(self, "_zone_suffix_index", None)
        else:
            with lock:
                records_map = dict(getattr(self, "records", {}) or {})
                name_index = dict(getattr(self, "_name_index", {}) or {})
                zone_soa = dict(getattr(self, "_zone_soa", {}) or {})
                zone_suffix_index = getattr(self, "_zone_suffix_index", None)

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

            owner_norm = dns_names.normalize_name(owner)

            zone = helpers.find_zone_for_name(
                owner_norm, zone_soa, zone_index=zone_suffix_index
            )
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
        dns_update_cfg = getattr(self, "_dns_update_config", None)
        if isinstance(dns_update_cfg, dict):
            persistence_cfg = dns_update_cfg.get("persistence")
            if isinstance(persistence_cfg, dict) and bool(
                persistence_cfg.get("enabled", False)
            ):
                journal_state_dir = getattr(self, "_dns_update_journal_state_dir", None)
                per_zone_state: Dict[str, Dict[str, object]] = {}
                zones_raw = dns_update_cfg.get("zones")
                configured_zones: List[str] = []
                if isinstance(zones_raw, list):
                    configured_zones = [
                        dns_names.normalize_name(z.get("zone", ""))
                        for z in zones_raw
                        if isinstance(z, dict) and z.get("zone")
                    ]
                try:
                    from .journal import load_manifest
                except Exception:
                    load_manifest = None
                for zone in configured_zones:
                    seq = int(
                        getattr(self, "_dynamic_last_seq_by_zone", {}).get(zone, 0) or 0
                    )
                    zone_state: Dict[str, object] = {"last_seq": seq}
                    if journal_state_dir and callable(load_manifest):
                        try:
                            manifest = load_manifest(
                                zone_apex=zone,
                                base_dir=str(journal_state_dir),
                            )
                            zone_state["journal_bytes"] = int(
                                getattr(manifest, "journal_bytes", 0) or 0
                            )
                            zone_state["snapshot_seq"] = int(
                                getattr(manifest, "snapshot_seq", 0) or 0
                            )
                        except Exception:
                            pass
                    per_zone_state[zone] = zone_state
                summary["dns_update"] = {
                    "replay_duration_seconds": float(
                        getattr(self, "_dns_update_replay_duration_seconds", 0.0) or 0.0
                    ),
                    "replay_entries": int(
                        getattr(self, "_dns_update_replay_entries", 0) or 0
                    ),
                    "compactions": int(
                        getattr(self, "_dns_update_compact_count", 0) or 0
                    ),
                    "rate_limit_hits": int(
                        getattr(self, "_dns_update_rate_limit_hits", 0) or 0
                    ),
                    "notify_sent": int(
                        getattr(self, "_dns_update_notify_sent", 0) or 0
                    ),
                    "notify_failed": int(
                        getattr(self, "_dns_update_notify_failed", 0) or 0
                    ),
                    "zones": per_zone_state,
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
        lock = getattr(self, "_reload_records_lock", None)
        if lock is None:
            loader.load_records(self)
            self._apply_dns_update_journal_replay()
            return
        with lock:
            loader.load_records(self)
            self._apply_dns_update_journal_replay()

    def _rebuild_indexes_from_records(self) -> None:
        """Brief: Rebuild internal name and wildcard indexes from records.

        Inputs:
          - None (uses current ``self.records`` mapping).

        Outputs:
          - None; mutates ``self._name_index`` and ``self._wildcard_owners``.
        """
        name_index: Dict[str, Dict[int, Tuple[int, List[str], List[str]]]] = {}
        for (owner, qtype), entry in (self.records or {}).items():
            try:
                ttl, values, sources = entry
            except (TypeError, ValueError):
                try:
                    ttl, values = entry
                    sources = []
                except (TypeError, ValueError):
                    continue
            owner_norm = dns_names.normalize_name(owner)
            qtype_int = int(qtype)
            per_owner = name_index.setdefault(owner_norm, {})
            per_owner[qtype_int] = (
                int(ttl),
                list(values or []),
                list(sources or []),
            )
        self._name_index = name_index
        wildcard_owners = [
            owner
            for owner in name_index.keys()
            if helpers.is_wildcard_domain_pattern(str(owner))
        ]
        self._wildcard_owners = helpers.sort_wildcard_patterns(wildcard_owners)

    def _apply_dns_update_journal_replay(self) -> None:
        """Brief: Replay persisted DNS UPDATE journals onto loaded records.

        Inputs:
          - None (uses current plugin config and in-memory records).

        Outputs:
          - None; mutates ``self.records`` and replay bookkeeping fields.
        """
        try:
            dns_update_cfg = getattr(self, "_dns_update_config", None)
            if not isinstance(dns_update_cfg, dict):
                return
            persistence_cfg = dns_update_cfg.get("persistence", {})
            if not isinstance(persistence_cfg, dict):
                return
            if not bool(persistence_cfg.get("enabled", False)):
                return
            from .journal import replay_journal_to_records
        except Exception:
            return

        state_dir = persistence_cfg.get("state_dir")
        if not state_dir:
            try:
                from foghorn.runtime_config import get_runtime_state_dir

                runtime_state_dir = get_runtime_state_dir()
                if runtime_state_dir:
                    state_dir = f"{runtime_state_dir}/zone_records"
            except Exception:
                state_dir = None
        if not state_dir:
            return

        self._dns_update_journal_state_dir = str(state_dir)

        zones = []
        if isinstance(dns_update_cfg.get("zones"), list):
            zones = [
                dns_names.normalize_name(z.get("zone", ""))
                for z in dns_update_cfg["zones"]
                if isinstance(z, dict) and z.get("zone")
            ]
        if not zones:
            return

        replay_started_at = time.time()
        replay_entries = 0
        with self._records_lock:
            merged_records = dict(self.records or {})
            for zone in zones:
                replayed_records, last_seq = replay_journal_to_records(
                    zone_apex=zone,
                    base_dir=str(state_dir),
                    records=merged_records,
                    start_seq=0,
                )
                merged_records = replayed_records
                self._dynamic_last_seq_by_zone[zone] = int(last_seq)
                replay_entries += max(0, int(last_seq))
            self.records = merged_records
            self._rebuild_indexes_from_records()
        self._dns_update_replay_duration_seconds = max(
            0.0, float(time.time() - replay_started_at)
        )
        self._dns_update_replay_entries = int(replay_entries)

    def compact_dns_update_journals(
        self, zone_apex: Optional[str] = None
    ) -> Dict[str, bool]:
        """Brief: Manually compact DNS UPDATE journals for one or all configured zones.

        Inputs:
          - zone_apex: Optional single zone apex to compact; when omitted all
            configured UPDATE zones are compacted.

        Outputs:
          - Mapping of zone apex to compaction success boolean.
        """
        result: Dict[str, bool] = {}
        dns_update_cfg = getattr(self, "_dns_update_config", None)
        if not isinstance(dns_update_cfg, dict):
            return result
        persistence_cfg = dns_update_cfg.get("persistence", {})
        if not isinstance(persistence_cfg, dict) or not bool(
            persistence_cfg.get("enabled", False)
        ):
            return result
        state_dir = getattr(self, "_dns_update_journal_state_dir", None)
        if not state_dir:
            return result

        configured_zones: List[str] = []
        zones_raw = dns_update_cfg.get("zones")
        if isinstance(zones_raw, list):
            configured_zones = [
                dns_names.normalize_name(z.get("zone", ""))
                for z in zones_raw
                if isinstance(z, dict) and z.get("zone")
            ]
        if zone_apex is not None:
            target = dns_names.normalize_name(zone_apex)
            configured_zones = [z for z in configured_zones if z == target]
        if not configured_zones:
            return result

        from .journal import compact_zone_journal

        with self._records_lock:
            records_snapshot = dict(getattr(self, "records", {}) or {})
        for zone in configured_zones:
            seq = int(getattr(self, "_dynamic_last_seq_by_zone", {}).get(zone, 0) or 0)
            try:
                ok = compact_zone_journal(
                    zone_apex=zone,
                    base_dir=str(state_dir),
                    records=records_snapshot,
                    seq=seq,
                )
            except Exception:
                ok = False
            if ok:
                self._dns_update_compact_count = int(
                    getattr(self, "_dns_update_compact_count", 0) + 1
                )
            result[zone] = bool(ok)
        return result

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
        reload_lock = getattr(self, "_reload_records_lock", None)
        if reload_lock is not None:
            try:
                acquired = reload_lock.acquire(timeout=2.0)
            except TypeError:  # pragma: no cover - defensive for older signatures
                acquired = reload_lock.acquire()
            if acquired:
                reload_lock.release()

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


def _client_allowed_for_axfr(client_ip: Optional[str]) -> bool:
    """Backward-compat wrapper for ZoneRecords-owned AXFR client policy checks."""
    return transfer._client_allowed_for_axfr(client_ip)


def iter_axfr_messages(
    req: DNSRecord,
    client_ip: Optional[str] = None,
    req_wire: Optional[bytes] = None,
) -> List[bytes]:
    """Backward-compat wrapper for ZoneRecords-owned AXFR/IXFR message streaming."""
    return transfer.iter_axfr_messages(req, client_ip=client_ip, req_wire=req_wire)


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
