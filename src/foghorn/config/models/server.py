"""Server block models for Foghorn configuration.

Inputs:
  - server.* sections: listen, resolver, cache, dnssec, limits, http, axfr, features.

Outputs:
  - ServerConfig and nested models for schema generation.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from foghorn.config.models.common import OpenModel, PortInt, StrictModel

OverloadResponse = Literal["servfail", "refused", "drop"]
TrustedListener = Literal["udp", "tcp", "dot", "doh", "secure", "insecure"]


class DecoratedCacheOverride(StrictModel):
    """Brief: Runtime override for a decorated helper cache.

    Inputs:
      - module / name: Target callable identity (required).
      - backend / ttl / maxsize / reset_on_ttl_change: Optional overrides.

    Outputs:
      - DecoratedCacheOverride model ($defs.DecoratedCacheOverride).
    """

    module: str = Field(
        description=(
            "Fully-qualified module name of the decorated function "
            "(e.g. 'foghorn.dnssec.dnssec_validate')."
        ),
    )
    name: str = Field(
        description=(
            "Function name / qualified name for the decorated callable "
            "(e.g. '_find_zone_apex_cached')."
        ),
    )
    backend: (
        Literal[
            "ttlcache",
            "lru_cache",
            "foghorn_ttl",
            "sqlite_ttl",
            "lfu_cache",
            "rr_cache",
        ]
        | None
    ) = Field(
        default=None,
        description=(
            "Optional backend filter (ttlcache, lru_cache, foghorn_ttl, "
            "sqlite_ttl, lfu_cache, or rr_cache)."
        ),
    )
    ttl: int | None = Field(default=None, ge=0)
    maxsize: int | None = Field(default=None, ge=0)
    reset_on_ttl_change: bool = Field(default=False)


class ListenDnsDefaults(StrictModel):
    """Brief: Default host/port for UDP/TCP listeners under server.listen.dns.

    Inputs:
      - host / port defaults shared by plain DNS listeners.

    Outputs:
      - ListenDnsDefaults model.
    """

    host: str | None = Field(
        default=None,
        description="Default host for UDP/TCP listeners when per-listener host is not set.",
    )
    port: PortInt | None = Field(
        default=None,
        description="Default port for UDP/TCP listeners when per-listener port is not set.",
    )


class UdpCidrInflightLimit(StrictModel):
    """Brief: One CIDR bucket limit for UDP in-flight queries.

    Inputs:
      - cidr: CIDR block string.
      - max_inflight: Cap for clients in that CIDR.

    Outputs:
      - UdpCidrInflightLimit model.
    """

    cidr: str = Field(description="CIDR block (e.g. '10.0.0.0/8' or '2001:db8::/32').")
    max_inflight: int = Field(
        ge=1,
        description="Maximum in-flight UDP queries for clients within this CIDR.",
    )


class ListenerConnLimits(OpenModel):
    """Brief: Shared connection-limit knobs for TCP/DoT-style listeners.

    Inputs:
      - max_connections*, idle_timeout_seconds, overload_response.

    Outputs:
      - Fields mixed into tcp/dot listener models.
    """

    max_connections: int = Field(default=1024, ge=1)
    max_connections_per_ip: int = Field(default=64, ge=1)
    max_queries_per_connection: int = Field(default=100, ge=1)
    idle_timeout_seconds: float = Field(default=15.0, ge=0)
    overload_response: OverloadResponse | None = Field(
        default=None,
        description="Per-listener overload response policy for connection-limit rejections.",
    )


class ListenerUdp(OpenModel):
    """Brief: UDP listener configuration under server.listen.udp.

    Inputs:
      - enabled/host/port plus in-flight and size limits.

    Outputs:
      - ListenerUdp model.
    """

    enabled: bool | None = None
    host: str | None = None
    port: PortInt | None = None
    use_asyncio: bool = Field(default=True)
    allow_threaded_fallback: bool = Field(default=True)
    exit_on_asyncio_failure: bool = Field(default=False)
    max_inflight: int = Field(default=1024, ge=1)
    max_inflight_per_ip: int = Field(default=64, ge=1)
    max_query_bytes: int = Field(default=4096, ge=12)
    max_response_bytes: int | None = Field(default=None, ge=0)
    overload_response: OverloadResponse | None = None
    max_inflight_by_cidr: list[UdpCidrInflightLimit] | None = Field(
        default=None,
        description=(
            "Optional CIDR bucket limits for UDP in-flight queries. "
            "When multiple buckets match, the most-specific prefix wins."
        ),
    )


class ListenerTcp(ListenerConnLimits):
    """Brief: TCP listener configuration under server.listen.tcp."""

    enabled: bool | None = None
    host: str | None = None
    port: PortInt | None = None


class ListenerDot(ListenerConnLimits):
    """Brief: DNS-over-TLS listener configuration under server.listen.dot."""

    enabled: bool | None = None
    host: str | None = None
    port: PortInt | None = None
    cert_file: str | None = None
    key_file: str | None = None
    generate: str | bool | None = Field(
        default="no",
        description=(
            "Optional self-signed TLS generation policy: no|maybe|yes "
            "(boolean aliases accepted). Same semantics as server.http.generate."
        ),
    )
    keys_dir: str | None = None
    tls_days: int = Field(default=3650, ge=1)


class ListenerDoh(OpenModel):
    """Brief: DNS-over-HTTPS listener configuration under server.listen.doh."""

    enabled: bool | None = None
    host: str | None = None
    port: PortInt | None = None
    cert_file: str | None = None
    key_file: str | None = None
    allow_threaded_fallback: bool = Field(default=True)
    overload_response: OverloadResponse | None = None


class ServerListenConfig(StrictModel):
    """Brief: server.listen block.

    Inputs:
      - dns defaults, per-listener blocks, global overload_response.

    Outputs:
      - ServerListenConfig model.
    """

    overload_response: OverloadResponse = Field(
        default="servfail",
        description=(
            "Global overload response policy for listeners. When set, this "
            "value is used by listeners unless overridden by "
            "server.listen.<listener>.overload_response."
        ),
    )
    dns: ListenDnsDefaults | None = None
    udp: ListenerUdp | None = None
    tcp: ListenerTcp | None = None
    dot: ListenerDot | None = None
    doh: ListenerDoh | None = None


class ServerResolverConfig(OpenModel):
    """Brief: server.resolver configuration.

    Inputs:
      - mode / timeouts / recursion controls.

    Outputs:
      - ServerResolverConfig model.
    """

    mode: Literal["forward", "recursive", "master", "none"] = Field(
        default="forward",
        description="Resolver mode: forward | recursive | master (none).",
    )
    timeout_ms: int = Field(default=2000, ge=0)
    max_depth: int = Field(
        default=12,
        ge=1,
        le=32,
        description="Recursive resolver max depth (clamped 1..32 at runtime).",
    )
    allow_private_destinations: bool = Field(default=True)
    destination_allowlist: list[str] = Field(default_factory=list)
    per_try_timeout_ms: int = Field(default=2000, ge=0)
    use_asyncio: bool = Field(default=True)


class ServerLimitsConfig(OpenModel):
    """Brief: server.limits hardening knobs."""

    resolver_executor_workers: int | None = Field(default=None, ge=1)
    bg_executor_workers: int | None = Field(default=4, ge=1)
    bg_executor_max_pending: int | None = Field(default=None, ge=1)


class ServerCacheConfig(OpenModel):
    """Brief: server.cache DNS cache selection and decorated overrides."""

    module: str | None = None
    config: dict[str, Any] | None = None
    modify: list[DecoratedCacheOverride] | None = None
    decorated_overrides: list[DecoratedCacheOverride] | None = None


class ServerDnssecConfig(OpenModel):
    """Brief: server.dnssec configuration.

    Inputs:
      - Open mapping for DNSSEC knobs (validation/signing/payload size, etc.).
      - Common keys include mode, validation, udp_payload_size, and for RFC 5011
        trust-anchor management: trust_anchor_mode, trust_anchor_store_path.

    Outputs:
      - Permissive dnssec object; detailed constraints live in runtime code.
    """

    trust_anchor_store_path: str | None = Field(
        default=None,
        description=(
            "Filesystem path for the RFC 5011 trust-anchor JSON store. When "
            "server.data_root is set, must resolve under that directory."
        ),
    )


class HttpAuthConfig(StrictModel):
    """Brief: server.http.auth configuration.

    Inputs:
      - mode: Auth mode (default "token"): none | token | basic.
      - token: Static bearer/API key token for mode=token.
      - username: HTTP Basic auth user name for mode=basic.
      - password: HTTP Basic auth password for mode=basic.

    Outputs:
      - HttpAuthConfig instance used by the config schema and runtime checks.
    """

    mode: Literal["none", "token", "basic"] = Field(default="token")
    token: str | None = None
    username: str | None = None
    password: str | None = None


class ServerHttpConfig(OpenModel):
    """Brief: Admin HTTP server configuration under server.http."""

    host: str = Field(default="127.0.0.1")
    port: PortInt = Field(default=5380)
    allow_threaded_fallback: bool = Field(default=True)
    cert_file: str | None = None
    key_file: str | None = None
    generate: str | bool | None = Field(
        default="no",
        description=(
            "Optional self-signed TLS generation policy: no|maybe|yes "
            "(boolean aliases accepted)."
        ),
    )
    keys_dir: str | None = None
    tls_days: int = Field(default=3650, ge=1)
    enable_api: bool = Field(default=False)
    enable_admin: bool = Field(default=False)
    enable_schema: bool = Field(default=False)
    enable_docs: bool = Field(default=False)
    auth: HttpAuthConfig | None = None


class AxfrTsigKey(StrictModel):
    """Brief: One inline AXFR/IXFR TSIG key."""

    name: str
    algorithm: str = Field(default="hmac-sha256")
    secret: str


class AxfrTsigKeySource(OpenModel):
    """Brief: External TSIG key source entry under server.axfr.tsig.key_sources.

    Inputs:
      - type: Source type (required), e.g. file.
      - path: Optional filesystem path for file sources.
      - Additional source-specific keys allowed.

    Outputs:
      - AxfrTsigKeySource model.
    """

    type: str = Field(description="Key source type (for example 'file').")
    path: str | None = Field(
        default=None, description="Filesystem path for file sources."
    )


class AxfrTsigConfig(StrictModel):
    """Brief: server.axfr.tsig keys and key_sources."""

    keys: list[AxfrTsigKey] = Field(default_factory=list)
    key_sources: list[AxfrTsigKeySource] = Field(default_factory=list)


class ServerAxfrConfig(OpenModel):
    """Brief: server.axfr zone-transfer controls."""

    enabled: bool = Field(default=False)
    allow_clients: list[str] = Field(default_factory=list)
    max_zone_rrs: int | None = Field(default=None, ge=1)
    max_concurrent_transfers: int = Field(default=4, ge=1)
    rate_limit_per_client_per_second: float = Field(default=0.0, ge=0)
    rate_limit_burst: float = Field(default=2.0, ge=1)
    max_transfer_rate_bytes_per_second: int | None = Field(default=None, ge=1)
    message_max_bytes: int = Field(default=64000, ge=512, le=65535)
    require_tsig: bool = Field(default=False)
    tsig: AxfrTsigConfig | None = None
    tsig_keys: list[AxfrTsigKey] = Field(
        default_factory=list,
        description="Legacy alias for server.axfr.tsig.keys.",
    )


class CookiesFeatureConfig(StrictModel):
    """Brief: server.features.cookies controls."""

    enabled: bool = Field(default=True)
    mode: Literal["learn", "require_udp"] = Field(default="learn")
    secret: str | None = None
    secret_old: str | None = None
    lifetime_seconds: int = Field(default=86400, ge=1, le=604800)


class TsigFeatureKey(StrictModel):
    """Brief: One inline server.features.tsig key."""

    name: str
    algorithm: str = Field(default="hmac-sha256")
    secret: str


class TsigFeatureKeySource(OpenModel):
    """Brief: External key source under server.features.tsig.key_sources.

    Inputs:
      - type: Source type (required), e.g. file.
      - path: Optional filesystem path for file sources.

    Outputs:
      - TsigFeatureKeySource model.
    """

    type: str = Field(description="Key source type (for example 'file').")
    path: str | None = Field(
        default=None, description="Filesystem path for file sources."
    )


class TsigFeatureConfig(StrictModel):
    """Brief: server.features.tsig downstream QUERY TSIG controls.

    Inputs:
      - enabled/mode/keys/key_sources/max_fudge_seconds/allow_clients/listeners.

    Outputs:
      - TsigFeatureConfig model.
    """

    enabled: bool = Field(
        default=False,
        description="Enable downstream QUERY TSIG verification and response signing.",
    )
    mode: Literal["optional", "require"] = Field(
        default="optional",
        description=(
            "optional accepts unsigned queries; require rejects missing TSIG "
            "with NOTAUTH."
        ),
    )
    keys: list[TsigFeatureKey] = Field(default_factory=list)
    key_sources: list[TsigFeatureKeySource] = Field(default_factory=list)
    max_fudge_seconds: int = Field(default=300, ge=0, le=86400)
    allow_clients: list[str] = Field(default_factory=list)
    listeners: list[TrustedListener] = Field(default_factory=list)


class EcsFeatureConfig(StrictModel):
    """Brief: server.features.ecs EDNS Client Subnet controls.

    Inputs:
      - enabled / forward_inbound / synthesize_from_client_ip.
      - source/scope prefix lengths and trust lists.

    Outputs:
      - EcsFeatureConfig model.
    """

    enabled: bool = Field(
        default=False,
        description="Enable ECS parsing and policy controls in the resolver.",
    )
    forward_inbound: bool = Field(
        default=False,
        description="Forward trusted inbound ECS to upstream resolvers in forward mode.",
    )
    synthesize_from_client_ip: bool = Field(
        default=False,
        description=(
            "When inbound ECS is absent, synthesize ECS from transport source IP "
            "in forward mode."
        ),
    )
    source_prefix_v4: int = Field(default=24, ge=0, le=32)
    source_prefix_v6: int = Field(default=56, ge=0, le=128)
    scope_prefix_v4: int = Field(default=0, ge=0, le=32)
    scope_prefix_v6: int = Field(default=0, ge=0, le=128)
    trusted_listeners: list[TrustedListener] = Field(default_factory=list)
    trusted_client_cidrs: list[str] = Field(default_factory=list)
    use_for_plugin_targeting: bool = Field(
        default=False,
        description="Allow trusted inbound ECS to drive plugin target-IP matching.",
    )


class ServerFeaturesConfig(StrictModel):
    """Brief: Canonical feature gates under server.features."""

    enable_ede: bool = Field(default=False)
    forward_local: bool = Field(default=False)
    refuse_any: bool = Field(default=False)
    cookies: CookiesFeatureConfig | None = None
    tsig: TsigFeatureConfig | None = None
    ecs: EcsFeatureConfig | None = None


class ServerConfig(StrictModel):
    """Brief: Top-level server configuration block.

    Inputs:
      - listen / resolver / cache / dnssec / limits / http / axfr / features.
      - data_root: Optional base directory for local file path containment.
      - Legacy enable_ede / forward_local aliases.

    Outputs:
      - ServerConfig model for FoghornConfig.server.
    """

    data_root: str | None = Field(
        default=None,
        description=(
            "Optional base directory for local file operations. When set, "
            "configurable paths (DNSSEC trust-anchor store, EtcHosts files, "
            "JSON query-log file_path, etc.) must resolve under this directory; "
            "paths that escape it fail startup validation. Relative paths are "
            "resolved against data_root. When unset, legacy unconstrained path "
            "resolution is used."
        ),
    )
    listen: ServerListenConfig | None = None
    resolver: ServerResolverConfig | None = None
    cache: None | ServerCacheConfig | str = None
    dnssec: ServerDnssecConfig | None = None
    limits: ServerLimitsConfig | None = None
    http: ServerHttpConfig | None = None
    axfr: ServerAxfrConfig | None = None
    features: ServerFeaturesConfig | None = None
    enable_ede: bool | None = Field(
        default=False,
        description="Deprecated legacy alias for server.features.enable_ede.",
    )
    forward_local: bool | None = Field(
        default=False,
        description="Deprecated legacy alias for server.features.forward_local.",
    )
