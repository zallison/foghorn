"""Server block models for Foghorn configuration.

Inputs:
  - server.* sections: listen, resolver, cache, dnssec, limits, http, axfr, features.

Outputs:
  - ServerConfig and nested models for schema generation.
"""

from __future__ import annotations

from typing import Any, Literal, Self

from pydantic import Field, model_validator

from foghorn.config.models.common import (
    BytesInt,
    PortInt,
    SecondsFloat,
    SecondsInt,
    StrictModel,
)

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


class ListenerConnLimits(StrictModel):
    """Brief: Shared connection-limit knobs for TCP/DoT-style listeners.

    Inputs:
      - max_connections*, idle_timeout_seconds, overload_response.

    Outputs:
      - Fields mixed into tcp/dot listener models.
    """

    max_connections: int = Field(default=1024, ge=1)
    max_connections_per_ip: int = Field(default=64, ge=1)
    max_queries_per_connection: int = Field(default=100, ge=1)
    idle_timeout_seconds: SecondsFloat = Field(default=15.0, ge=0)
    overload_response: OverloadResponse | None = Field(
        default=None,
        description="Per-listener overload response policy for connection-limit rejections.",
    )


class ListenerUdp(StrictModel):
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
    max_query_bytes: BytesInt = Field(default=4096, ge=12)
    max_response_bytes: BytesInt | None = Field(default=None, ge=0)
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
    enable_tls: bool | str | None = Field(
        default=None,
        description=(
            "Explicit TLS enable flag: enabled/true/yes or disabled/false/no. "
            "When unset, cert material enables TLS. When explicitly disabled "
            "while certs/secrets/generate are set, startup fails."
        ),
    )
    cert_file: str | None = None
    key_file: str | None = None
    cert_secret: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Secrets ref for TLS certificate: "
            "{id|backend: <backend-id>, key: <secret-key>}."
        ),
    )
    key_secret: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Secrets ref for TLS private key: "
            "{id|backend: <backend-id>, key: <secret-key>}."
        ),
    )
    generate: str | bool | None = Field(
        default="no",
        description=(
            "Optional self-signed TLS generation policy: no|maybe|yes "
            "(boolean aliases accepted). Same semantics as server.http.generate."
        ),
    )
    keys_dir: str | None = None
    tls_days: int = Field(default=3650, ge=1)


class ListenerDoh(StrictModel):
    """Brief: DNS-over-HTTPS listener configuration under server.listen.doh."""

    enabled: bool | None = None
    host: str | None = None
    port: PortInt | None = None
    enable_tls: bool | str | None = Field(
        default=None,
        description=(
            "Explicit TLS enable flag: enabled/true/yes or disabled/false/no. "
            "When unset, cert material enables TLS. When explicitly disabled "
            "while certs/secrets are set, startup fails."
        ),
    )
    cert_file: str | None = None
    key_file: str | None = None
    cert_secret: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Secrets ref for TLS certificate: "
            "{id|backend: <backend-id>, key: <secret-key>}."
        ),
    )
    key_secret: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Secrets ref for TLS private key: "
            "{id|backend: <backend-id>, key: <secret-key>}."
        ),
    )
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


class ResolverSearchConfig(StrictModel):
    """Brief: server.resolver.search domain qualification settings.

    Inputs:
      - domain: Search/qualification suffix (e.g. lan domain).
      - qualify_single_label: Append domain to single-label queries.
      - qualify_non_proper_tld: Bool or list of non-proper TLD suffixes to qualify.
      - non_proper_tld_mode: Match mode for list entries (suffix|exact).

    Outputs:
      - ResolverSearchConfig nested under server.resolver.search.
    """

    domain: str = Field(
        default="", description="Search domain suffix without trailing dot."
    )
    qualify_single_label: bool = Field(
        default=True,
        description="When true, append search domain to single-label queries.",
    )
    qualify_non_proper_tld: bool | list[str] = Field(
        default=False,
        description=(
            "When true, qualify names under non-proper TLDs; when a list, "
            "only those suffixes/names are qualified."
        ),
    )
    non_proper_tld_mode: Literal["suffix", "exact"] = Field(
        default="suffix",
        description="How list entries in qualify_non_proper_tld are matched.",
    )


class ServerResolverConfig(StrictModel):
    """Brief: server.resolver configuration.

    Inputs:
      - mode / timeouts / recursion controls.
      - search: Optional search-domain qualification block.

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
    search: ResolverSearchConfig | None = Field(
        default=None,
        description="Optional search-domain qualification for short names.",
    )


class ServerLimitsConfig(StrictModel):
    """Brief: server.limits hardening knobs."""

    resolver_executor_workers: int | None = Field(default=None, ge=1)
    bg_executor_workers: int | None = Field(default=4, ge=1)
    bg_executor_max_pending: int | None = Field(default=None, ge=1)
    allow_unsafe_threaded_listeners: bool = Field(
        default=False,
        description=(
            "When true, allow threaded UDP/TCP listeners on non-loopback binds "
            "(DoS-exposed; asyncio is preferred)."
        ),
    )


class ServerCacheConfig(StrictModel):
    """Brief: server.cache DNS cache selection and decorated overrides."""

    module: str | None = None
    config: dict[str, Any] | None = Field(
        default=None,
        description="Opaque cache-backend configuration mapping.",
    )
    func_caches: list[DecoratedCacheOverride] | None = Field(
        default=None,
        description="Decorated helper cache overrides (preferred key).",
    )
    modify: list[DecoratedCacheOverride] | None = Field(
        default=None,
        description="Deprecated alias for func_caches.",
    )
    decorated_overrides: list[DecoratedCacheOverride] | None = Field(
        default=None,
        description="Deprecated alias for func_caches.",
    )


class TrustAnchorEntry(StrictModel):
    """Brief: One operator trust anchor under server.dnssec.trust_anchors.

    Inputs:
      - zone: Zone apex (default '.').
      - type: Optional 'dnskey' | 'ds' (inferred from fields when omitted).
      - DNSKEY form: algorithm + public_key (flags/protocol optional).
      - DS form: key_tag + algorithm + digest_type + digest.

    Outputs:
      - TrustAnchorEntry model used by schema generation.
    """

    zone: str = Field(default=".", description="Zone apex for this trust anchor.")
    type: Literal["dnskey", "ds", "key"] | None = Field(
        default=None,
        description="Anchor kind; inferred from public_key vs digest when omitted.",
    )
    # DNSKEY fields
    flags: int | None = Field(
        default=257, description="DNSKEY flags (default 257 KSK)."
    )
    protocol: int | None = Field(default=3, description="DNSKEY protocol (always 3).")
    algorithm: int | None = Field(
        default=None, description="DNSKEY/DS algorithm number."
    )
    public_key: str | None = Field(
        default=None, description="Base64 DNSKEY public key material."
    )
    public_key_b64: str | None = Field(
        default=None, description="Alias for public_key."
    )
    # DS fields
    key_tag: int | None = Field(default=None, description="DS key tag.")
    digest_type: int | None = Field(
        default=None, description="DS digest type (2=SHA-256)."
    )
    digest_alg: int | None = Field(default=None, description="Alias for digest_type.")
    digest: str | None = Field(default=None, description="DS digest hex string.")


class ServerDnssecConfig(StrictModel):
    """Brief: server.dnssec configuration.

    Inputs:
      - mode / validation / udp_payload_size for EDNS and validation strategy.
      - trust_anchor_mode / trust_anchor_store_path / hold-downs for RFC 5011.
      - trust_anchors: optional static DNSKEY/DS anchors (root or islands).

    Outputs:
      - Permissive dnssec object; runtime applies knobs via dnssec_validate.
    """

    mode: Literal["ignore", "passthrough", "validate"] | None = Field(
        default="ignore",
        description="DNSSEC mode: ignore | passthrough | validate.",
    )
    validation: Literal["upstream_ad", "local", "local_extended"] | None = Field(
        default="upstream_ad",
        description=(
            "When mode=validate: upstream_ad trusts upstream AD bit; "
            "local/local_extended perform local chain validation."
        ),
    )
    udp_payload_size: int | None = Field(
        default=1232,
        ge=512,
        le=65535,
        description="Default EDNS UDP payload size.",
    )
    trust_anchor_mode: Literal["static", "rfc5011"] | None = Field(
        default="static",
        description=(
            "static uses baked-in root KSK (+ trust_anchors); rfc5011 enables "
            "automated root trust-anchor management (requires store path)."
        ),
    )
    trust_anchor_store_path: str | None = Field(
        default=None,
        description=(
            "Filesystem path for the RFC 5011 trust-anchor JSON store. When "
            "server.data_root is set, must resolve under that directory."
        ),
    )
    hold_down_add_days: int | None = Field(
        default=2,
        ge=0,
        description=(
            "RFC 5011: days a new KSK must remain present before promotion "
            "from pending_add to trusted."
        ),
    )
    hold_down_remove_days: int | None = Field(
        default=2,
        ge=0,
        description=(
            "RFC 5011: days a missing/revoked KSK must remain absent before "
            "removal from the trusted set."
        ),
    )
    trust_anchors: list[TrustAnchorEntry] | None = Field(
        default=None,
        description=(
            "Optional static DNSKEY and/or DS trust anchors. DNSKEY entries "
            "for '.' supplement the root anchors; non-root DNSKEY/DS entries "
            "create islands of trust for local validation."
        ),
    )


class HttpAuthConfig(StrictModel):
    """Brief: server.http.auth configuration.

    Inputs:
      - mode: Auth mode (default "token"): none | token | basic.
      - token: Static token for mode=token (Bearer, X-API-Key, and optionally
        Basic foghorn:<token>). Must not be set when mode=basic.
      - token_secret: Optional secrets-backend ref ({backend,id} or id string)
        used when token is blank.
      - allow_basic_token: When mode=token, accept Basic foghorn:<token> and
        advertise Basic on 401 (default true).
      - username: HTTP Basic auth user name for mode=basic.
      - password: HTTP Basic auth password for mode=basic.

    Outputs:
      - HttpAuthConfig instance used by the config schema and runtime checks.
    """

    mode: Literal["none", "token", "basic"] = Field(default="token")
    token: str | None = None
    token_secret: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional secrets backend reference for mode=token when token is "
            "unset: {id|backend: <backend-id>, key: <secret-key>}."
        ),
    )
    # password_secret is declared below with password.
    allow_basic_token: bool = Field(
        default=True,
        description=(
            "When mode=token, accept Authorization: Basic foghorn:<token> "
            "(password is the token) and include Basic in WWW-Authenticate. "
            "Set false to require Bearer or X-API-Key only."
        ),
    )
    username: str | None = None
    password: str | dict[str, Any] | None = None
    password_secret: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional secrets ref for mode=basic when password is unset: "
            "{id|backend: <backend-id>, key: <secret-key>}."
        ),
    )

    @model_validator(mode="after")
    def _reject_basic_mode_with_token(self) -> Self:
        """Brief: Reject mode=basic combined with a non-empty token.

        Inputs:
          - self: Validated HttpAuthConfig fields.

        Outputs:
          - Self when the combination is allowed.

        Raises:
          - ValueError: when mode is basic and token is non-empty (ambiguous).
        """

        mode = str(self.mode or "token").strip().lower()
        token = str(self.token or "").strip()
        if mode == "basic" and token:
            raise ValueError(
                "server.http.auth.mode=basic must not set auth.token "
                "(token is only valid with mode=token); remove token or switch mode"
            )
        return self


class HttpLogsConfig(StrictModel):
    """Brief: server.http.logs ring-buffer settings."""

    buffer_size: int = Field(default=500, ge=1)


class HttpCorsConfig(StrictModel):
    """Brief: server.http.cors settings."""

    enabled: bool = Field(default=False)
    allowlist: list[str] = Field(default_factory=list)
    allow_credentials: bool = Field(default=False)


class HttpApiRequestAuditConfig(StrictModel):
    """Brief: server.http.api_request_audit settings."""

    enabled: bool = Field(default=True)
    db_path: str | None = None
    retention_max_records: int | None = Field(default=None, ge=0)
    retention_max_age_seconds: SecondsFloat | None = Field(default=None, ge=0)
    retention_max_db_bytes: BytesInt | None = Field(
        default=None,
        ge=0,
        description="Optional SQLite file size cap for audit log pruning (bytes).",
    )
    retention_prune_every_n_inserts: int | None = Field(
        default=None,
        ge=1,
        description="Run retention prune after this many inserts (default 100 at runtime).",
    )


class HttpAdminRateLimitConfig(StrictModel):
    """Brief: server.http.admin_rate_limit settings."""

    enabled: bool = Field(default=True)
    backend: Literal["plugin", "memory"] = Field(default="plugin")
    requests_per_window: int = Field(default=60, ge=1)
    window_seconds: SecondsInt = Field(default=60, ge=1)
    burst: int = Field(default=0, ge=0)
    key_mode: Literal["client", "client_action"] = Field(default="client_action")
    excluded_actions: list[str] = Field(default_factory=list)


class ServerHttpConfig(StrictModel):
    """Brief: Admin HTTP server configuration under server.http."""

    enabled: bool | None = Field(
        default=None,
        description="When unset, presence of the http block enables the admin server.",
    )
    host: str = Field(default="127.0.0.1")
    port: PortInt = Field(default=5380)
    allow_threaded_fallback: bool = Field(default=True)
    enable_tls: bool | str | None = Field(
        default=None,
        description=(
            "Explicit TLS enable flag: enabled/true/yes or disabled/false/no. "
            "When unset, cert material enables HTTPS. When explicitly disabled "
            "while certs/secrets/generate are set, startup fails."
        ),
    )
    cert_file: str | None = None
    key_file: str | None = None
    cert_secret: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Secrets ref for TLS certificate: "
            "{id|backend: <backend-id>, key: <secret-key>}."
        ),
    )
    key_secret: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Secrets ref for TLS private key: "
            "{id|backend: <backend-id>, key: <secret-key>}."
        ),
    )
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
    www_root: str | None = Field(
        default=None,
        description="Static admin UI root directory override.",
    )
    index: bool = Field(default=True, description="Serve / and /index.html when true.")
    logs: HttpLogsConfig | None = None
    system_info_ttl_seconds: SecondsFloat | None = Field(default=None, ge=0)
    stats_snapshot_ttl_seconds: SecondsFloat | None = Field(default=None, ge=0)
    config_cache_ttl_seconds: SecondsFloat | None = Field(default=None, ge=0)
    system_metrics_detail: Literal["basic", "full"] | None = Field(default=None)
    debug_timings: bool = Field(default=False)
    limit_concurrency: int | None = Field(
        default=None,
        ge=1,
        description="Optional uvicorn concurrency cap override for admin HTTP.",
    )
    cors: HttpCorsConfig | None = None
    auth: HttpAuthConfig | None = None
    redact_keys: list[str] | None = Field(
        default=None,
        description="Extra secret key names redacted in /config responses.",
    )
    api_request_audit: HttpApiRequestAuditConfig | None = None
    admin_rate_limit: HttpAdminRateLimitConfig | None = None


class AxfrTsigKey(StrictModel):
    """Brief: One inline AXFR/IXFR TSIG key."""

    name: str
    algorithm: str = Field(default="hmac-sha256")
    secret: str


class AxfrTsigKeySource(StrictModel):
    """Brief: External TSIG key source entry under server.axfr.tsig.key_sources.

    Inputs:
      - type: Source type (required): file | secrets | store.
      - path: Filesystem path for type=file.
      - backend / id / ids: Secrets router selectors for type=secrets.

    Outputs:
      - AxfrTsigKeySource model.
    """

    type: str = Field(
        description="Key source type (file, secrets, or store).",
    )
    path: str | None = Field(
        default=None, description="Filesystem path for file sources."
    )
    backend: str | None = Field(
        default=None, description="Secrets backend id when type=secrets."
    )
    id: str | None = Field(default=None, description="Secret id when type=secrets.")
    ids: list[str] | None = Field(
        default=None,
        description="Legacy secret keys when type=secrets without key=.",
    )
    key: str | None = Field(
        default=None, description="Secret lookup key when type=secrets."
    )
    keys: list[str] | None = Field(
        default=None, description="Secret lookup keys when type=secrets."
    )


class AxfrTsigConfig(StrictModel):
    """Brief: server.axfr.tsig keys and key_sources."""

    keys: list[AxfrTsigKey] = Field(default_factory=list)
    key_sources: list[AxfrTsigKeySource] = Field(default_factory=list)


class ServerAxfrConfig(StrictModel):
    """Brief: server.axfr zone-transfer controls."""

    enabled: bool = Field(default=False)
    allow_clients: list[str] = Field(default_factory=list)
    max_zone_rrs: int | None = Field(default=None, ge=1)
    max_concurrent_transfers: int = Field(default=4, ge=1)
    rate_limit_per_client_per_second: float = Field(default=0.0, ge=0)
    rate_limit_burst: float = Field(default=2.0, ge=1)
    max_transfer_rate_bytes_per_second: BytesInt | None = Field(default=None, ge=1)
    message_max_bytes: BytesInt = Field(default=64000, ge=512, le=65535)
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
    lifetime_seconds: SecondsInt = Field(default=86400, ge=1, le=604800)


class TsigFeatureKey(StrictModel):
    """Brief: One inline server.features.tsig key."""

    name: str
    algorithm: str = Field(default="hmac-sha256")
    secret: str


class TsigFeatureKeySource(StrictModel):
    """Brief: External key source under server.features.tsig.key_sources.

    Inputs:
      - type: Source type (required): file | secrets | store.
      - path: Filesystem path for type=file.
      - backend / id / ids: Secrets router selectors for type=secrets.

    Outputs:
      - TsigFeatureKeySource model.
    """

    type: str = Field(
        description="Key source type (file, secrets, or store).",
    )
    path: str | None = Field(
        default=None, description="Filesystem path for file sources."
    )
    backend: str | None = Field(
        default=None, description="Secrets backend id when type=secrets."
    )
    id: str | None = Field(default=None, description="Secret id when type=secrets.")
    ids: list[str] | None = Field(
        default=None,
        description="Legacy secret keys when type=secrets without key=.",
    )
    key: str | None = Field(
        default=None, description="Secret lookup key when type=secrets."
    )
    keys: list[str] | None = Field(
        default=None, description="Secret lookup keys when type=secrets."
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
    mode: Literal["optional", "require", "passthrough"] = Field(
        default="optional",
        description=(
            "optional accepts unsigned queries; require rejects missing TSIG "
            "with NOTAUTH; passthrough forwards client TSIG without local "
            "verify/re-sign."
        ),
    )
    keys: list[TsigFeatureKey] = Field(default_factory=list)
    key_sources: list[TsigFeatureKeySource] = Field(default_factory=list)
    max_fudge_seconds: SecondsInt = Field(default=300, ge=0, le=86400)
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
