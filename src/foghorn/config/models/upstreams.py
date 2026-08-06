"""Upstream endpoint and pool models for Foghorn configuration.

Inputs:
  - Top-level upstreams block (endpoints, strategy, backup, health).

Outputs:
  - UpstreamsConfig and related endpoint models for schema generation.
"""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from foghorn.config.models.common import PortInt, StrictModel


class UpstreamTlsConfig(StrictModel):
    """Brief: TLS settings for an upstream endpoint.

    Inputs:
      - verify / ca_file / server_name.

    Outputs:
      - UpstreamTlsConfig model.
    """

    verify: bool | None = Field(
        default=None,
        description="When true, verify upstream TLS certificates.",
    )
    ca_file: str | None = Field(
        default=None,
        description="Optional CA bundle path used to verify the upstream cert.",
    )
    server_name: str | None = Field(
        default=None,
        description="Optional SNI / expected server name for TLS.",
    )


class UpstreamPoolConfig(StrictModel):
    """Brief: Connection pool knobs for an upstream endpoint.

    Inputs:
      - max_connections / idle_timeout_ms.

    Outputs:
      - UpstreamPoolConfig model.
    """

    max_connections: int | None = Field(default=None, ge=1)
    idle_timeout_ms: int | None = Field(default=None, ge=0)


class UpstreamNotifyConfig(StrictModel):
    """Brief: NOTIFY-related allow/block lists for an upstream endpoint.

    Inputs:
      - allow_hosts / allow_zones / block_hosts.

    Outputs:
      - UpstreamNotifyConfig model.
    """

    allow_hosts: list[str] | None = None
    allow_zones: list[str] | None = None
    block_hosts: list[str] | None = None


class UpstreamEndpointBase(StrictModel):
    """Brief: Shared optional fields on host/DoH/URL upstream endpoints.

    Inputs:
      - abort_on_fail aliases, tls/pool/notify, metadata.

    Outputs:
      - Base fields mixed into concrete endpoint models.
    """

    abort_on_fail: bool | None = None
    abort_on_failure: bool | None = None
    tls: UpstreamTlsConfig | None = None
    pool: UpstreamPoolConfig | None = None
    notify: UpstreamNotifyConfig | None = None

    model_config = ConfigDict(extra="allow")


class UpstreamHost(UpstreamEndpointBase):
    """Brief: Host/port upstream endpoint (UDP/TCP/DoT-style).

    Inputs:
      - host: Upstream hostname or IP (required).
      - port / transport / shared endpoint fields.

    Outputs:
      - UpstreamHost model ($defs.upstream_host).
    """

    host: str = Field(description="Upstream hostname or IP address.")
    port: PortInt | None = Field(default=53, description="Upstream port.")
    transport: Literal["udp", "tcp", "dot"] | None = Field(
        default="udp",
        description="Transport: udp, tcp, or dot.",
    )


class UpstreamDoh(UpstreamEndpointBase):
    """Brief: DoH upstream endpoint.

    Inputs:
      - url: HTTPS DoH URL (required).
      - method / headers / transport / shared fields.

    Outputs:
      - UpstreamDoh model ($defs.upstream_doh).
    """

    url: str = Field(description="DoH URL (https://...).")
    transport: Literal["doh"] = Field(default="doh")
    method: Literal["GET", "POST"] | None = Field(default=None)
    headers: dict[str, str] | None = None


class UpstreamUrl(UpstreamEndpointBase):
    """Brief: URL-form upstream endpoint (udp/tcp/dot schemes).

    Inputs:
      - url: Endpoint URL with scheme (required).
      - transport / shared endpoint fields.

    Outputs:
      - UpstreamUrl model ($defs.upstream_url).
    """

    url: str = Field(
        description=(
            "Upstream URL (udp://, tcp://, or dot://). "
            "DoH uses upstream_doh or https DoH endpoints."
        ),
        pattern=r"^(udp|tcp|dot)://",
    )
    transport: Literal["udp", "tcp", "dot"] | None = None


UpstreamEndpoint = UpstreamHost | UpstreamDoh | UpstreamUrl


class UpstreamsBackup(StrictModel):
    """Brief: Backup upstream pool.

    Inputs:
      - endpoints: Backup endpoint list.
      - Optional strategy overrides.

    Outputs:
      - UpstreamsBackup model.
    """

    endpoints: list[UpstreamEndpoint] = Field(default_factory=list)
    strategy: Literal["failover", "round_robin", "random"] | None = None

    model_config = ConfigDict(extra="allow")


class UpstreamsHealth(StrictModel):
    """Brief: Upstream health-check configuration.

    Inputs:
      - probe_* percentages, max_serv_fail, recheck timers, profile.

    Outputs:
      - UpstreamsHealth model.
    """

    profile: str | None = Field(
        default=None,
        description="Optional named health profile identifier.",
    )
    max_serv_fail: int = Field(default=3, ge=0)
    max_recheck: float = Field(default=300.0, ge=0)
    unknown_after_seconds: float = Field(default=300.0, ge=0)
    probe_percent: float = Field(default=1.0, ge=0, le=100)
    probe_min_percent: float = Field(default=0.5, ge=0.5, le=100)
    probe_max_percent: float = Field(default=50.0, ge=0, le=100)
    probe_increase: float = Field(default=1.0, ge=0, le=100)
    probe_decrease: float = Field(default=1.0, ge=0, le=100)


class UpstreamsConfig(StrictModel):
    """Brief: Top-level upstreams configuration.

    Inputs:
      - endpoints: Primary upstream list (required at schema level).
      - strategy / max_concurrent / backup / health.

    Outputs:
      - UpstreamsConfig model for FoghornConfig.upstreams.
    """

    endpoints: list[UpstreamEndpoint] = Field(
        description="Primary upstream endpoints (host, DoH, or URL form)."
    )
    strategy: Literal["failover", "round_robin", "random"] = Field(
        default="failover",
        description="Upstream selection strategy.",
    )
    max_concurrent: int = Field(
        default=1,
        ge=1,
        description="Maximum concurrent upstream queries for a client request.",
    )
    backup: UpstreamsBackup | None = None
    health: UpstreamsHealth | None = None
