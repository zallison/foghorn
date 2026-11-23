"""Statistics configuration models for Foghorn.

Inputs:
  - Top-level stats block.

Outputs:
  - StatsConfig model for schema generation.
"""

from __future__ import annotations

from pydantic import ConfigDict, Field

from foghorn.config.models.common import SecondsFloat, StrictModel


class StatsIgnoreConfig(StrictModel):
    """Brief: Optional ignore lists for top-N stats views.

    Inputs:
      - top_* lists and match modes used by the stats reporter/UI.

    Outputs:
      - StatsIgnoreConfig model nested under stats.ignore.
    """

    top_clients: list[str] = Field(default_factory=list)
    top_domains: list[str] = Field(default_factory=list)
    top_subdomains: list[str] = Field(default_factory=list)
    top_domains_mode: str = Field(default="exact")
    top_subdomains_mode: str = Field(default="exact")
    ignore_single_host: bool = Field(default=False)
    include_in_stats: bool = Field(
        default=True,
        description=(
            "When true, ignored top-N entries still count toward aggregate "
            "stats; when false they are excluded from aggregates too."
        ),
    )


class StatsConfig(StrictModel):
    """Brief: Runtime statistics collection configuration.

    Inputs:
      - enabled: Master on/off switch.
      - source_backend: Primary backend id for reads.
      - max_unique_* / max_store_*: Cardinality caps.
      - Reporter/UI toggles (interval, top-N, ignore lists).

    Outputs:
      - StatsConfig model for FoghornConfig.stats.
    """

    enabled: bool = Field(
        default=True,
        description="Master on/off switch for runtime statistics collection.",
    )
    source_backend: str | None = Field(
        default=None,
        description=(
            "Identifier of the primary statistics/query-log backend to read from. "
            "When logging.backends is configured, this typically matches one of "
            "the backends[].id values."
        ),
    )
    interval_seconds: SecondsFloat | None = Field(
        default=None,
        ge=0,
        description="Optional stats reporter interval override (seconds).",
    )
    reset_on_log: bool = Field(default=False)
    log_level: str = Field(
        default="info",
        description="Log level used by the periodic stats reporter.",
    )
    track_uniques: bool = Field(
        default=True,
        description="Track unique client IPs and domains in the in-memory collector.",
    )
    include_qtype_breakdown: bool = Field(default=True)
    include_top_clients: bool = Field(default=True)
    include_top_domains: bool = Field(default=True)
    top_n: int = Field(default=10, ge=0)
    track_latency: bool = Field(default=True)
    force_rebuild: bool = Field(default=False)
    sigusr1_resets_stats: bool = Field(
        default=False,
        description="When true, SIGUSR1 resets the in-memory statistics collector.",
    )
    sigusr2_resets_stats: bool = Field(
        default=False,
        description="When true, SIGUSR2 resets the in-memory statistics collector.",
    )
    ignore: StatsIgnoreConfig | None = None
    max_unique_clients: int = Field(
        default=50000,
        ge=0,
        description=(
            "Maximum unique client IP values retained in memory when unique "
            "tracking is enabled."
        ),
    )
    max_unique_domains: int = Field(
        default=50000,
        ge=0,
        description=(
            "Maximum unique domain values retained in memory when unique "
            "tracking is enabled."
        ),
    )
    max_store_clients: int = Field(
        default=50000,
        ge=0,
        description=(
            "Maximum distinct client keys mirrored into the persistent stats "
            "store (0 disables the cap)."
        ),
    )
    max_store_domains: int = Field(
        default=50000,
        ge=0,
        description=(
            "Maximum distinct base-domain keys mirrored into the persistent "
            "stats store (0 disables the cap)."
        ),
    )
    max_store_subdomains: int = Field(
        default=50000,
        ge=0,
        description=(
            "Maximum distinct subdomain keys mirrored into the persistent "
            "stats store (0 disables the cap)."
        ),
    )
    max_store_qtype_qnames: int = Field(
        default=50000,
        ge=0,
        description=(
            "Maximum distinct qtype|qname keys mirrored into the persistent "
            "stats store (0 disables the cap)."
        ),
    )

    model_config = ConfigDict(extra="forbid")
