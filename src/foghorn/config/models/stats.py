"""Statistics configuration models for Foghorn.

Inputs:
  - Top-level stats block.

Outputs:
  - StatsConfig model for schema generation.
"""

from __future__ import annotations

from pydantic import ConfigDict, Field

from foghorn.config.models.common import StrictModel


class StatsConfig(StrictModel):
    """Brief: Runtime statistics collection configuration.

    Inputs:
      - enabled: Master on/off switch.
      - source_backend: Primary backend id for reads.
      - max_unique_* / max_store_*: Cardinality caps.

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

    model_config = ConfigDict(extra="allow")
