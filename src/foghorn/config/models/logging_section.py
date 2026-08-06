"""Logging and query-log backend models for Foghorn configuration.

Inputs:
  - Top-level logging block (python, backends, query_log policies).

Outputs:
  - LoggingConfig model for schema generation.

Notes:
  - Phase 0 captures the main keys used by schema tests; nested detail expands
    in Phase 1.
"""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field

from foghorn.config.models.common import StrictModel


class PythonLoggingConfig(StrictModel):
    """Brief: Python stdlib logging settings under logging.python.

    Inputs:
      - file / level / stderr / color / syslog.

    Outputs:
      - PythonLoggingConfig model.
    """

    file: str | None = Field(default=None, description="Optional log file path.")
    level: str | None = Field(
        default=None,
        description="Log level (debug, info, warn/warning, error, crit/critical).",
    )
    stderr: bool | None = Field(default=None, description="Log to stderr when true.")
    color: bool = Field(
        default=True,
        description=(
            "Enable ANSI colorized stderr logging output for improved "
            "readability of levels and important tokens."
        ),
    )
    syslog: bool | dict[str, Any] | None = Field(
        default=None,
        description="Syslog toggle or syslog configuration object.",
    )

    model_config = ConfigDict(extra="allow")


class LoggingBackendConfig(StrictModel):
    """Brief: One statistics/query-log backend entry under logging.backends.

    Inputs:
      - id: Logical backend id (optional).
      - backend: Backend alias or import path (required).
      - config: Backend-specific mapping.

    Outputs:
      - LoggingBackendConfig model.
    """

    id: str | None = Field(
        default=None,
        description=(
            "Logical backend identifier used by stats.source_backend and "
            "related selectors."
        ),
    )
    backend: str = Field(
        description=(
            "Backend identifier or dotted import path "
            "(for example 'sqlite', 'mysql', 'mqtt_logging')."
        ),
    )
    config: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Backend-specific configuration mapping passed verbatim to the "
            "selected BaseStatsStore implementation."
        ),
    )

    # id is also a MetaFields attribute; redeclare backend-required shape.
    model_config = ConfigDict(extra="forbid")


class QueryLogRetentionConfig(StrictModel):
    """Brief: Retention policy for query-log backends.

    Inputs:
      - max_records / days / max_bytes / prune_* knobs.

    Outputs:
      - QueryLogRetentionConfig model.
    """

    max_records: int | None = Field(default=None, ge=1)
    days: float | None = Field(default=None, gt=0)
    max_bytes: int | None = Field(default=None, ge=1)
    prune_interval_seconds: float | None = Field(default=None, gt=0)
    prune_every_n_inserts: int | None = Field(default=None, ge=1)


class QueryLogSamplingConfig(StrictModel):
    """Brief: Sampling policy before persistent query_log writes.

    Inputs:
      - enabled / sample_rate / rate.

    Outputs:
      - QueryLogSamplingConfig model.
    """

    enabled: bool = Field(default=True)
    sample_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    rate: float | None = Field(default=None, ge=0.0, le=1.0)


class QueryLogDedupeConfig(StrictModel):
    """Brief: Dedupe policy before persistent query_log writes.

    Inputs:
      - window_seconds / max_entries.

    Outputs:
      - QueryLogDedupeConfig model.
    """

    window_seconds: float = Field(default=0.0, ge=0.0)
    max_entries: int = Field(default=50000, ge=1)


class LoggingConfig(StrictModel):
    """Brief: Top-level logging configuration.

    Inputs:
      - python: Stdlib logging block.
      - async / max_logging_queue / query_log_* policies.
      - backends: Stats/query-log backend list.

    Outputs:
      - LoggingConfig model for FoghornConfig.logging.
    """

    python: PythonLoggingConfig | None = Field(
        default=None,
        description="Python logging configuration (file/level/stderr/syslog).",
    )
    async_logging: bool | None = Field(
        default=True,
        alias="async",
        description=(
            "When true, statistics/query-log backends default to using an "
            "async worker queue for high-volume writes."
        ),
    )
    max_logging_queue: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Optional global default for backend async queue capacity. "
            "Values <= 0 use an unbounded queue."
        ),
    )
    query_log_only: bool = Field(
        default=False,
        description=(
            "When true, only the raw query_log is written to configured "
            "backends and aggregate counters stay in-memory only."
        ),
    )
    query_log_retention: QueryLogRetentionConfig | None = None
    query_log_retention_max_records: int | None = Field(default=None, ge=1)
    query_log_retention_days: float | None = Field(default=None, gt=0)
    query_log_retention_max_bytes: int | None = Field(default=None, ge=1)
    query_log_retention_prune_interval_seconds: float | None = Field(default=None, gt=0)
    query_log_retention_prune_every_n_inserts: int | None = Field(default=None, ge=1)
    query_log_sampling: QueryLogSamplingConfig | None = None
    query_log_sample_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    query_log_dedupe: QueryLogDedupeConfig | None = None
    query_log_dedupe_window_seconds: float | None = Field(default=None, ge=0.0)
    query_log_dedupe_max_entries: int | None = Field(default=None, ge=1)
    backends: list[LoggingBackendConfig] | None = Field(
        default=None,
        description="Statistics/query-log backend list.",
    )

    model_config = ConfigDict(extra="forbid", populate_by_name=True)
