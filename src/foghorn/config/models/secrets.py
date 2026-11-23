"""Secrets backend configuration models for Foghorn.

Inputs:
  - Top-level secrets block (backends list or single-module shorthand).

Outputs:
  - SecretsConfig model for FoghornConfig.secrets / schema generation.
"""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field

from foghorn.config.models.common import StrictModel


class SecretsBackendInstance(StrictModel):
    """Brief: One secrets backend under secrets.backends[].

    Inputs:
      - id / name: Logical backend instance id.
      - module: Backend alias (file, mysql, ...) or dotted import path.
      - config: Backend-specific mapping.
      - abort_on_failure: When true (default), init/probe failures abort startup.

    Outputs:
      - SecretsBackendInstance model.
    """

    id: str | None = Field(
        default=None,
        description="Logical backend identifier used in secret refs.",
    )
    name: str | None = Field(
        default=None,
        description="Optional alias for id (logging.backends-compatible).",
    )
    module: str = Field(
        description=(
            "Secrets backend alias or dotted import path "
            "(for example 'file', 'mysql', 'mariadb')."
        ),
    )
    config: dict[str, Any] | None = Field(
        default=None,
        description="Backend-specific configuration mapping.",
    )
    abort_on_failure: bool | None = Field(
        default=True,
        description="When true, backend init/probe failure aborts startup.",
    )
    abort_on_fail: bool | None = Field(
        default=None,
        description="Alias for abort_on_failure.",
    )
    enabled: bool | None = Field(
        default=True,
        description="When false, skip loading this backend.",
    )

    model_config = ConfigDict(extra="forbid")


class SecretsConfig(StrictModel):
    """Brief: Top-level secrets configuration.

    Inputs:
      - backends: Preferred multi-backend list.
      - module/config: Optional single-backend shorthand.
      - id/name: Optional id for single-backend shorthand.

    Outputs:
      - SecretsConfig model for FoghornConfig.secrets.
    """

    backends: list[SecretsBackendInstance] | None = Field(
        default=None,
        description="Named secrets backends (file, mysql, ...).",
    )
    # Single-backend shorthand (mirrors server.cache shape).
    module: str | None = Field(
        default=None,
        description="Single-backend module alias when backends is omitted.",
    )
    config: dict[str, Any] | None = Field(
        default=None,
        description="Single-backend config when backends is omitted.",
    )
    id: str | None = Field(
        default=None,
        description="Optional id for single-backend shorthand.",
    )
    name: str | None = Field(
        default=None,
        description="Optional name alias for single-backend shorthand.",
    )
    abort_on_failure: bool | None = Field(
        default=True,
        description="Default abort policy for single-backend shorthand.",
    )

    model_config = ConfigDict(extra="forbid")
