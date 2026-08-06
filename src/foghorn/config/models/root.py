"""Root Foghorn configuration model.

Inputs:
  - Top-level config.yaml mapping keys.

Outputs:
  - FoghornConfig Pydantic model used as the JSON Schema source of truth.
"""

from __future__ import annotations

from pydantic import ConfigDict, Field

from foghorn.config.models.common import StrictModel
from foghorn.config.models.logging_section import LoggingConfig
from foghorn.config.models.plugins import PluginInstance
from foghorn.config.models.server import ServerConfig
from foghorn.config.models.stats import StatsConfig
from foghorn.config.models.upstreams import UpstreamsConfig
from foghorn.config.models.vars_section import VARS_DESCRIPTION, VarsConfig


class FoghornConfig(StrictModel):
    """Brief: Root configuration document for Foghorn.

    Inputs:
      - server: Required server block.
      - vars / upstreams / logging / stats / plugins: Optional top-level sections.
      - $schema: Optional schema URI for editor tooling.

    Outputs:
      - FoghornConfig instance; primary input to model_json_schema().

    Example:
      >>> FoghornConfig(server={})  # doctest: +SKIP
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_uri: str | None = Field(
        default=None,
        alias="$schema",
        description=(
            "Optional URI or identifier for the JSON Schema associated with "
            "this configuration file."
        ),
    )
    vars: VarsConfig | None = Field(default=None, description=VARS_DESCRIPTION)
    server: ServerConfig = Field(description="Core server configuration block.")
    upstreams: UpstreamsConfig | None = Field(
        default=None,
        description="Upstream resolvers (required in forward mode).",
    )
    logging: LoggingConfig | None = None
    stats: StatsConfig | None = None
    plugins: list[PluginInstance] | None = Field(
        default=None,
        description="Ordered list of resolve plugin instances.",
    )
