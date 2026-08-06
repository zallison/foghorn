"""Plugin instance shell models for Foghorn configuration.

Inputs:
  - plugins[] entries from config.yaml.

Outputs:
  - PluginInstance model and list typing for the root schema.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from foghorn.config.models.common import OpenModel, StrictModel


class PluginHooksConfig(OpenModel):
    """Brief: Per-hook enablement and priorities for a plugin instance.

    Inputs:
      - priority / pre_resolve / post_resolve / setup and related knobs.

    Outputs:
      - Permissive hooks object (strict key checks remain in config_schema.py).
    """

    priority: int | None = None
    pre_resolve: Any | None = None
    post_resolve: Any | None = None
    setup: Any | None = None


class PluginSetupConfig(OpenModel):
    """Brief: Setup-phase behaviour for a plugin instance.

    Inputs:
      - enabled / priority / abort_on_failure and related keys.

    Outputs:
      - Permissive setup object.
    """


class PluginLoggingConfig(OpenModel):
    """Brief: Per-plugin logging overrides.

    Inputs:
      - Arbitrary logging override mapping.

    Outputs:
      - Permissive logging object.
    """


class PluginInstance(StrictModel):
    """Brief: One entry in the top-level plugins array.

    Inputs:
      - type: Plugin type/alias (required).
      - enabled: When false, plugin is not loaded.
      - logging / setup / hooks: Optional control blocks.
      - config: Plugin-specific configuration mapping.
      - id / comment: Optional metadata (from MetaFields).

    Outputs:
      - PluginInstance model used for JSON Schema $defs.PluginInstance.
    """

    type: str = Field(description="Plugin type/alias.")
    enabled: bool = Field(
        default=True, description="When false, skip loading this plugin."
    )
    logging: PluginLoggingConfig | None = Field(
        default=None,
        description="Per-plugin logging overrides.",
    )
    setup: PluginSetupConfig | None = Field(
        default=None,
        description="Setup-phase behaviour (enabled/priority/abort_on_failure).",
    )
    hooks: PluginHooksConfig | None = Field(
        default=None,
        description="Per-hook enablement/priorities (pre_resolve/post_resolve).",
    )
    config: dict[str, Any] | None = Field(
        default=None,
        description="Plugin-specific configuration mapping.",
    )
