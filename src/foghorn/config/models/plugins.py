"""Plugin instance shell models for Foghorn configuration.

Inputs:
  - plugins[] entries from config.yaml.

Outputs:
  - PluginInstance model and list typing for the root schema.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from foghorn.config.models.common import StrictModel


class PluginHookNode(StrictModel):
    """Brief: Mapping form of a single plugin hook priority.

    Inputs:
      - priority: Optional integer priority for this hook.

    Outputs:
      - Object accepted as hooks.pre_resolve / post_resolve / setup.
    """

    priority: int | None = None


class PluginHooksConfig(StrictModel):
    """Brief: Per-hook enablement and priorities for a plugin instance.

    Inputs:
      - priority: Shorthand integer applied to setup/pre_resolve/post_resolve.
      - setup / pre_resolve / post_resolve: Integer priority or {priority: int}.

    Outputs:
      - Hooks object with known keys only.
    """

    priority: int | None = None
    pre_resolve: int | PluginHookNode | None = None
    post_resolve: int | PluginHookNode | None = None
    setup: int | PluginHookNode | None = None


class PluginSetupConfig(StrictModel):
    """Brief: Setup-phase behaviour for a plugin instance.

    Inputs:
      - enabled / priority / abort_on_failure (and abort_on_fail alias).

    Outputs:
      - Setup object with known keys only.
    """

    enabled: bool | None = None
    priority: int | None = None
    abort_on_failure: bool | None = None
    abort_on_fail: bool | None = None


class PluginLoggingConfig(StrictModel):
    """Brief: Per-plugin logging overrides.

    Inputs:
      - level / logger name style overrides used by plugin loaders.

    Outputs:
      - Logging object with known keys only.
    """

    level: str | None = None
    logger: str | None = None
    name: str | None = None


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
