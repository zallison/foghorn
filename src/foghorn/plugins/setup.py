"""Plugin lifecycle helpers used during startup and reload.

Brief:
  Foghorn supports optional plugin setup hooks. Plugins that override
  ``BasePlugin.setup`` are treated as "setup-aware" and are executed in
  ascending ``setup_priority`` order.

Inputs:
  - list[BasePlugin]: plugin instances

Outputs:
  - None (may raise RuntimeError for aborting setup failures)

Notes:
  - This module exists so startup logic and config reload logic can share the
    same implementation without importing the main entrypoint.
"""

from __future__ import annotations

import logging
from typing import List

from .resolve.base import BasePlugin


def _is_setup_plugin(plugin: BasePlugin) -> bool:
    """Brief: Determine whether a plugin overrides BasePlugin.setup.

    Inputs:
      - plugin: BasePlugin instance.

    Outputs:
      - bool: True when plugin defines its own setup() implementation.

    Example:
      >>> from foghorn.plugins.resolve.base import BasePlugin
      >>> class P(BasePlugin):
      ...     def setup(self):
      ...         pass
      >>> p = P()
      >>> _is_setup_plugin(p)
      True
    """

    try:
        return plugin.__class__.setup is not BasePlugin.setup
    except Exception:
        return False


def run_setup_plugins(plugins: List[BasePlugin]) -> None:
    """Brief: Run setup() on setup-aware plugins in ascending setup_priority order.

    Inputs:
      - plugins: List[BasePlugin] instances, typically from load_plugins().

    Outputs:
      - None; raises RuntimeError if a setup plugin with abort_on_failure=True fails.

    Notes:
      - Plugins that override BasePlugin.setup are considered setup plugins.
      - Execution order is controlled by each plugin's setup_priority attribute
        (default 100).

    Example:
      >>> # Typically called by foghorn.main after load_plugins().
      >>> run_setup_plugins([])
    """

    logger = logging.getLogger("foghorn.main.setup")

    setup_entries: List[tuple[int, BasePlugin]] = []
    for p in plugins or []:
        if not _is_setup_plugin(p):
            continue
        try:
            prio = int(getattr(p, "setup_priority", 100))
        except Exception:
            prio = 100
        setup_entries.append((prio, p))

    setup_entries.sort(key=lambda item: item[0])

    for prio, plugin in setup_entries:
        cfg = getattr(plugin, "config", {}) or {}
        abort_on_failure = bool(cfg.get("abort_on_failure", True))
        name = plugin.__class__.__name__
        logger.info(
            "Running setup for plugin %s (setup_priority=%d, abort_on_failure=%s)",
            name,
            prio,
            abort_on_failure,
        )
        try:
            plugin.setup()
        except Exception as e:  # pragma: no cover
            logger.error("Setup for plugin %s failed: %s", name, e, exc_info=True)
            if abort_on_failure:
                raise RuntimeError(f"Setup for plugin {name} failed") from e
            logger.warning(
                "Continuing startup despite setup failure in plugin %s because abort_on_failure is False",
                name,
            )
