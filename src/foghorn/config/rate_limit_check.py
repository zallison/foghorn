"""Rate limit plugin configuration checker.

Brief:
  This module provides configuration validation to warn operators when exposed
  listeners lack rate limiting protection. It detects deployments that bind
  to non-loopback addresses without a rate_limit plugin configured for
  pre_resolve hooks.

Inputs:
  - List of loaded plugins
  - Parsed configuration mapping

Outputs:
  - Logs warning with recommended configuration if both conditions are true
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from ..plugins.resolve.base import BasePlugin


def check_rate_limit_plugin_config(
    plugins: List[BasePlugin],
    cfg: Dict[str, Any],
) -> None:
    """Brief: Warn if exposed listeners lack rate limiting plugin.

    Inputs:
      - plugins: List of loaded plugin instances.
      - cfg: Parsed configuration mapping.

    Outputs:
      - None (logs warning if conditions are met).

    Notes:
      - Checks if any listener (udp/tcp/dot/doh) is bound to a non-loopback address.
      - Checks if a rate_limit plugin is configured as pre_resolve.
      - Logs a warning with recommended configuration if both conditions are true.
    """
    logger = logging.getLogger("foghorn.config.plugins")

    # Check for rate limiting plugins
    has_rate_limit = False
    rate_plugin_aliases = {"rate", "rate_limit", "ratelimit"}
    for p in plugins:
        name = getattr(p, "name", "").lower()
        plugin_type = getattr(p, "__class__", None)
        if plugin_type:
            class_name = plugin_type.__name__.lower()
        else:
            class_name = ""

        if (
            name in rate_plugin_aliases
            or "rate" in class_name
            or "ratelimit" in class_name
        ):
            # Check if it's enabled (not explicitly disabled)
            if getattr(p, "enabled", True):
                has_rate_limit = True
                break

    if has_rate_limit:
        return

    # Check if any listener is exposed (not bound to 127.0.0.1 or ::1)
    server_cfg = cfg.get("server")
    if not isinstance(server_cfg, dict):
        return

    listen_cfg = server_cfg.get("listen") or {}
    if not isinstance(listen_cfg, dict):
        return

    exposed = False
    default_host = listen_cfg.get("host") or "127.0.0.1"

    # Helper to check if a host is exposed
    def _is_exposed(host: str | None) -> bool:
        if not host:
            return False
        h = str(host).strip()
        return h not in {"127.0.0.1", "::1", "localhost"}

    # Check default host first
    if _is_exposed(default_host):
        exposed = True

    # Check per-listener overrides
    if not exposed:
        for listener_type in ["udp", "tcp", "dot", "doh"]:
            listener_cfg = listen_cfg.get(listener_type) or {}
            if isinstance(listener_cfg, dict):
                host = listener_cfg.get("host") or default_host
                if _is_exposed(host):
                    exposed = True
                    break

    if exposed:
        logger.warning(
            "No rate limiting plugin (rate/rate_limit) configured with non-loopback listeners. "
            "For exposed deployments, consider adding a rate limit plugin for DoS protection. "
            "Recommended minimal configuration:\n"
            "  plugins:\n"
            "    - type: rate\n"
            "      id: rate_limit\n"
            "      hooks:\n"
            "        pre_resolve: 10\n"
            "This uses sensible defaults: 50 RPS minimum, 5000 RPS global max, "
            "learning-based enforcement with 3x burst factor, and PSL-aware base domain keys. "
            "Rate-limited queries return REFUSED by default (configurable to NXDOMAIN, SERVFAIL, etc)."
        )
