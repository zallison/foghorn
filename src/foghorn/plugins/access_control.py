from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from .base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

logger = logging.getLogger(__name__)


@plugin_aliases("acl", "access_control")
class AccessControlPlugin(BasePlugin):
    """
    A plugin that provides access control based on client IP addresses.

    Example use:
        In config.yaml:
        plugins:
          - module: foghorn.plugins.access_control.AccessControlPlugin
            config:
              default: deny
              allow:
                - 192.168.1.0/24
    """

    def setup(self, **config):
        """
        Initializes the AccessControlPlugin.

        Args:
            **config: Configuration for the plugin.

        Example use:
            >>> from foghorn.plugins.access_control import AccessControlPlugin
            >>> config = {"default": "deny", "allow": ["192.168.1.0/24"]}
            >>> plugin = AccessControlPlugin(**config)
            >>> plugin.default
            'deny'
        """

        self.default = (self.config.get("default", "allow")).lower()
        self.allow_nets = [
            ipaddress.ip_network(n, strict=False) for n in self.config.get("allow", [])
        ]
        self.deny_nets = [
            ipaddress.ip_network(n, strict=False) for n in self.config.get("deny", [])
        ]

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Checks if the client's IP is in the allow or deny lists.
        Args:
            qname: The queried domain name.
            qtype: The query type.
            req: The raw DNS request.
            ctx: The plugin context.
        Returns:
            A PluginDecision to allow or deny the request.

        Example use:
            >>> from foghorn.plugins.access_control import AccessControlPlugin
            >>> from foghorn.plugins.base import PluginContext
            >>> config = {"default": "allow", "deny": ["192.168.1.10"]}
            >>> plugin = AccessControlPlugin(**config)
            >>> ctx = PluginContext(client_ip="192.168.1.10")
            >>> decision = plugin.pre_resolve("example.com", 1, b'', ctx)
            >>> decision.action
            'deny'
        """
        if not self.targets(ctx):
            return None

        ip = ipaddress.ip_address(ctx.client_ip)
        # Deny takes precedence
        for n in self.deny_nets:
            if ip in n:
                logger.warning(
                    "Access denied for %s (deny rule: %s)", ctx.client_ip, str(n)
                )
                return PluginDecision(action="deny")
        for n in self.allow_nets:
            if ip in n:
                logger.debug(
                    "Access allowed for %s (allow rule: %s)", ctx.client_ip, str(n)
                )
                return None

        logger.debug("Access %s for %s (default policy)", self.default, ctx.client_ip)
        return PluginDecision(action=self.default)
