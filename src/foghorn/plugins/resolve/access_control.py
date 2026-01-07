from __future__ import annotations

import ipaddress
import logging
from typing import List, Optional

from pydantic import BaseModel, Field

from .base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

logger = logging.getLogger(__name__)


class AccessControlConfig(BaseModel):
    """Brief: Typed configuration model for AccessControl used for startup validation.

    Inputs:
      - default: Default policy ("allow" or "deny").
      - allow: List of CIDR/IP strings to allow.
      - deny: List of CIDR/IP strings to deny.

    Outputs:
      - AccessControlConfig instance with normalized types.
    """

    default: str = Field(default="allow")
    allow: List[str] = Field(default_factory=list)
    deny: List[str] = Field(default_factory=list)

    class Config:
        extra = "allow"


@plugin_aliases("acl", "access_control")
class AccessControl(BasePlugin):
    """
    A plugin that provides access control based on client IP addresses.

    Example use:
        In config.yaml:
        plugins:
          - module: foghorn.plugins.access_control.AccessControl
            config:
              default: deny
              allow:
                - 192.168.1.0/24
    """

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - AccessControlConfig class for use by the core config loader.
        """

        return AccessControlConfig

    def setup(self, **config):
        """
        Initializes the AccessControl.

        Args:
            **config: Configuration for the plugin.

        Example use:
            >>> from foghorn.plugins.access_control import AccessControl
            >>> config = {"default": "deny", "allow": ["192.168.1.0/24"]}
            >>> plugin = AccessControl(**config)
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
            >>> from foghorn.plugins.access_control import AccessControl
            >>> from foghorn.plugins.resolve.base import PluginContext
            >>> config = {"default": "allow", "deny": ["192.168.1.10"]}
            >>> plugin = AccessControl(**config)
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
