from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple, ClassVar, Sequence

@dataclass
class PluginDecision:
    """
    Represents a decision made by a plugin.

    Example use:
        >>> from foghorn.plugins.base import PluginDecision
        >>> decision = PluginDecision(action="deny")
        >>> decision.action
        'deny'
    """
    action: str  # "allow", "deny", or "override"
    response: Optional[bytes] = None

class PluginContext:
    """
    Holds contextual information for a DNS query, passed through the plugin chain.

    Example use:
        >>> from foghorn.plugins.base import PluginContext
        >>> ctx = PluginContext(client_ip="192.0.2.1")
        >>> ctx.client_ip
        '192.0.2.1'
    """
    def __init__(self, client_ip: str) -> None:
        """
        Initializes the PluginContext.

        Args:
            client_ip: The IP address of the client that sent the query.

        Example use:
            >>> from foghorn.plugins.base import PluginContext
            >>> ctx = PluginContext(client_ip="192.0.2.1")
            >>> ctx.client_ip
            '192.0.2.1'
        """
        self.client_ip = client_ip
        # Optional per-request upstream override (host, port)
        self.upstream_override: Optional[Tuple[str, int]] = None

class BasePlugin:
    """
    Base class for all plugins.

    Example use:
        >>> from foghorn.plugins.base import BasePlugin
        >>> class MyPlugin(BasePlugin):
        ...     def pre_resolve(self, qname, qtype, ctx):
        ...         return None
        >>> plugin = MyPlugin(config={})
        >>> plugin.pre_resolve("example.com", 1, None) is None
        True
    """
    aliases: ClassVar[Sequence[str]] = ()

    @classmethod
    def get_aliases(cls) -> Sequence[str]:
        # Always returns a sequence (even if empty) for discovery
        return tuple(getattr(cls, "aliases", ()))

    def __init__(self, **config):
        """
        Initializes the BasePlugin.

        Args:
            **config: Plugin-specific configuration.

        Example use:
            >>> from foghorn.plugins.base import BasePlugin
            >>> plugin = BasePlugin(my_config="value")
            >>> plugin.config["my_config"]
            'value'
        """
        self.config = config

    def pre_resolve(self, qname: str, qtype: int, ctx: PluginContext) -> Optional[PluginDecision]:
        """
        A hook that runs before the DNS query is resolved.
        Args:
            qname: The queried domain name.
            qtype: The query type.
            ctx: The plugin context.
        Returns:
            A PluginDecision, or None to allow the query to proceed.

        Example use:
            >>> from foghorn.plugins.base import BasePlugin, PluginDecision
            >>> plugin = BasePlugin()
            >>> plugin.pre_resolve("example.com", 1, None) is None
            True
        """
        return None

    def post_resolve(self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext) -> Optional[PluginDecision]:
        """
        A hook that runs after the DNS query has been resolved.
        Args:
            qname: The queried domain name.
            qtype: The query type.
            response_wire: The response from the upstream server.
            ctx: The plugin context.
        Returns:
            A PluginDecision, or None to allow the response to be sent as-is.

        Example use:
            >>> from foghorn.plugins.base import BasePlugin, PluginDecision
            >>> plugin = BasePlugin()
            >>> plugin.post_resolve("example.com", 1, b"response", None) is None
            True
        """
        return None


def plugin_aliases(*aliases: str):
    """
    Decorator to set aliases on a plugin class.
    Usage:
        @plugin_aliases("acl", "access")
        class AccessControlPlugin(BasePlugin):
            ...
    """
    def _wrap(cls):
        cls.aliases = tuple(aliases)
        return cls
    return _wrap
