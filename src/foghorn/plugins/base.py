from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple, ClassVar, Sequence, List, Dict, Union
import logging


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
    Context passed to plugins during pre- and post-resolve phases.

    Attributes (inputs to plugins):
      - client_ip: str of the requestor's IP address
      - upstream_candidates: Optional[list[dict]] overrides global upstreams when set;
        each item is {'host': str, 'port': int}. When provided, the server must use
        only these upstreams for this request and return SERVFAIL if all fail.
      - upstream_override: Optional[tuple] legacy single upstream override (host, port)

    Example use:
        >>> from foghorn.plugins.base import PluginContext
        >>> ctx = PluginContext(client_ip="192.0.2.1")
        >>> ctx.client_ip
        '192.0.2.1'
        >>> ctx.upstream_candidates = [{'host': '10.0.0.1', 'port': 53}]
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
        # Optional per-request upstream candidates override
        self.upstream_candidates: Optional[List[Dict[str, Union[str, int]]]] = None
        # Optional per-request upstream override (host, port) - legacy
        self.upstream_override: Optional[Tuple[str, int]] = None


class BasePlugin:
    """
    Base class for all plugins.

    Plugins can control execution order using pre_priority (for pre_resolve hooks)
    and post_priority (for post_resolve hooks). Lower values run first.

    Inputs:
      - **config: Plugin configuration including optional pre_priority, post_priority,
                  or legacy priority keys

    Outputs:
      - Initialized plugin instance with priority attributes

    Example use:
        >>> from foghorn.plugins.base import BasePlugin
        >>> class MyPlugin(BasePlugin):
        ...     pre_priority = 10
        ...     def pre_resolve(self, qname, qtype, req, ctx):
        ...         return None
        >>> plugin = MyPlugin(pre_priority=25)
        >>> plugin.pre_priority
        25
    """

    pre_priority: ClassVar[int] = 50
    post_priority: ClassVar[int] = 50

    aliases: ClassVar[Sequence[str]] = ()

    @classmethod
    def get_aliases(cls) -> Sequence[str]:
        # Always returns a sequence (even if empty) for discovery
        return tuple(getattr(cls, "aliases", ()))

    def __init__(self, **config):
        """
        Initializes the BasePlugin.

        Inputs:
          - **config: Plugin configuration including:
            - pre_priority (int): Priority for pre_resolve (1-255, default from class)
            - post_priority (int): Priority for post_resolve (1-255, default from class)
            - priority (int): Legacy; sets both pre/post if neither specified

        Outputs:
          - None (sets self.config, self.pre_priority, self.post_priority)

        Priority values are clamped to [1, 255]. Invalid types use class defaults.

        Example use:
            >>> from foghorn.plugins.base import BasePlugin
            >>> plugin = BasePlugin(pre_priority=10, post_priority=200)
            >>> plugin.pre_priority
            10
            >>> plugin2 = BasePlugin(priority=15)
            >>> plugin2.pre_priority == plugin2.post_priority == 15
            True
        """
        self.config = config
        logger = logging.getLogger(__name__)

        # Determine if specific pre/post priorities were provided
        has_pre = "pre_priority" in config
        has_post = "post_priority" in config
        has_legacy = "priority" in config

        # Handle legacy priority
        if has_legacy and not has_pre and not has_post:
            legacy_val = self._parse_priority_value(
                config["priority"], "priority", logger
            )
            self.pre_priority = legacy_val
            self.post_priority = legacy_val
        elif has_legacy:
            logger.warning(
                "legacy 'priority' ignored because 'pre_priority'/'post_priority' explicitly set"
            )
            self.pre_priority = self._parse_priority_value(
                config.get("pre_priority", self.__class__.pre_priority),
                "pre_priority",
                logger,
            )
            self.post_priority = self._parse_priority_value(
                config.get("post_priority", self.__class__.post_priority),
                "post_priority",
                logger,
            )
        else:
            # Standard path: use class defaults or config overrides
            self.pre_priority = self._parse_priority_value(
                config.get("pre_priority", self.__class__.pre_priority),
                "pre_priority",
                logger,
            )
            self.post_priority = self._parse_priority_value(
                config.get("post_priority", self.__class__.post_priority),
                "post_priority",
                logger,
            )

    @staticmethod
    def _parse_priority_value(value, key: str, logger) -> int:
        """
        Parse and clamp a priority value to [1, 255].

        Inputs:
          - value: Priority value (int, str, or other)
          - key: Config key name for logging
          - logger: Logger instance

        Outputs:
          - int: Clamped priority in range [1, 255]

        Example:
            >>> BasePlugin._parse_priority_value("25", "pre_priority", logging.getLogger())
            25
            >>> BasePlugin._parse_priority_value(300, "post_priority", logging.getLogger())
            255
        """
        default = 50
        try:
            val = int(value)
        except (ValueError, TypeError):
            logger.warning("Invalid %s %r; using default %d", key, value, default)
            return default

        if val < 1:
            logger.warning("%s below 1; clamping to 1", key)
            return 1
        if val > 255:
            logger.warning("%s above 255; clamping to 255", key)
            return 255
        return val

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        A hook that runs before the DNS query is resolved.
        Args:
            qname: The queried domain name.
            qtype: The query type.
            req: The raw DNS request.
            ctx: The plugin context.
        Returns:
            A PluginDecision, or None to allow the query to proceed.

        Example use:
            >>> from foghorn.plugins.base import BasePlugin, PluginDecision, PluginContext
            >>> plugin = BasePlugin()
            >>> ctx = PluginContext('127.0.0.1')
            >>> plugin.pre_resolve("example.com", 1, b'', ctx) is None
            True
        """
        return None

    def post_resolve(
        self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
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
            >>> from foghorn.plugins.base import BasePlugin, PluginDecision, PluginContext
            >>> plugin = BasePlugin()
            >>> ctx = PluginContext('127.0.0.1')
            >>> plugin.post_resolve("example.com", 1, b"response", ctx) is None
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
