from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple, ClassVar, Sequence, List, Dict, Union, final
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

    @final
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

    Plugins can control execution order using:
      - pre_priority (for pre_resolve hooks; lower runs first)
      - post_priority (for post_resolve hooks; lower runs first)
      - setup_priority (for setup() hooks; lower runs first)

    Inputs:
      - **config: Plugin configuration including optional
        pre_priority, post_priority, and setup_priority. Plugins may also
        use an `abort_on_failure` boolean in their config to control
        whether setup() failures abort startup (default True).

    Outputs:
      - Initialized plugin instance with priority attributes.

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
    setup_priority: ClassVar[int] = 50

    aliases: ClassVar[Sequence[str]] = ()

    @classmethod
    def get_aliases(cls) -> Sequence[str]:
        # Always returns a sequence (even if empty) for discovery
        return tuple(getattr(cls, "aliases", ()))

    @final
    def __init__(self, **config):
        """
        Initializes the BasePlugin.

        Inputs:
          - **config: Plugin configuration including:
            - pre_priority (int): Priority for pre_resolve (1-255, default from class).
            - post_priority (int): Priority for post_resolve (1-255, default from class).
            - setup_priority (int): Priority for setup() (1-255, default from class).
              If setup_priority is not provided, pre_priority from config is used as a
              fallback for setup plugins.

        Outputs:
          - None (sets self.config, self.pre_priority, self.post_priority,
            self.setup_priority).

        Priority values are clamped to [1, 255]. Invalid types use class
        defaults.

        Example use:
            >>> from foghorn.plugins.base import BasePlugin
            >>> plugin = BasePlugin(pre_priority=10, post_priority=200)
            >>> plugin.pre_priority
            10
        """
        self.config = config
        logger = logging.getLogger(__name__)
        logger.info(f"loading {self}")
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
        # Setup priority: prefer explicit setup_priority, then pre_priority from
        # config as a fallback, then class default.
        raw_setup = config.get(
            "setup_priority",
            config.get("pre_priority", getattr(self.__class__, "setup_priority", 50)),
        )
        self.setup_priority = self._parse_priority_value(
            raw_setup,
            "setup_priority",
            logger,
        )

    @staticmethod
    def _parse_priority_value(value, key: str, logger) -> int:
        """
        Parse and clamp a priority value to [1, 255].

        Inputs:
          - value: Priority value (int, str, or other).
          - key: Config key name for logging.
          - logger: Logger instance.

        Outputs:
          - int: Clamped priority in range [1, 255].

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

    def handle_sigusr2(self) -> None:
        """
        Handle SIGUSR2 signal.

        Inputs:
          - None
        Outputs:
          - None

        Brief: Default implementation does nothing; plugins may override to
        perform maintenance or resets when SIGUSR2 is received.

        Example:
            >>> class P(BasePlugin):
            ...     def handle_sigusr2(self):
            ...         self.touched = True
            >>> p = P()
            >>> p.handle_sigusr2()
        """
        return None

    def setup(self) -> None:
        """
        Run one-time initialization logic for setup-aware plugins.

        Inputs:
          - None (uses plugin configuration and instance attributes).
        Outputs:
          - None

        Brief: Base implementation is a no-op; plugins that participate in the
        setup phase should override this method. The main process will invoke
        setup() on such plugins in ascending setup_priority order before
        starting listeners.

        Example:
            >>> from foghorn.plugins.base import BasePlugin
            >>> class P(BasePlugin):
            ...     def setup(self):
            ...         self.ready = True
            >>> p = P()
            >>> hasattr(p, 'ready')
            False
            >>> p.setup()
            >>> p.ready
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
