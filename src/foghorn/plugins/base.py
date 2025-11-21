from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import wraps
from typing import ClassVar, Dict, List, Optional, Sequence, Tuple, Union, final

from cachetools import TTLCache

logger = logging.getLogger(__name__)


@dataclass
class PluginDecision:
    """
    Brief: Represents a decision made by a plugin.

    Inputs:
      - action: str indicating the decision (e.g., "allow", "deny", "override").
      - response: Optional[bytes] DNS response to use when action == "override".

    Outputs:
      - PluginDecision instance with attributes populated.
    """

    action: str
    response: Optional[bytes] = None


def inheritable_ttl_cache(keyfunc=None):
    """Brief: Create an inheritable per-subclass TTL cache decorator for instance methods.

    Inputs:
      - keyfunc: Optional callable used to build the cache key. When provided it
        is called as ``keyfunc(self, *args, **kwargs)`` and must return a
        hashable object. When omitted, the key defaults to
        ``(args, tuple(sorted(kwargs.items())))``.

    Outputs:
      - Callable decorator that wraps an instance method so that each plugin
        subclass gets its own ``cachetools.TTLCache`` instance, using
        ``cache_ttl`` and ``cache_maxsize`` attributes on the subclass
        (defaults: 60 seconds, 128 entries).

    Example:
        >>> from foghorn.plugins.base import BasePlugin, inheritable_ttl_cache
        >>> class MyPlugin(BasePlugin):
        ...     cache_ttl = 120
        ...
        ...     @inheritable_ttl_cache(lambda self, qname, qtype, req, ctx: (qname, qtype))
        ...     def pre_resolve(self, qname, qtype, req, ctx):
        ...         return None
    """

    def decorator(method):
        caches: Dict[type, TTLCache] = {}

        @wraps(method)
        def wrapper(self, *args, **kwargs):
            cls = type(self)
            ttl = int(getattr(cls, "cache_ttl", 60))
            maxsize = int(getattr(cls, "cache_maxsize", 128))

            cache = caches.get(cls)
            if cache is None or cache.ttl != ttl or cache.maxsize != maxsize:
                cache = TTLCache(maxsize=maxsize, ttl=ttl)
                caches[cls] = cache

            if keyfunc is not None:
                key = keyfunc(self, *args, **kwargs)
            else:
                key = (args, tuple(sorted(kwargs.items())))

            try:
                return cache[key]
            except KeyError:
                result = method(self, *args, **kwargs)
                cache[key] = result
                return result

        # Expose caches for inspection/testing if needed
        wrapper._caches = caches  # type: ignore[attr-defined]
        return wrapper

    return decorator


class PluginContext:
    """Brief: Context passed to plugins during pre- and post-resolve phases.

    Inputs:
      - client_ip: str IP address of the requesting client.

    Attributes (inputs to plugins):
      - client_ip: Requestor's IP address.
      - upstream_candidates: Optional[list[dict]] overrides global upstreams when set;
        each item is {'host': str, 'port': int}. When provided, the server must use
        only these upstreams for this request and return SERVFAIL if all fail.
      - upstream_override: Optional[tuple[str, int]] legacy single upstream override.

    Outputs:
      - PluginContext instance with fields initialized.

    Example use:
        >>> from foghorn.plugins.base import PluginContext
        >>> ctx = PluginContext(client_ip="192.0.2.1")
        >>> ctx.client_ip
        '192.0.2.1'
        >>> ctx.upstream_candidates = [{'host': '10.0.0.1', 'port': 53}]
    """

    @final
    def __init__(self, client_ip: str) -> None:
        """Initialize the PluginContext.

        Inputs:
          - client_ip: The IP address of the client that sent the query.

        Outputs:
          - None (sets client_ip, upstream_candidates, upstream_override).
        """
        self.client_ip = client_ip
        # Optional per-request upstream candidates override
        self.upstream_candidates: Optional[List[Dict[str, Union[str, int]]]] = None
        # Optional per-request upstream override (host, port) - legacy
        self.upstream_override: Optional[Tuple[str, int]] = None


class BasePlugin:
    """Brief: Base class for all plugins.

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

    ttl: ClassVar[int] = 300

    pre_priority: ClassVar[int] = 50
    post_priority: ClassVar[int] = 50
    setup_priority: ClassVar[int] = 50
    aliases: ClassVar[Sequence[str]] = ()

    @classmethod
    def get_aliases(cls) -> Sequence[str]:
        """Brief: Return plugin aliases used for discovery.

        Inputs:
          - None

        Outputs:
          - tuple[str, ...]: Sequence of alias strings (may be empty).
        """
        return tuple(getattr(cls, "aliases", ()))

    @classmethod
    def cache(cls, keyfunc=None):
        """Brief: Convenience wrapper around :func:`inheritable_ttl_cache`.

        Inputs:
          - keyfunc: Optional callable used to build cache keys, passed through
            to :func:`inheritable_ttl_cache`.

        Outputs:
          - Callable decorator that applies an inheritable TTL cache to an
            instance method.

        Example:
            >>> from foghorn.plugins.base import BasePlugin
            >>> class MyPlugin(BasePlugin):
            ...     cache_ttl = 120
            ...
            ...     @BasePlugin.cache(lambda self, qname, qtype, req, ctx: (qname, qtype))
            ...     def pre_resolve(self, qname, qtype, req, ctx):
            ...         return None
        """
        return inheritable_ttl_cache(keyfunc)

    @final
    def __init__(self, **config: object) -> None:
        """Initialize the BasePlugin with configuration and priorities.

        Inputs:
          - **config: Plugin configuration including (optional):
            - pre_priority (int | str): Priority for pre_resolve (1-255, default from class).
            - post_priority (int | str): Priority for post_resolve (1-255, default from class).
            - setup_priority (int | str): Priority for setup() (1-255, default from class).
              If setup_priority is not provided, pre_priority from config is used as a
              fallback for setup plugins.

        Outputs:
          - None (sets self.config, self.pre_priority, self.post_priority, self.setup_priority).

        Priority values are clamped to [1, 255]. Invalid types use class defaults.

        Example use:
            >>> from foghorn.plugins.base import BasePlugin
            >>> plugin = BasePlugin(pre_priority=10, post_priority=200)
            >>> plugin.pre_priority
            10
        """
        self.config = config
        logger.debug("loading %s", self)

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
    def _parse_priority_value(value: object, key: str, logger: logging.Logger) -> int:
        """Brief: Parse and clamp a priority value to the inclusive range [1, 255].

        Inputs:
          - value: Priority value (int, str, or other).
          - key: Config key name for logging (e.g., "pre_priority").
          - logger: Logger instance for warnings.

        Outputs:
          - int: Clamped priority value in range [1, 255]; defaults to 50 on invalid input.

        Example:
            >>> BasePlugin._parse_priority_value("25", "pre_priority", logger)
            25
            >>> BasePlugin._parse_priority_value(300, "post_priority", logger)
            255
        """
        default = 50
        try:
            val = int(value)  # type: ignore[arg-type]
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

    @inheritable_ttl_cache(lambda self, qname, qtype, req, ctx: (qname, int(qtype)))
    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Hook that runs before the DNS query is resolved.

        Inputs:
          - qname: The queried domain name.
          - qtype: The query type.
          - req: The raw DNS request.
          - ctx: The plugin context.

        Outputs:
          - PluginDecision instance to modify/short-circuit handling, or None to allow
            the query to proceed unchanged (default).

        Example use:
            >>> from foghorn.plugins.base import BasePlugin, PluginContext
            >>> plugin = BasePlugin()
            >>> ctx = PluginContext('127.0.0.1')
            >>> plugin.pre_resolve("example.com", 1, b'', ctx) is None
            True
        """
        return None

    @inheritable_ttl_cache(
        lambda self, qname, qtype, response_wire, ctx: (
            qname,
            int(qtype),
            response_wire,
        )
    )
    def post_resolve(
        self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Hook that runs after the DNS query has been resolved.

        Inputs:
          - qname: The queried domain name.
          - qtype: The query type.
          - response_wire: DNS response from the upstream server.
          - ctx: The plugin context.

        Outputs:
          - PluginDecision instance to override/modify the response, or None to send
            the upstream response as-is (default).

        Example use:
            >>> from foghorn.plugins.base import BasePlugin, PluginContext
            >>> plugin = BasePlugin()
            >>> ctx = PluginContext('127.0.0.1')
            >>> plugin.post_resolve("example.com", 1, b"response", ctx) is None
            True
        """
        return None

    def handle_sigusr2(self) -> None:
        """Brief: Handle SIGUSR2 signal (default implementation is a no-op).

        Inputs:
          - None

        Outputs:
          - None (subclasses may override to perform maintenance or resets).

        Example:
            >>> class P(BasePlugin):
            ...     def handle_sigusr2(self):
            ...         self.touched = True
            >>> p = P()
            >>> p.handle_sigusr2()
        """
        return None

    def setup(self) -> None:
        """Brief: Run one-time initialization logic for setup-aware plugins.

        Inputs:
          - None (uses plugin configuration and instance attributes).

        Outputs:
          - None

        Notes:
          - Base implementation is a no-op; plugins that participate in the
            setup phase should override this method. The main process will
            invoke setup() on such plugins in ascending setup_priority order
            before starting listeners.

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
    """Brief: Decorator to set aliases on a plugin class for registry discovery.

    Inputs:
      - *aliases: Variable number of alias strings for the plugin.

    Outputs:
      - Callable that applies the aliases to a plugin class and returns it.

    Example:
        >>> from foghorn.plugins.base import BasePlugin, plugin_aliases
        >>> @plugin_aliases("acl", "access")
        ... class AccessControlPlugin(BasePlugin):
        ...     pass
        >>> AccessControlPlugin.aliases
        ('acl', 'access')
    """

    def _wrap(cls: type) -> type:
        cls.aliases = tuple(aliases)
        return cls

    return _wrap
