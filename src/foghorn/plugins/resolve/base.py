from __future__ import annotations

import inspect
import ipaddress
import logging
import logging.handlers
import os
import sys
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional, Sequence, Tuple, Union, Set, final

from cachetools import LRUCache
from dnslib import (  # noqa: F401 - imports are for implementations of this class
    AAAA,
    CNAME,
    MX,
    NAPTR,
    PTR,
    QTYPE,
    RR,
    SRV,
    TXT,
    A,
    DNSHeader,
    DNSRecord,
)

from foghorn.plugins.cache.base import CachePlugin
from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache
from foghorn.config.logging_config import BracketLevelFormatter, SyslogFormatter

# Canonical DNS response cache used by the resolver.
#
# Brief:
#   This is intentionally defined at module scope so the core resolver
#   (foghorn.server.resolve_query_bytes) and all transports share a single
#   cache object.
#
# Inputs:
#   - None
#
# Outputs:
#   - DNS_CACHE: CachePlugin instance
DNS_CACHE: CachePlugin = InMemoryTTLCache()

# Canonical DNS response cache used by the resolver.
#
# Brief:
#   This is intentionally defined at module scope so the core resolver
#   (foghorn.server.resolve_query_bytes) and all transports share a single
#   cache object.
#
# Inputs:
#   - None
#
# Outputs:
#   - DNS_CACHE: CachePlugin instance
DNS_CACHE: CachePlugin = InMemoryTTLCache()

logger = logging.getLogger(__name__)

_PLUGIN_LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "crit": logging.CRITICAL,
    "critical": logging.CRITICAL,
}


@dataclass
class AdminPageSpec:
    """Brief: Describe a plugin-contributed admin web UI page.

    Inputs (constructor fields):
      - slug: Short, URL-safe identifier for the page (e.g. "docker-hosts").
      - title: Human-friendly page title shown in the UI tab.
      - description: Optional short help text for the page.
      - layout: Optional layout hint; "one_column" or "two_column". Defaults
        to "one_column" when omitted or unknown.
      - kind: Optional implementation hint used by the core UI for
        well-known page types (for example, "docker_hosts"). Custom plugins can
        leave this unset.
      - html_left: Optional HTML fragment rendered into the left admin column
        when layout == "two_column" or the primary column when layout is
        "one_column".
      - html_right: Optional HTML fragment rendered into the right admin column
        when layout == "two_column".

    Outputs:
      - AdminPageSpec instance suitable for JSON-serialization via a simple
        dataclasses.asdict() or attribute inspection.

    Example:
      >>> page = AdminPageSpec(slug="docker-hosts", title="Docker Hosts")
      >>> page.layout
      'one_column'
    """

    slug: str
    title: str
    description: Optional[str] = None
    layout: str = "one_column"
    kind: Optional[str] = None
    html_left: Optional[str] = None
    html_right: Optional[str] = None


@dataclass
class PluginDecision:
    """
    Brief: Represents a decision made by a plugin.

    Inputs:
      - action: str indicating the decision (e.g., "allow", "deny", "override").
      - response: Optional[bytes] DNS response to use when action == "override".
      - plugin: Optional[type[BasePlugin]] set to the originating plugin class when
        instantiated from within a plugin hook (best-effort).
      - plugin_label: Optional[str] best-effort label derived from the originating
        plugin instance (typically BasePlugin.name) for use in statistics and
        logging when available.

    Outputs:
      - PluginDecision instance with attributes populated.
    """

    action: str
    stat: Optional[str] = None
    response: Optional[bytes] = None
    plugin: Optional[type["BasePlugin"]] = None
    plugin_label: Optional[str] = None

    def __post_init__(self) -> None:
        """Brief: Infer originating plugin metadata when not explicitly provided.

        Inputs:
          - None.

        Outputs:
          - None; sets self.plugin to the BasePlugin subclass that created this
            decision when called from within a plugin method, and populates
            plugin_label with the instance's name when available.
        """

        if self.plugin is not None and self.plugin_label is not None:
            return

        # Best-effort: walk the call stack and look for a "self" bound to a
        # BasePlugin instance, which indicates a plugin hook constructed this
        # decision. Any failures here must not affect normal query handling.
        try:
            for frame_info in inspect.stack():
                self_obj = frame_info.frame.f_locals.get("self")
                if isinstance(self_obj, BasePlugin):
                    if self.plugin is None:
                        self.plugin = type(self_obj)
                    if self.plugin_label is None:
                        try:
                            label = getattr(self_obj, "name", None)
                        except (
                            Exception
                        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                            label = None
                        if label is not None:
                            self.plugin_label = str(label)
                    break
        except Exception:  # pragma: no cover - defensive best-effort only
            return


class PluginContext:
    """Brief: Context passed to plugins during pre- and post-resolve phases.

    Inputs:
      - client_ip: str IP address of the requesting client.
      - listener: Optional logical inbound listener identifier (for example,
        "udp", "tcp", "dot", or "doh").
      - secure: Optional bool indicating whether the inbound transport is secured
        with TLS (True for DoT/DoH, False for plain UDP/TCP). When not provided,
        plugins should treat this as "unknown" and avoid assuming security state.

    Attributes (inputs to plugins):
      - client_ip: Requestor's IP address.
      - listener: Optional string naming the listener/transport that received the
        query.
      - secure: Optional bool flag for transport security (True/False/None).
      - upstream_candidates: Optional[list[dict]] overrides global upstreams when set;
        each item is {'host': str, 'port': int}. When provided, the server must use
        only these upstreams for this request and return SERVFAIL if all fail.
      - upstream_override: Optional[tuple[str, int]] legacy single upstream override.

    Outputs:
      - PluginContext instance with fields initialized.

    Example use:
        >>> from foghorn.plugins.resolve.base import PluginContext
        >>> ctx = PluginContext(client_ip="192.0.2.1", listener="udp", secure=False)
        >>> ctx.client_ip
        '192.0.2.1'
        >>> ctx.listener
        'udp'
        >>> ctx.secure
        False
        >>> ctx.upstream_candidates = [{'host': '10.0.0.1', 'port': 53}]
    """

    @final
    def __init__(
        self,
        client_ip: str,
        listener: Optional[str] = None,
        secure: Optional[bool] = None,
    ) -> None:
        """Initialize the PluginContext.

        Inputs:
          - client_ip: The IP address of the client that sent the query.
          - listener: Optional logical listener/transport identifier.
          - secure: Optional transport security flag (True for TLS, False for
            cleartext, None when unspecified).

        Outputs:
          - None (sets client_ip, listener, secure, upstream_candidates,
            upstream_override).
        """
        self.client_ip = client_ip
        self.listener = listener
        # Optional per-request qname; core server paths may attach this so that
        # BasePlugin domain targeting helpers can operate on a normalized name.
        # Callers that do not set qname will simply bypass domain filters.
        self.qname: Optional[str] = None
        # Preserve None when not explicitly provided so callers can distinguish
        # between "unknown" and an explicit True/False value.
        self.secure: Optional[bool] = bool(secure) if secure is not None else None
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
      - name: Optional human-friendly identifier used when logging statistics
        and other plugin-related data. When omitted, a default derived from the
        plugin's aliases or class name is used.
      - **config: Plugin configuration including optional
        pre_priority, post_priority, and setup_priority. Plugins may also
        use an `abort_on_failure` boolean in their config to control
        whether setup() failures abort startup (default True).

    Outputs:
      - Initialized plugin instance with priority attributes and targeting
        helpers.

    Example use:
        >>> from foghorn.plugins.resolve.base import BasePlugin
        >>> class MyPlugin(BasePlugin):
        ...     pre_priority = 10
        ...     def pre_resolve(self, qname, qtype, req, ctx):
        ...         return None
        >>> plugin = MyPlugin(name="my_filter", pre_priority=25)
        >>> plugin.pre_priority
        25
        >>> plugin.name
        'my_filter'
    """

    ttl: ClassVar[int] = 300

    pre_priority: ClassVar[int] = 100
    post_priority: ClassVar[int] = 100
    setup_priority: ClassVar[int] = 100
    aliases: ClassVar[Sequence[str]] = ()
    # Query-type targeting: plugins may override this at the class level to
    # restrict which qtypes they apply to. By default, all qtypes are targeted
    # via the "*" wildcard.
    target_qtypes: ClassVar[Sequence[str]] = ("*",)

    @classmethod
    def get_aliases(cls) -> Sequence[str]:
        """Brief: Return plugin aliases used for discovery.

        Inputs:
          - None

        Outputs:
          - tuple[str, ...]: Sequence of alias strings (may be empty).
        """
        return tuple(getattr(cls, "aliases", ()))

    @final
    def __init__(self, name: Optional[str] = None, **config: object) -> None:
        """Initialize the BasePlugin with configuration, priorities, and targets.

        Inputs:
          - name: Optional friendly identifier used in place of the plugin class
            name when logging statistics or other plugin-related data.
          - **config: Plugin configuration including (optional):
            - pre_priority (int | str): Priority for pre_resolve (1-255, default from class).
            - post_priority (int | str): Priority for post_resolve (1-255, default from class).
            - setup_priority (int | str): Priority for setup() (1-255, default from class).
              If setup_priority is not provided, pre_priority from config is used as a
              fallback for setup plugins.
            - targets (list[str] | str | None): List of CIDR/IP strings (or a single
              string) specifying clients this plugin should target. When omitted or
              empty, all clients are targeted.
            - targets_ignore (list[str] | str | None): List of CIDR/IP strings
              specifying clients to ignore. When targets is empty and
              targets_ignore is non-empty, targeting is inverted so that all
              clients are targeted except those in targets_ignore.
            - targets_listener (str | list[str] | None): Optional listener-level
              targeting. Accepts one or more of {"udp", "tcp", "dot", "doh"}.
              Aliases:
                * "secure"              -> ["dot", "doh"]
                * "unsecure"/"insecure" -> ["udp", "tcp"]
                * "any" / "*" / None     -> no listener restriction.

        Outputs:
          - None (sets self.name, self.config, priority attributes, and target
            networks).

        Priority values are clamped to [1, 255]. Invalid types use class defaults.

        Example use:
            >>> from foghorn.plugins.resolve.base import BasePlugin
            >>> plugin = BasePlugin(pre_priority=10, post_priority=200)
            >>> plugin.pre_priority
            10
        """
        # Determine a stable, human-friendly name for logging and statistics.
        if name is not None:
            self.name = str(name)
        else:
            # Prefer the first alias when available, falling back to the class name.
            try:
                aliases = list(getattr(self.__class__, "get_aliases", lambda: [])())
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                aliases = []
            if aliases:
                default_name = str(aliases[0])
            else:
                default_name = self.__class__.__name__
            self.name = default_name

        self.config = config
        logger.debug("loading %s", self)

        # Per-plugin logger (optional): default to module logger and apply
        # config["logging"] when provided.
        self.logger = logging.getLogger(getattr(self.__class__, "__module__", __name__))
        try:
            plugin_logging_cfg = config.get("logging")
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            plugin_logging_cfg = None
        if isinstance(plugin_logging_cfg, dict):
            self._init_instance_logger(plugin_logging_cfg)

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
            config.get("pre_priority", getattr(self.__class__, "setup_priority", 100)),
        )
        self.setup_priority = self._parse_priority_value(
            raw_setup,
            "setup_priority",
            logger,
        )

        # Optional client targeting: normalize targets/targets_ignore into
        # ipaddress network lists for use by plugins.
        self._target_networks = self._parse_network_list(config.get("targets"))
        self._ignore_networks = self._parse_network_list(config.get("targets_ignore"))

        # Optional domain targeting: restrict this plugin to specific qname
        # patterns (exact or suffix-based) using normalized lower-case names.
        self._targets_domains, self._targets_domains_mode = (
            self._normalize_domain_targets(
                config.get("targets_domains"),
                mode=config.get("targets_domains_mode", "any"),
            )
        )

        # Optional listener-level targeting: restrict this plugin to specific
        # listeners (udp/tcp/dot/doh). When the normalized set is empty, listener
        # type does not affect targeting ("any").
        self._targets_listeners = self._normalize_listener_target(
            config.get("targets_listener")
        )

        # Per-client targeting decisions are cached in-memory to avoid
        # repeatedly parsing IP addresses and scanning CIDR lists under load.
        # Historically this used a TTL cache controlled by
        # targets_cache_ttl_seconds; it now uses a size-bounded LRU cache for
        # simpler behaviour under load. The TTL config key is accepted for
        # backwards compatibility but is no longer used.
        self._targets_cache_ttl: int = int(config.get("targets_cache_ttl_seconds", 300))
        self._targets_cache: LRUCache = LRUCache(maxsize=4096)
        # Lightweight per-cache counters for admin snapshots. These mirror the
        # naming used by other cache backends (calls_total/cache_hits/cache_misses)
        # so that the cache admin UI can treat them uniformly.
        try:
            self._targets_cache.calls_total = 0
            self._targets_cache.cache_hits = 0
            self._targets_cache.cache_misses = 0
        except Exception:  # pragma: nocover - defensive, attributes are best-effort
            pass

        # Optional qtype targeting: normalize configured target_qtypes into
        # uppercase mnemonic values (e.g., ["A", "AAAA"], or ["*."]). When the
        # resolved list is empty or contains "*", all qtypes are targeted.
        #
        # For backwards compatibility with older plugins, allow an
        # `apply_to_qtypes` config key as an alias for `target_qtypes` when the
        # latter is not explicitly provided.
        raw_qtypes_cfg = config.get("target_qtypes")
        if raw_qtypes_cfg is None:
            raw_qtypes_cfg = config.get(
                "apply_to_qtypes",
                getattr(self.__class__, "target_qtypes", ("*",)),
            )
        self._target_qtypes = self._normalize_qtype_list(raw_qtypes_cfg)

    def _init_instance_logger(self, logging_cfg: Dict[str, object]) -> None:
        """Brief: Configure an optional per-plugin logger from a logging config block.

        Inputs:
          - logging_cfg: Mapping-style object with per-plugin logging options
            matching the root-level "logging" config (level, stderr, file, syslog).

        Outputs:
          - None; attaches a configured logger to self.logger and updates the
            underlying module logger in-place.
        """
        try:
            cfg: Dict[str, object] = dict(logging_cfg)
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            return

        logger_name = getattr(self.__class__, "__module__", __name__)
        plugin_logger = logging.getLogger(str(logger_name))

        level_str = str(cfg.get("level", "info")).lower()
        level = _PLUGIN_LOG_LEVELS.get(level_str, logging.INFO)
        plugin_logger.setLevel(level)

        for handler in list(plugin_logger.handlers):
            plugin_logger.removeHandler(handler)

        fmt = "%(asctime)s %(level_tag)s %(name)s: %(message)s"
        formatter = BracketLevelFormatter(fmt=fmt)

        if bool(cfg.get("stderr", True)):
            stderr_handler = logging.StreamHandler(sys.stderr)
            stderr_handler.setFormatter(formatter)
            plugin_logger.addHandler(stderr_handler)

        file_path = cfg.get("file")
        if isinstance(file_path, str) and file_path.strip():
            path = os.path.abspath(os.path.expanduser(file_path.strip()))
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                file_handler = logging.FileHandler(path, mode="a", encoding="utf-8")
                file_handler.setFormatter(formatter)
                plugin_logger.addHandler(file_handler)
            except (
                OSError
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                plugin_logger.warning(
                    "Failed to configure file logging for plugin %s", self.name
                )

        syslog_cfg = cfg.get("syslog")
        if syslog_cfg:
            try:
                if isinstance(syslog_cfg, dict):
                    address = syslog_cfg.get("address", "/dev/log")
                    facility = getattr(
                        logging.handlers.SysLogHandler,
                        f"LOG_{syslog_cfg.get('facility', 'USER').upper()}",
                        logging.handlers.SysLogHandler.LOG_USER,
                    )
                else:
                    address = "/dev/log"
                    facility = logging.handlers.SysLogHandler.LOG_USER

                syslog_handler = logging.handlers.SysLogHandler(
                    address=address, facility=facility
                )
                syslog_handler.setFormatter(SyslogFormatter())
                plugin_logger.addHandler(syslog_handler)
            except (
                OSError,
                ValueError,
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                plugin_logger.warning(
                    "Failed to configure syslog for plugin %s", self.name
                )

        plugin_logger.propagate = False

        self.logger = plugin_logger

    @staticmethod
    def _normalize_qtype_list(raw: object) -> List[str]:
        """Brief: Normalize a raw target_qtypes config value into qtype names.

        Inputs:
          - raw: Configuration value for target_qtypes. May be None, a
            single string, or a list/tuple of strings or string-like objects
            representing qtype mnemonics (e.g., "A", "AAAA") or "*".

        Outputs:
          - list[str]: Uppercase qtype names; empty when no valid entries are
            provided. The wildcard "*" is preserved when present.
        """
        if raw is None:
            return ["*"]

        if isinstance(raw, str):
            entries = [raw]
        elif isinstance(raw, (list, tuple)):
            entries = [str(x) for x in raw]
        else:
            logger.warning(
                "BasePlugin: ignoring invalid target_qtypes value %r (expected str or list)",
                raw,
            )
            return ["*"]

        normalized: List[str] = []
        for entry in entries:
            text = str(entry).strip()
            if not text:
                continue
            if text == "*":
                # Wildcard applies to all qtypes; no need to collect others.
                return ["*"]
            normalized.append(text.upper())

        return normalized or ["*"]

    @staticmethod
    def _parse_priority_value(value: object, key: str, logger: logging.Logger) -> int:
        """Brief: Parse and clamp a priority value to the inclusive range [1, 255].

        Inputs:
          - value: Priority value (int, str, or other).
          - key: Config key name for logging (e.g., "pre_priority").
          - logger: Logger instance for warnings.

        Outputs:
          - int: Clamped priority value in range [1, 255]; defaults to 100 on invalid input.

        Example:
            >>> BasePlugin._parse_priority_value("25", "pre_priority", logger)
            25
            >>> BasePlugin._parse_priority_value(300, "post_priority", logger)
            255
        """
        default = 100
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

    @staticmethod
    def _parse_network_list(raw: object) -> List[ipaddress._BaseNetwork]:
        """Brief: Normalize a raw targets/targets_ignore value into IP networks.

        Inputs:
          - raw: Configuration value for targets or targets_ignore. May be
            None, a single string, or a list/tuple of strings or string-like
            objects representing IP addresses or CIDR ranges.

        Outputs:
          - list[ipaddress._BaseNetwork]: Parsed networks; empty on None or
            when no valid entries are provided.

        Example:
            >>> nets = BasePlugin._parse_network_list(["10.0.0.0/8", "192.0.2.1"])
            >>> bool(nets)
            True
        """
        networks: List[ipaddress._BaseNetwork] = []
        if raw is None:
            return networks

        if isinstance(raw, str):
            entries = [raw]
        elif isinstance(raw, (list, tuple)):
            entries = [str(x) for x in raw]
        else:
            logger.warning(
                "BasePlugin: ignoring invalid targets value %r (expected str or list)",
                raw,
            )
            return networks

        for entry in entries:
            text = str(entry).strip()
            if not text:
                continue
            try:
                net = ipaddress.ip_network(text, strict=False)
            except Exception:
                logger.warning("BasePlugin: skipping invalid target entry %r", text)
                continue
            networks.append(net)

        return networks

    @staticmethod
    def _normalize_domain_targets(
        raw: object,
        mode: object = "any",
    ) -> Tuple[List[str], str]:
        """Brief: Normalize targets_domains and its mode.

        Inputs:
          - raw: Configuration value for targets_domains (str or list[str]).
          - mode: Configuration value for targets_domains_mode.

        Outputs:
          - (domains, mode):
            - domains: list of normalized lower-case domain strings.
            - mode: one of "any", "exact", "suffix".
        """

        # Normalize domain list
        domains: List[str] = []
        entries: List[str]
        if raw is None:
            entries = []
        elif isinstance(raw, str):
            entries = [raw]
        elif isinstance(raw, (list, tuple)):
            entries = [str(x) for x in raw]
        else:
            logger.warning(
                "BasePlugin: ignoring invalid targets_domains value %r (expected str or list)",
                raw,
            )
            entries = []

        for entry in entries:
            text = BasePlugin.normalize_qname(
                entry, lower=True, strip_trailing_dot=True
            )
            if not text:
                continue
            domains.append(text)

        # Normalize mode
        try:
            mode_text = str(mode).strip().lower()
        except Exception:
            mode_text = "any"

        if not mode_text or mode_text in {"any", "*"}:
            return domains, "any"
        if mode_text in {"exact", "eq"}:
            return domains, "exact"
        if mode_text in {"suffix", "sub", "domain"}:
            return domains, "suffix"

        logger.warning(
            "BasePlugin: unknown targets_domains_mode %r; treating as 'any'",
            mode,
        )
        return domains, "any"

    @staticmethod
    def _normalize_listener_target(raw: object) -> Set[str]:
        """Brief: Normalize a targets_listener value into a set of listener names.

        Inputs:
          - raw: Configuration value for targets_listener.

        Outputs:
          - set[str]: Normalized listener names in {"udp", "tcp", "dot", "doh"}.
            An empty set means "any" (no listener restriction).
        """

        def _add_token(out: Set[str], token: str) -> None:
            """Expand a single listener token or alias into concrete names."""
            t = token.strip().lower()
            if not t:
                return
            if t in {"any", "*"}:
                # Any listener allowed; represented by empty set at the caller.
                out.clear()
                return
            if t in {"udp", "tcp", "dot", "doh"}:
                out.add(t)
                return
            if t == "secure":
                out.update({"dot", "doh"})
                return
            if t in {"unsecure", "insecure"}:
                out.update({"udp", "tcp"})
                return
            logger.warning(
                "BasePlugin: unknown targets_listener value %r; ignoring", token
            )

        listeners: Set[str] = set()

        if raw is None:
            return listeners

        if isinstance(raw, str):
            _add_token(listeners, raw)
        elif isinstance(raw, (list, tuple)):
            for item in raw:
                try:
                    text = str(item)
                except Exception:
                    logger.warning(
                        "BasePlugin: ignoring non-string targets_listener entry %r",
                        item,
                    )
                    continue
                _add_token(listeners, text)
        else:
            logger.warning(
                "BasePlugin: ignoring invalid targets_listener value %r (expected str or list)",
                raw,
            )

        # If an "any" token was seen at any point, listeners will have been
        # cleared by _add_token and the empty set represents "no restriction".
        return listeners

    def targets(self, ctx: PluginContext) -> bool:
        """Brief: Determine whether this plugin targets the given client IP.

        Inputs:
          - ctx: PluginContext providing client_ip and listener info for the request.
            Callers may optionally attach a qname attribute (or similar) when
            they wish to use domain-based targeting helpers.

        Outputs:
          - bool: True if the client should be targeted by this plugin based on
            targets/targets_ignore and targets_listener configuration; False
            otherwise.

        Behavior:
          - When "targets" is omitted or empty, all clients are targeted by
            default (subject to targets_listener and targets_domains).
          - When "targets_ignore" is provided without "targets", all clients
            are targeted except those matching any ignore CIDR (inverted
            logic).
          - When both are provided, "targets_ignore" acts as an override to
            exclude specific clients from the targeted set.
          - When "targets_listener" is set to "secure", only queries where
            ctx.secure is True are targeted. When set to "unsecure", only
            queries where ctx.secure is False are targeted. Any other value is
            treated as "any" and does not restrict targeting by listener.

        Example use:
            >>> ctx = PluginContext(client_ip="192.0.2.1")
            >>> p = BasePlugin(targets=["192.0.2.0/24"])
            >>> p.targets(ctx)
            True
        """
        # Listener-level targeting: when configured with one or more concrete
        # listeners (udp/tcp/dot/doh), require the PluginContext.listener to
        # match. When the normalized set is empty, listener type does not
        # affect targeting ("any"). Aliases such as "secure" and "unsecure"
        # are expanded into the underlying listener names during
        # initialization.
        listeners: Set[str] = getattr(self, "_targets_listeners", set())
        if listeners:
            listener_name = str(getattr(ctx, "listener", "") or "").strip().lower()
            if not listener_name or listener_name not in listeners:
                return False

        # Domain-level targeting: when targets_domains are configured, restrict
        # this plugin to matching qnames. Callers may attach a qname-like
        # attribute (for example, ctx.qname) for this purpose; when absent,
        # domain filters are not applied.
        domains_cfg: List[str] = getattr(self, "_targets_domains", [])
        domains_mode: str = getattr(self, "_targets_domains_mode", "any")
        if domains_cfg and domains_mode != "any":
            qname_val = getattr(ctx, "qname", None)
            if qname_val is None:
                # No qname context available; treat as non-targeted when an
                # explicit domain filter exists.
                return False
            qtext = BasePlugin.normalize_qname(
                qname_val, lower=True, strip_trailing_dot=True
            )
            if not qtext:
                return False

            if domains_mode == "exact":
                if qtext not in domains_cfg:
                    return False
            elif domains_mode == "suffix":
                if not any(qtext == d or qtext.endswith("." + d) for d in domains_cfg):
                    return False

        # Fast path: when no explicit targets or ignores are configured, all
        # clients are targeted (subject to the listener and domain checks above)
        # and no cache lookups are performed.
        if not self._target_networks and not self._ignore_networks:
            return True

        client_ip = getattr(ctx, "client_ip", "")
        if not client_ip:
            # With explicit targets/ignores but no usable client IP, treat as
            # not targeted.
            return False

        cache_key = (str(client_ip), 0)

        # Consult per-client cache first to avoid repeated IP parsing and CIDR
        # scans under sustained load.
        try:
            # Update best-effort call counter when the cache exposes one.
            calls_attr = getattr(self._targets_cache, "calls_total", None)
            if isinstance(calls_attr, int):
                try:
                    self._targets_cache.calls_total = calls_attr + 1
                except Exception:
                    pass
            cached = self._targets_cache.get(cache_key)
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            cached = None

        if cached is not None:
            # Cache hit: increment hit counter when available.
            hits_attr = getattr(self._targets_cache, "cache_hits", None)
            if isinstance(hits_attr, int):
                try:
                    self._targets_cache.cache_hits = hits_attr + 1
                except Exception:
                    pass
            try:
                return bool(int(cached.decode()))
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                pass

        # Cache miss or decode failure: compute targeting decision and treat as
        # a cache miss for counter purposes.
        misses_attr = getattr(self._targets_cache, "cache_misses", None)
        if isinstance(misses_attr, int):
            try:
                self._targets_cache.cache_misses = misses_attr + 1
            except Exception:
                pass

        try:
            addr = ipaddress.ip_address(client_ip)
        except Exception:
            # Invalid client IP with explicit targets/ignores -> not targeted.
            result = False
        else:
            # Ignore list takes precedence regardless of targets configuration.
            if any(addr in net for net in self._ignore_networks):
                result = False
            # Empty targets means "everyone" (subject to ignore list above).
            elif not self._target_networks:
                result = True
            else:
                # Non-empty targets restrict to matching networks.
                result = any(addr in net for net in self._target_networks)

        # Store decision in the per-client cache for subsequent queries from
        # the same client_ip. This is a size-bounded LRU cache rather than a
        # TTL-based cache; entries remain until evicted.
        try:
            self._targets_cache[cache_key] = b"1" if result else b"0"
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            pass

        return result

    def targets_qtype(self, qtype: Union[int, str]) -> bool:
        """Brief: Determine whether this plugin targets the given DNS qtype.

        Inputs:
          - qtype: DNS RR type, as an integer code or mnemonic string.

        Outputs:
          - bool: True if the plugin should run for this qtype based on its
            target_qtypes configuration; False otherwise.
        """
        # Fast path: wildcard or empty list means "all qtypes".
        try:
            qtypes = list(getattr(self, "_target_qtypes", ["*"]))
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            qtypes = ["*"]

        if not qtypes or "*" in qtypes:
            return True

        name = self.qtype_name(qtype)
        return str(name).upper() in {qt.upper() for qt in qtypes}

    @staticmethod
    def qtype_name(qtype: Union[int, str]) -> str:
        """Brief: Normalize a DNS qtype value to its uppercase mnemonic.

        Inputs:
          - qtype: DNS RR type as an integer code (e.g. 1) or mnemonic string
            (e.g. "A", "AAAA").

        Outputs:
          - str: Uppercase qtype name when resolvable, or stringified value
            when the code is unknown.
        """
        if isinstance(qtype, int):
            try:
                name = QTYPE.get(qtype, str(qtype))
            except Exception:  # pragma: no cover - defensive
                name = str(qtype)
            return str(name).upper()
        return str(qtype).upper()

    @staticmethod
    def normalize_qname(
        qname: object,
        *,
        lower: bool = True,
        strip_trailing_dot: bool = True,
    ) -> str:
        """Brief: Normalize a qname-like value into a DNS name string.

        Inputs:
          - qname: Value representing a domain name (string or dnslib QNAME).
          - lower: When True (default), lower-case the result.
          - strip_trailing_dot: When True (default), remove a final trailing
            dot while preserving interior dots.

        Outputs:
          - str: Normalized domain name string (may be empty when input is
            empty or cannot be coerced).
        """
        try:
            text = str(qname)
        except Exception:  # pragma: no cover - defensive
            text = ""

        if strip_trailing_dot:
            text = text.rstrip(".")
        if lower:
            text = text.lower()
        return text

    @staticmethod
    def base_domain(qname: object, base_labels: int = 2) -> str:
        """Brief: Extract a base domain using the last N labels from qname.

        Inputs:
          - qname: Domain name-like value; may include a trailing dot.
          - base_labels: Number of rightmost labels that define the base
            domain (default 2, e.g. "example.com").

        Outputs:
          - str: Base domain string such as 'example.com' for
            'a.b.example.com.', or the normalized name itself when it has
            fewer than base_labels labels.
        """
        name = BasePlugin.normalize_qname(qname, lower=True, strip_trailing_dot=True)
        if not name:
            return ""
        labels = [p for p in name.split(".") if p]
        if len(labels) >= int(base_labels):
            return ".".join(labels[-int(base_labels) :])
        return name

    def get_admin_ui_descriptor(self) -> Optional[Dict[str, object]]:
        """Brief: Describe this plugin's admin web UI surface (if any).

        Inputs:
          - None.

        Outputs:
          - Optional[dict]: Minimal metadata describing this plugin's admin UI,
            or None when the plugin does not contribute any admin UI.

        Notes:
          - Subclasses that expose admin web pages should override this method
            and return a JSON-serializable mapping. Common keys include:

              * name (str): Effective plugin instance name used for routing.
              * title (str): Human-friendly tab title for the admin UI.
              * kind (str): Short identifier used by the frontend to pick a
                renderer (for example, "docker_hosts" or "mdns_services").
              * order (int): Optional ordering hint (lower appears earlier).
              * endpoints (dict): Optional mapping of logical endpoint names to
                URLs (for example, {"snapshot": "/api/v1/plugins/{name}/..."}).

          - The base implementation returns None so plugins without admin UI do
            not appear in generic discovery responses.
        """

        return None

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
            >>> from foghorn.plugins.resolve.base import BasePlugin, PluginContext
            >>> plugin = BasePlugin()
            >>> ctx = PluginContext('127.0.0.1')
            >>> plugin.pre_resolve("example.com", 1, b'', ctx) is None
            True
        """
        return None

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
            >>> from foghorn.plugins.resolve.base import BasePlugin, PluginContext
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
            >>> from foghorn.plugins.resolve.base import BasePlugin
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

    def _make_a_response(
        self,
        qname: str,
        query_type: int,
        raw_req: bytes,
        ctx: PluginContext,
        ipaddr: str,
    ) -> Optional[bytes]:
        try:
            request = DNSRecord.parse(raw_req)
        except Exception as e:
            logger.warning("parse failure: %s", e)
            return None

        # Normalize domain
        # qname = str(request.q.qname).rstrip(".")

        ip = ipaddr
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        if query_type == QTYPE.A:
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.A,
                    rclass=1,
                    ttl=self._ttl,
                    rdata=A(ip),
                )
            )
        elif query_type == QTYPE.AAAA:
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.AAAA,
                    rclass=1,
                    ttl=60,
                    rdata=AAAA(ip),
                )
            )

        return reply.pack()


def plugin_aliases(*aliases: str):
    """Brief: Decorator to set aliases on a plugin class for registry discovery.

    Inputs:
      - *aliases: Variable number of alias strings for the plugin.

    Outputs:
      - Callable that applies the aliases to a plugin class and returns it.

    Example:
        >>> from foghorn.plugins.resolve.base import BasePlugin, plugin_aliases
        >>> @plugin_aliases("acl", "access")
        ... class AccessControl(BasePlugin):
        ...     pass
        >>> AccessControl.aliases
        ('acl', 'access')
    """

    def _wrap(cls: type) -> type:
        cls.aliases = tuple(aliases)
        return cls

    return _wrap
