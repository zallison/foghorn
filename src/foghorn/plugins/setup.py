"""Plugin lifecycle helpers used during startup, reload, and shutdown.

Brief:
  Foghorn supports optional plugin lifecycle hooks.
  - ``setup``: Plugins that override ``BasePlugin.setup`` are treated as
    setup-aware and executed by phase in ascending ``setup_priority`` order.
  - ``shutdown``: Objects with a callable ``shutdown()`` method can be
    invoked best-effort during process teardown.

Inputs:
  - list[object]: lifecycle objects (resolver plugins, cache plugins, stats backends)

Outputs:
  - None

Notes:
  - This module exists so startup logic and config reload logic can share the
    same implementation without importing the main entrypoint.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Dict, List, Optional, Sequence, Tuple

from dnslib import QTYPE, DNSRecord

from .resolve.base import BasePlugin, PluginContext


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


def _setup_priority_for(plugin: BasePlugin) -> int:
    """Brief: Parse setup priority with safe fallback.

    Inputs:
      - plugin: BasePlugin instance.

    Outputs:
      - int: Setup priority, defaulting to 100 for malformed values.
    """

    try:
        return int(getattr(plugin, "setup_priority", 100))
    except Exception:
        return 100


def _setup_abort_on_failure(plugin: BasePlugin) -> bool:
    """Brief: Resolve setup abort behavior from plugin config.

    Inputs:
      - plugin: BasePlugin instance.

    Outputs:
      - bool: True when setup failure should abort startup/reload.
    """

    cfg = getattr(plugin, "config", {}) or {}
    return bool(cfg.get("abort_on_failure", True))


def _setup_dns_fallback_to_system(plugin: BasePlugin) -> bool:
    """Brief: Resolve setup-time DNS fallback policy for setup consumers.

    Inputs:
      - plugin: BasePlugin instance.

    Outputs:
      - bool: True when misses should fall back to system DNS.

    Notes:
      - Config key: ``setup_dns_fallback_to_system`` (default True).
    """

    cfg = getattr(plugin, "config", {}) or {}
    if "setup_dns_fallback_to_system" not in cfg:
        return True

    raw = cfg.get("setup_dns_fallback_to_system")
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
    return True


def _extract_rr_addresses(response_wire: bytes, qtype: int) -> List[str]:
    """Brief: Extract A/AAAA addresses from DNS wire response bytes.

    Inputs:
      - response_wire: Packed DNS response bytes.
      - qtype: Desired qtype (QTYPE.A or QTYPE.AAAA).

    Outputs:
      - list[str]: Parsed addresses matching qtype.
    """

    out: List[str] = []
    try:
        msg = DNSRecord.parse(response_wire)
    except Exception:
        return out

    for rr in list(getattr(msg, "rr", []) or []):
        if int(getattr(rr, "rtype", -1)) != int(qtype):
            continue
        text = str(getattr(rr, "rdata", "")).strip()
        if not text:
            continue
        try:
            ip_obj = ipaddress.ip_address(text)
        except ValueError:
            continue
        if qtype == QTYPE.A and ip_obj.version != 4:
            continue
        if qtype == QTYPE.AAAA and ip_obj.version != 6:
            continue
        out.append(str(ip_obj))
    return out


class _SetupDNSResolverContext:
    """Brief: Temporarily patch socket DNS lookups during setup().

    Inputs:
      - providers: Setup-ready plugins marked setup_provides_dns=True.
      - upstreams: Effective forwarder endpoints (primary + backup).
      - timeout_ms: Upstream timeout budget.
      - resolver_mode: Effective resolver mode.
      - upstream_max_concurrent: Upstream parallelism cap.
      - fallback_to_system: Whether to fallback to system resolver on misses.
      - logger_obj: Logger for debug diagnostics.

    Outputs:
      - Context manager that patches getaddrinfo/gethostbyname/gethostbyname_ex.
    """

    def __init__(
        self,
        *,
        providers: Sequence[BasePlugin],
        upstreams: Sequence[Dict],
        timeout_ms: int,
        resolver_mode: str,
        upstream_max_concurrent: int,
        fallback_to_system: bool,
        logger_obj: logging.Logger,
    ) -> None:
        self.providers = list(providers or [])
        self.upstreams = list(upstreams or [])
        self.timeout_ms = int(timeout_ms)
        self.resolver_mode = str(resolver_mode or "forward").lower()
        self.upstream_max_concurrent = max(1, int(upstream_max_concurrent or 1))
        self.fallback_to_system = bool(fallback_to_system)
        self.logger = logger_obj

        self._orig_getaddrinfo = socket.getaddrinfo
        self._orig_gethostbyname = socket.gethostbyname
        self._orig_gethostbyname_ex = socket.gethostbyname_ex

    def _resolve_with_providers(self, host: str, family: int) -> List[str]:
        """Brief: Resolve A/AAAA using setup-ready provider plugins.

        Inputs:
          - host: Hostname (no trailing dot required).
          - family: socket.AF_INET or socket.AF_INET6.

        Outputs:
          - list[str]: Address candidates from provider plugin overrides.
        """

        if family not in (socket.AF_INET, socket.AF_INET6):
            return []
        qtype = QTYPE.A if family == socket.AF_INET else QTYPE.AAAA
        qtype_name = "A" if qtype == QTYPE.A else "AAAA"
        host_norm = str(host or "").strip().rstrip(".")
        if not host_norm:
            return []

        try:
            req_wire = DNSRecord.question(host_norm, qtype_name).pack()
        except Exception:
            return []

        # Use a concrete listener label to maximize compatibility with plugins
        # that restrict execution by listener.
        ctx = PluginContext(client_ip="127.0.0.1", listener="udp", secure=False)
        ctx.qname = host_norm

        out: List[str] = []
        for provider in self.providers:
            try:
                decision = provider.pre_resolve(host_norm, int(qtype), req_wire, ctx)
            except Exception:
                self.logger.debug(
                    "Setup DNS provider %s pre_resolve failed",
                    provider.__class__.__name__,
                    exc_info=True,
                )
                continue
            if decision is None:
                continue
            if str(getattr(decision, "action", "")).lower() != "override":
                continue
            response_wire = getattr(decision, "response", None)
            if not isinstance(response_wire, (bytes, bytearray)):
                continue
            out.extend(_extract_rr_addresses(bytes(response_wire), int(qtype)))

        # Deduplicate while preserving order.
        deduped: List[str] = []
        seen: set[str] = set()
        for ip_text in out:
            if ip_text in seen:
                continue
            seen.add(ip_text)
            deduped.append(ip_text)
        return deduped

    def _resolve_with_upstreams(self, host: str, family: int) -> List[str]:
        """Brief: Resolve A/AAAA directly against configured upstreams.

        Inputs:
          - host: Hostname.
          - family: socket.AF_INET or socket.AF_INET6.

        Outputs:
          - list[str]: Address candidates from upstreams.
        """

        if self.resolver_mode != "forward":
            return []
        if not self.upstreams:
            return []
        if family not in (socket.AF_INET, socket.AF_INET6):
            return []

        qtype = QTYPE.A if family == socket.AF_INET else QTYPE.AAAA
        qtype_name = "A" if qtype == QTYPE.A else "AAAA"
        host_norm = str(host or "").strip().rstrip(".")
        if not host_norm:
            return []

        try:
            query = DNSRecord.question(host_norm, qtype_name)
        except Exception:
            return []

        try:
            from foghorn.servers.server import send_query_with_failover
        except Exception:
            return []

        try:
            response_wire, _upstream, _reason = send_query_with_failover(
                query,
                list(self.upstreams or []),
                int(self.timeout_ms),
                host_norm,
                int(qtype),
                max_concurrent=int(self.upstream_max_concurrent),
            )
        except Exception:
            self.logger.debug("Setup DNS upstream query failed", exc_info=True)
            return []

        if not response_wire:
            return []
        return _extract_rr_addresses(response_wire, int(qtype))

    def _resolve_for_family(self, host: str, family: int) -> List[str]:
        """Brief: Resolve one host for one address family.

        Inputs:
          - host: Hostname.
          - family: socket.AF_INET or socket.AF_INET6.

        Outputs:
          - list[str]: Address candidates.
        """

        provider_ips = self._resolve_with_providers(host, family)
        if provider_ips:
            return provider_ips

        upstream_ips = self._resolve_with_upstreams(host, family)
        if upstream_ips:
            return upstream_ips

        return []

    def _as_getaddrinfo(
        self,
        host: str,
        port,
        family: int,
        type: int,
        proto: int,
        flags: int,
    ) -> List[Tuple]:
        """Brief: Convert resolved addresses into getaddrinfo tuples.

        Inputs:
          - host: Original host string.
          - port/family/type/proto/flags: getaddrinfo arguments.

        Outputs:
          - list[tuple]: getaddrinfo-compatible result tuples.
        """

        families: List[int] = []
        if family in (0, socket.AF_UNSPEC):
            families = [socket.AF_INET, socket.AF_INET6]
        elif family in (socket.AF_INET, socket.AF_INET6):
            families = [family]

        ips: List[str] = []
        for fam in families:
            ips.extend(self._resolve_for_family(host, fam))
        if not ips:
            return []

        out: List[Tuple] = []
        seen: set[Tuple] = set()
        for ip_text in ips:
            try:
                resolved = self._orig_getaddrinfo(
                    ip_text,
                    port,
                    family if family not in (0, socket.AF_UNSPEC) else 0,
                    type,
                    proto,
                    flags | getattr(socket, "AI_NUMERICHOST", 0),
                )
            except Exception:
                continue
            for item in resolved:
                if item in seen:
                    continue
                seen.add(item)
                out.append(item)
        return out

    def __enter__(self) -> "_SetupDNSResolverContext":
        """Brief: Install patched socket DNS functions.

        Inputs:
          - None.

        Outputs:
          - _SetupDNSResolverContext self.
        """

        def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if host is None:
                return self._orig_getaddrinfo(host, port, family, type, proto, flags)
            host_text = str(host)
            try:
                ipaddress.ip_address(host_text)
                return self._orig_getaddrinfo(
                    host_text, port, family, type, proto, flags
                )
            except Exception:
                pass

            synthetic = self._as_getaddrinfo(
                host_text,
                port,
                family,
                type,
                proto,
                flags,
            )
            if synthetic:
                return synthetic
            if self.fallback_to_system:
                return self._orig_getaddrinfo(
                    host_text, port, family, type, proto, flags
                )
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

        def _patched_gethostbyname(host):
            host_text = str(host or "")
            try:
                ipaddress.ip_address(host_text)
                return self._orig_gethostbyname(host_text)
            except Exception:
                pass
            ips = self._resolve_for_family(host_text, socket.AF_INET)
            if ips:
                return ips[0]
            if self.fallback_to_system:
                return self._orig_gethostbyname(host_text)
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

        def _patched_gethostbyname_ex(host):
            host_text = str(host or "")
            try:
                ipaddress.ip_address(host_text)
                return self._orig_gethostbyname_ex(host_text)
            except Exception:
                pass
            ips = self._resolve_for_family(host_text, socket.AF_INET)
            if ips:
                return (host_text, [], ips)
            if self.fallback_to_system:
                return self._orig_gethostbyname_ex(host_text)
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

        socket.getaddrinfo = _patched_getaddrinfo
        socket.gethostbyname = _patched_gethostbyname
        socket.gethostbyname_ex = _patched_gethostbyname_ex
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Brief: Restore original socket DNS functions.

        Inputs:
          - exc_type/exc/tb: Context manager exception triplet.

        Outputs:
          - None.
        """

        socket.getaddrinfo = self._orig_getaddrinfo
        socket.gethostbyname = self._orig_gethostbyname
        socket.gethostbyname_ex = self._orig_gethostbyname_ex


def run_setup_plugins(
    plugins: List[BasePlugin],
    *,
    upstreams: Optional[List[Dict]] = None,
    upstream_backups: Optional[List[Dict]] = None,
    timeout_ms: int = 2000,
    resolver_mode: str = "forward",
    upstream_max_concurrent: int = 1,
) -> None:
    """Brief: Run setup() hooks with provider-first setup-time DNS orchestration.

    Inputs:
      - plugins: List[BasePlugin] instances, typically from load_plugins().
      - upstreams: Primary upstream endpoint mappings.
      - upstream_backups: Backup upstream endpoint mappings.
      - timeout_ms: Upstream timeout budget in milliseconds.
      - resolver_mode: Effective resolver mode.
      - upstream_max_concurrent: Max concurrent upstream attempts.

    Outputs:
      - None; raises RuntimeError if a setup plugin with abort_on_failure=True fails.

    Notes:
      - Setup-aware plugins are executed in two phases:
        1) providers (`setup_provides_dns=True`)
        2) regular setup plugins
      - Within each phase, setup_priority controls ordering.
      - Setup consumers (`setup_requires_dns=True`) run under a temporary socket
        DNS context:
          providers -> configured upstreams (forward mode) -> optional system fallback.
    """

    logger = logging.getLogger("foghorn.main.setup")

    setup_entries: List[Tuple[int, BasePlugin]] = []
    for p in plugins or []:
        if not _is_setup_plugin(p):
            continue
        setup_entries.append((_setup_priority_for(p), p))

    setup_entries.sort(key=lambda item: item[0])

    provider_entries: List[Tuple[int, BasePlugin]] = [
        (prio, p)
        for prio, p in setup_entries
        if bool(getattr(p, "setup_provides_dns", False))
    ]
    regular_entries: List[Tuple[int, BasePlugin]] = [
        (prio, p)
        for prio, p in setup_entries
        if not bool(getattr(p, "setup_provides_dns", False))
    ]

    providers_ready: List[BasePlugin] = []
    all_upstreams: List[Dict] = list(upstreams or []) + list(upstream_backups or [])

    for phase_name, phase_entries in (
        ("provider", provider_entries),
        ("regular", regular_entries),
    ):
        for prio, plugin in phase_entries:
            abort_on_failure = _setup_abort_on_failure(plugin)
            requires_dns = bool(getattr(plugin, "setup_requires_dns", False))
            fallback_to_system = _setup_dns_fallback_to_system(plugin)
            name = plugin.__class__.__name__

            logger.info(
                "Running setup for plugin %s (phase=%s, setup_priority=%d, abort_on_failure=%s, requires_dns=%s)",
                name,
                phase_name,
                prio,
                abort_on_failure,
                requires_dns,
            )
            try:
                if requires_dns:
                    with _SetupDNSResolverContext(
                        providers=providers_ready,
                        upstreams=all_upstreams,
                        timeout_ms=int(timeout_ms),
                        resolver_mode=str(resolver_mode or "forward"),
                        upstream_max_concurrent=max(
                            1, int(upstream_max_concurrent or 1)
                        ),
                        fallback_to_system=bool(fallback_to_system),
                        logger_obj=logger,
                    ):
                        plugin.setup()
                else:
                    plugin.setup()
            except Exception as e:
                logger.error("Setup for plugin %s failed: %s", name, e, exc_info=True)
                if abort_on_failure:
                    raise RuntimeError(f"Setup for plugin {name} failed") from e
                logger.warning(
                    "Continuing startup despite setup failure in plugin %s because abort_on_failure is False",
                    name,
                )
                continue

            if bool(getattr(plugin, "setup_provides_dns", False)):
                providers_ready.append(plugin)

            if requires_dns:
                logger.debug(
                    "Setup DNS for plugin %s used providers=%d fallback_to_system=%s",
                    name,
                    len(providers_ready),
                    bool(fallback_to_system),
                )

    # Notify plugins that the setup phase is complete. This runs after both
    # provider and regular setup phases, so plugins can start background tasks
    # that should not execute during setup().
    finished_order: List[BasePlugin] = [p for _, p in provider_entries] + [
        p for _, p in regular_entries
    ]
    seen_ids = {id(p) for p in finished_order}
    for plugin in plugins or []:
        if id(plugin) in seen_ids:
            continue
        seen_ids.add(id(plugin))
        finished_order.append(plugin)

    for plugin in finished_order:
        abort_on_failure = _setup_abort_on_failure(plugin)
        name = plugin.__class__.__name__
        try:
            plugin.post_setup()
        except Exception as e:
            logger.error("post_setup for plugin %s failed: %s", name, e, exc_info=True)
            if abort_on_failure:
                raise RuntimeError(f"post_setup for plugin {name} failed") from e
            logger.warning(
                "Continuing startup despite post_setup failure in plugin %s because abort_on_failure is False",
                name,
            )


def run_shutdown_plugins(plugins: List[object]) -> None:
    """Brief: Run shutdown() on lifecycle objects that expose a callable hook.

    Inputs:
      - plugins: List of objects. Any item with a callable shutdown() is invoked
        once in input order. Duplicate object references are ignored.

    Outputs:
      - None. Errors are logged and processing continues (best effort).

    Notes:
      - This helper is intentionally generic so it can be used for resolver
        plugins, cache plugins, and query-log/statistics backends.
      - shutdown() failures must never abort process teardown.
    """

    logger = logging.getLogger("foghorn.main.shutdown")
    seen: set[int] = set()

    for plugin in plugins or []:
        if plugin is None:
            continue

        obj_id = id(plugin)
        if obj_id in seen:
            continue
        seen.add(obj_id)

        shutdown = getattr(plugin, "shutdown", None)
        if not callable(shutdown):
            continue

        name = getattr(plugin, "name", None) or plugin.__class__.__name__
        logger.info("Running shutdown for plugin %s", name)
        try:
            shutdown()
        except Exception as e:
            logger.error("Shutdown for plugin %s failed: %s", name, e, exc_info=True)
