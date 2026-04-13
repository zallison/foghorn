"""Brief: NOTIFY infrastructure for AXFR-backed zones.

Inputs/Outputs:
  - NOTIFY sending, target validation, throttling, and delayed scheduling.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from typing import Dict, List

from dnslib import OPCODE, DNSRecord

from foghorn.servers.transports.dot import dot_query
from foghorn.servers.transports.tcp import tcp_query
from foghorn.utils import ip_networks

logger = logging.getLogger(__name__)
_RESOLVE_CACHE_LOCK = threading.RLock()
_RESOLVE_CACHE: dict[str, tuple[float, set[str]]] = {}
_PENDING_NOTIFY_TIMERS_LOCK = threading.RLock()
_PENDING_NOTIFY_TIMERS: dict[tuple[str, str], threading.Timer] = {}


def _target_key(target: Dict[str, object]) -> str:
    """Brief: Build a stable key for a NOTIFY target.

    Inputs:
      - target: Target mapping containing host/port/transport.

    Outputs:
      - str key for dedupe/rate-limit state.
    """
    host = str(target.get("host", "")).strip().lower()
    try:
        port = int(target.get("port", 53))
    except Exception:
        port = 53
    transport = str(target.get("transport", "tcp") or "tcp").strip().lower()
    if transport not in {"tcp", "dot"}:
        transport = "tcp"
    return f"{host}:{port}/{transport}"


def _get_local_dns_listener_endpoints() -> set[tuple[str, int]]:
    """Brief: Return local DNS listener endpoints as (ip, port) tuples.

    Inputs:
      - None.

    Outputs:
      - set[(ip, port)] derived from runtime server.listen config.
    """
    endpoints: set[tuple[str, int]] = set()
    try:
        from foghorn.runtime_config import get_runtime_snapshot

        cfg = get_runtime_snapshot().cfg
    except Exception:
        cfg = {}
    server = cfg.get("server") if isinstance(cfg, dict) else {}
    listen = server.get("listen") if isinstance(server, dict) else {}
    if not isinstance(listen, dict):
        return endpoints

    for proto in ("udp", "tcp", "dot"):
        node = listen.get(proto)
        if not isinstance(node, dict):
            continue
        if not bool(node.get("enabled", False)):
            continue
        try:
            port = int(node.get("port", 53))
        except Exception:
            port = 53
        bind_ip = str(node.get("bind_ip", "0.0.0.0") or "0.0.0.0").strip()
        if bind_ip in ("0.0.0.0", "::"):
            endpoints.add(("0.0.0.0", port))
            endpoints.add(("::", port))
        else:
            endpoints.add((bind_ip, port))
    return endpoints


def _resolve_target_ips(host: str) -> set[str]:
    """Brief: Resolve a notify target host into IP addresses with short caching.

    Inputs:
      - host: Target host (IP literal or DNS name).

    Outputs:
      - set[str] of resolved IP addresses.
    """
    out: set[str] = set()
    text = str(host or "").strip()
    if not text:
        return out

    cache_key = text.lower()
    now = time.monotonic()
    with _RESOLVE_CACHE_LOCK:
        cached = _RESOLVE_CACHE.get(cache_key)
    if cached is not None:
        expires_at, ips = cached
        if expires_at > now:
            return set(ips)

    ip_obj = ip_networks.parse_ip(text)
    if ip_obj is not None:
        out.add(str(ip_obj))
        with _RESOLVE_CACHE_LOCK:
            _RESOLVE_CACHE[cache_key] = (now + 300.0, set(out))
        return out

    try:
        infos = socket.getaddrinfo(text, None, 0, socket.SOCK_STREAM)
    except Exception:
        return out

    for info in infos:
        try:
            addr = info[4][0]
            ip_obj = ip_networks.parse_ip(addr)
            if ip_obj is not None:
                out.add(str(ip_obj))
        except Exception:
            continue

    with _RESOLVE_CACHE_LOCK:
        _RESOLVE_CACHE[cache_key] = (now + 60.0, set(out))
    return out


def _get_local_interface_ips() -> set[str]:
    """Brief: Resolve local interface addresses for self-loop detection.

    Inputs:
      - None.

    Outputs:
      - set[str] of local interface IP addresses.
    """
    out: set[str] = set()
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, 0, socket.SOCK_STREAM)
    except Exception:
        return out

    for info in infos:
        try:
            addr = str(info[4][0]).strip()
            ip_obj = ip_networks.parse_ip(addr)
            if ip_obj is not None:
                out.add(str(ip_obj))
        except Exception:
            continue
    return out


def _is_local_notify_target(target: Dict[str, object]) -> bool:
    """Brief: Determine whether a NOTIFY target points to this local node.

    Inputs:
      - target: Notify target mapping with host/port.

    Outputs:
      - bool: True when target maps to local listener endpoint(s).
    """
    try:
        port = int(target.get("port", 53))
    except Exception:
        port = 53
    host = str(target.get("host", "") or "").strip()
    if not host:
        return False

    local_eps = _get_local_dns_listener_endpoints()
    if not local_eps:
        return False

    local_ifaces = _get_local_interface_ips()
    for ip_text in _resolve_target_ips(host):
        if (ip_text, port) in local_eps:
            return True
        if ip_text in local_ifaces and any(
            lep_port == port for (_lep_ip, lep_port) in local_eps
        ):
            return True
        if any(
            lep_port == port and lep_ip in ("0.0.0.0", "::")
            for (lep_ip, lep_port) in local_eps
        ):
            return True
    return False


def record_axfr_client(
    plugin: object,
    zone_apex: str,
    client_ip: str,
) -> None:
    """Brief: Deprecated no-op retained for API compatibility.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - zone_apex: Zone apex name.
      - client_ip: AXFR/IXFR client IP.

    Outputs:
      - None.
    """
    _ = (plugin, zone_apex, client_ip)
    return


def _target_has_disallowed_ip(target: Dict[str, object]) -> bool:
    """Brief: Check whether target resolution includes private/special addresses.

    Inputs:
      - target: NOTIFY target mapping.

    Outputs:
      - bool: True when target address set should be blocked by default policy.
    """
    host = str(target.get("host", "")).strip()
    if not host:
        return True
    resolved = _resolve_target_ips(host)
    if not resolved:
        return True

    for ip_text in resolved:
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except Exception:
            return True
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
            or ip_obj.is_reserved
        ):
            return True
    return False


def _target_is_allowlisted(plugin: object, target: Dict[str, object]) -> bool:
    """Brief: Check whether a NOTIFY target is permitted by configured allowlist.

    Inputs:
      - plugin: ZoneRecords plugin instance carrying allowlist settings.
      - target: NOTIFY target mapping with host/port/transport.

    Outputs:
      - bool: True when allowlist is unset, or target host/IP matches allowlist.
    """
    raw_allowlist = getattr(plugin, "_axfr_notify_target_allowlist", None)
    if not raw_allowlist:
        return True

    host_allowlist = getattr(plugin, "_axfr_notify_target_allowlist_hosts", set())
    if not isinstance(host_allowlist, set):
        host_allowlist = set()

    network_allowlist = getattr(plugin, "_axfr_notify_target_allowlist_networks", [])
    if not isinstance(network_allowlist, list):
        network_allowlist = []

    host = str(target.get("host", "") or "").strip().lower().rstrip(".")
    if not host:
        return False
    if host in host_allowlist:
        return True

    resolved = _resolve_target_ips(host)
    if not resolved:
        return False

    for ip_text in resolved:
        ip_obj = ip_networks.parse_ip(ip_text)
        if ip_obj is None:
            return False
        if not ip_networks.ip_in_any_network(ip_obj, network_allowlist):
            return False
    return True


def _should_send_notify(plugin: object, target: Dict[str, object]) -> bool:
    """Brief: Apply per-target min-interval and rate-limit checks.

    Inputs:
      - plugin: ZoneRecords plugin instance carrying notify policy state.
      - target: NOTIFY target mapping.

    Outputs:
      - bool: True when a send is allowed now.
    """
    now = time.monotonic()
    target_key = _target_key(target)
    min_interval = max(
        0.0, float(getattr(plugin, "_axfr_notify_min_interval_seconds", 1.0) or 0.0)
    )
    rate_limit = max(
        1,
        int(getattr(plugin, "_axfr_notify_rate_limit_per_target_per_minute", 60) or 60),
    )

    lock = getattr(plugin, "_axfr_notify_lock", None)
    if lock is None:
        lock = threading.RLock()

    with lock:
        history = getattr(plugin, "_axfr_notify_send_history", {})
        if not isinstance(history, dict):
            history = {}
            setattr(plugin, "_axfr_notify_send_history", history)

        last_sent = getattr(plugin, "_axfr_notify_last_sent", {})
        if not isinstance(last_sent, dict):
            last_sent = {}
            setattr(plugin, "_axfr_notify_last_sent", last_sent)

        recent = [ts for ts in list(history.get(target_key, [])) if now - ts < 60.0]
        previous_sent = float(last_sent.get(target_key, 0.0) or 0.0)

        if (
            min_interval > 0.0
            and previous_sent > 0.0
            and now - previous_sent < min_interval
        ):
            history[target_key] = recent
            return False

        if len(recent) >= rate_limit:
            history[target_key] = recent
            return False

        recent.append(now)
        history[target_key] = recent
        last_sent[target_key] = now
    return True


def send_notify_to_target(zone_apex: str, target: Dict[str, object]) -> None:
    """Brief: Send a DNS NOTIFY for *zone_apex* to a single downstream target.

    Inputs:
      - zone_apex: Zone apex name without trailing dot.
      - target: Mapping with at least ``host`` and ``port`` keys and
        optional ``timeout_ms``, ``transport``, ``server_name``, ``verify``,
        and ``ca_file`` entries.

    Outputs:
      - None; logs but otherwise ignores transport errors.

    Notes:
      - Only 'tcp' and 'dot' transports are supported. Any transport other than
        'dot' is treated as plain TCP.
    """
    from foghorn.utils import dns_names

    apex = dns_names.normalize_name(zone_apex)
    if not apex:
        return

    host = str(target.get("host", ""))
    if not host:
        return
    try:
        port = int(target.get("port", 53))
    except Exception:  # pragma: no cover - defensive
        port = 53
    try:
        timeout_ms = int(target.get("timeout_ms", 2000))
    except Exception:  # pragma: no cover - defensive
        timeout_ms = 2000

    transport = str(target.get("transport", "tcp") or "tcp").lower()
    server_name = target.get("server_name")
    verify_flag = bool(target.get("verify", True))
    ca_file = target.get("ca_file")

    qname = apex + "."
    try:
        notify_msg = DNSRecord.question(qname, qtype="SOA")
        notify_msg.header.opcode = OPCODE.NOTIFY
    except Exception:  # pragma: no cover - defensive
        return

    wire = notify_msg.pack()

    try:
        if transport == "dot":
            dot_query(
                host,
                port,
                wire,
                server_name=str(server_name) if server_name is not None else None,
                verify=bool(verify_flag),
                ca_file=str(ca_file) if ca_file is not None else None,
                connect_timeout_ms=timeout_ms,
                read_timeout_ms=timeout_ms,
            )
        else:
            tcp_query(
                host,
                port,
                wire,
                connect_timeout_ms=timeout_ms,
                read_timeout_ms=timeout_ms,
            )
    except Exception:  # pragma: no cover - defensive logging only
        logger.warning(
            "ZoneRecords: NOTIFY send to %s:%d via %s failed for zone %s",
            host,
            port,
            transport,
            apex,
            exc_info=True,
        )


def send_notify_for_zones(
    plugin: object,
    zone_apexes: List[str],
) -> None:
    """Brief: Send DNS NOTIFY for each changed zone to configured targets.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - zone_apexes: List of zone apex names whose data changed.

    Outputs:
      - None; best-effort fire-and-forget NOTIFY sends.

    Notes:
      - Uses statically configured targets from ``plugin._axfr_notify_static_targets`` only.
      - Applies destination policy checks, self-loop suppression, and per-target throttling.
    """
    if not zone_apexes:
        return

    static_targets: List[Dict[str, object]] = list(
        getattr(plugin, "_axfr_notify_static_targets", []) or []
    )

    for apex in zone_apexes:
        from foghorn.utils import dns_names

        zone_norm = dns_names.normalize_name(apex)
        if not zone_norm:
            continue

        if not static_targets:
            continue

        for target in static_targets:
            if not _target_is_allowlisted(plugin, target):
                logger.warning(
                    "ZoneRecords: blocked NOTIFY target not in allowlist for zone %s: %r",
                    zone_norm,
                    target,
                )
                continue
            if _is_local_notify_target(target):
                logger.info(
                    "ZoneRecords: skipping NOTIFY self-loop target for zone %s: %r",
                    zone_norm,
                    target,
                )
                continue

            if not bool(
                getattr(plugin, "_axfr_notify_allow_private_targets", False)
            ) and _target_has_disallowed_ip(target):
                logger.warning(
                    "ZoneRecords: blocked NOTIFY target with non-public address for zone %s: %r",
                    zone_norm,
                    target,
                )
                continue

            if not _should_send_notify(plugin, target):
                logger.info(
                    "ZoneRecords: throttled NOTIFY target for zone %s: %r",
                    zone_norm,
                    target,
                )
                continue

            try:
                send_notify_to_target(zone_norm, target)
            except Exception:  # pragma: no cover - defensive logging only
                logger.warning(
                    "ZoneRecords: failed to send NOTIFY for zone %s to target %r",
                    zone_norm,
                    target,
                    exc_info=True,
                )


def schedule_delayed_notify(
    zone_apex: str,
    target: Dict[str, object],
    delay_s: float,
) -> None:
    """Brief: Schedule a delayed DNS NOTIFY with per-target deduplication.

    Inputs:
      - zone_apex: Zone apex name.
      - target: Target mapping as accepted by send_notify_to_target.
      - delay_s: Delay in seconds before sending NOTIFY.

    Outputs:
      - None; starts/cancels background timers.
    """
    if delay_s <= 0.0:
        try:
            send_notify_to_target(zone_apex, target)
        except Exception:  # pragma: no cover - defensive logging only
            logger.warning(
                "ZoneRecords: failed to send immediate scheduled NOTIFY for %s",
                zone_apex,
                exc_info=True,
            )
        return

    zone_key = str(zone_apex).strip().lower().rstrip(".")
    timer_key = (zone_key, _target_key(target))

    def _cb() -> None:
        with _PENDING_NOTIFY_TIMERS_LOCK:
            _PENDING_NOTIFY_TIMERS.pop(timer_key, None)
        try:
            send_notify_to_target(zone_apex, target)
        except Exception:  # pragma: no cover - defensive logging only
            logger.warning(
                "ZoneRecords: failed to send delayed NOTIFY for %s",
                zone_apex,
                exc_info=True,
            )

    timer = threading.Timer(float(delay_s), _cb)
    timer.daemon = True
    with _PENDING_NOTIFY_TIMERS_LOCK:
        existing = _PENDING_NOTIFY_TIMERS.get(timer_key)
        if existing is not None:
            try:
                existing.cancel()
            except Exception:
                pass
        _PENDING_NOTIFY_TIMERS[timer_key] = timer
    timer.start()
