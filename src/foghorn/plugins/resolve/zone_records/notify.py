"""Brief: NOTIFY infrastructure for AXFR-backed zones.

Inputs/Outputs:
  - NOTIFY target tracking, sending, and scheduling for downstream secondaries.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Dict, List

from dnslib import OPCODE, QTYPE, DNSRecord

from foghorn.servers.transports.dot import dot_query
from foghorn.servers.transports.tcp import tcp_query
from foghorn.utils import ip_networks

logger = logging.getLogger(__name__)


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
    """Brief: Resolve a notify target host into IP addresses.

    Inputs:
      - host: Target host (IP literal or DNS name).

    Outputs:
      - set[str] of resolved IP addresses.
    """
    out: set[str] = set()
    text = str(host or "").strip()
    if not text:
        return out
    ip_obj = ip_networks.parse_ip(text)
    if ip_obj is not None:
        out.add(str(ip_obj))
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

    for ip_text in _resolve_target_ips(host):
        if (ip_text, port) in local_eps:
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
    """Brief: Track an AXFR/IXFR client as a potential NOTIFY target.

    Inputs:
      - plugin: ZoneRecords plugin instance with _axfr_notify_* attributes.
      - zone_apex: Normalized zone apex name (lowercase, no trailing dot).
      - client_ip: Source IP address of the AXFR/IXFR client.

    Outputs:
      - None; updates learned NOTIFY targets and may schedule a delayed or
        immediate NOTIFY when axfr_notify_scheduled is configured.
      - When the plugin does not expose an _axfr_notify_lock (unexpected), this
        function is a no-op.
    """
    from foghorn.utils import dns_names

    def _safe_str(value: object) -> str:
        """Brief: Best-effort string conversion with a retry.

        Inputs:
          - value: Any object convertible to string.

        Outputs:
          - str: Converted string or empty string on failure.
        """
        try:
            return str(value)
        except Exception:
            try:
                return str(value)
            except Exception:
                return ""

    zone_norm = dns_names.normalize_name(_safe_str(zone_apex))
    if not zone_norm:
        return
    host = _safe_str(client_ip).strip()
    if not host:
        return

    # Learned targets always use TCP port 53 by default. Operators that need
    # a different port or transport can configure explicit axfr_notify entries.
    target: Dict[str, object] = {
        "host": host,
        "port": 53,
        "timeout_ms": 2000,
        "transport": "tcp",
        "server_name": None,
        "verify": True,
        "ca_file": None,
    }
    key = f"{host}:53/tcp"

    lock = getattr(plugin, "_axfr_notify_lock", None)
    if lock is None:
        return

    with lock:
        per_zone = plugin._axfr_notify_learned.setdefault(zone_norm, {})
        per_zone[key] = target

    # Optionally schedule or immediately send a NOTIFY back to this client.
    delay = getattr(plugin, "_axfr_notify_delay", None)
    if delay is None:
        return

    try:
        delay_f = float(delay)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        delay_f = 0.0

    if delay_f <= 0.0:
        try:
            send_notify_to_target(zone_norm, target)
        except Exception:  # pragma: no cover - defensive logging only
            logger.warning(
                "ZoneRecords: failed to send immediate NOTIFY to %s for zone %s",
                host,
                zone_norm,
                exc_info=True,
            )
    else:
        schedule_delayed_notify(zone_norm, target, delay_f)


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
      - Only "tcp" and "dot" transports are supported. Any transport other than
        "dot" is treated as plain TCP.
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
    # Build a minimal NOTIFY message for the zone SOA.
    try:
        # dnslib's DNSRecord.question expects a qtype mnemonic string (e.g. "SOA"),
        # not a numeric code.
        notify = DNSRecord.question(qname, qtype="SOA")
        notify.header.opcode = OPCODE.NOTIFY
    except Exception:  # pragma: no cover - defensive
        return

    wire = notify.pack()

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
      - Uses both statically configured targets (plugin._axfr_notify_static_targets)
        and learned targets from recent AXFR/IXFR clients (plugin._axfr_notify_learned).
    """
    if not zone_apexes:
        return

    static_targets: List[Dict[str, object]] = list(
        getattr(plugin, "_axfr_notify_static_targets", []) or []
    )

    # Snapshot learned targets under lock so network I/O never holds it.
    learned_snapshot: Dict[str, Dict[str, Dict[str, object]]] = {}
    lock = getattr(plugin, "_axfr_notify_lock", None)
    if lock is not None:
        with lock:
            for zone, targets in plugin._axfr_notify_learned.items():
                learned_snapshot[zone] = dict(targets)
    else:
        raw = getattr(plugin, "_axfr_notify_learned", {}) or {}
        for zone, targets in raw.items():
            if isinstance(targets, dict):
                learned_snapshot[zone] = dict(targets)

    for apex in zone_apexes:
        from foghorn.utils import dns_names

        zone_norm = dns_names.normalize_name(apex)
        if not zone_norm:
            continue

        per_zone_targets: List[Dict[str, object]] = []
        per_zone_targets.extend(static_targets)
        for _key, t in learned_snapshot.get(zone_norm, {}).items():
            per_zone_targets.append(t)

        if not per_zone_targets:
            continue

        for t in per_zone_targets:
            if _is_local_notify_target(t):
                logger.info(
                    "ZoneRecords: skipping NOTIFY self-loop target for zone %s: %r",
                    zone_norm,
                    t,
                )
                continue
            try:
                send_notify_to_target(zone_norm, t)
            except Exception:  # pragma: no cover - defensive logging only
                logger.warning(
                    "ZoneRecords: failed to send NOTIFY for zone %s to target %r",
                    zone_norm,
                    t,
                    exc_info=True,
                )


def schedule_delayed_notify(
    zone_apex: str,
    target: Dict[str, object],
    delay_s: float,
) -> None:
    """Brief: Schedule a delayed DNS NOTIFY for a learned or static target.

    Inputs:
      - zone_apex: Zone apex name.
      - target: Target mapping as accepted by send_notify_to_target.
      - delay_s: Delay in seconds before sending NOTIFY.

    Outputs:
      - None; spawns a background timer when delay is positive.
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

    def _cb() -> None:
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
    timer.start()
