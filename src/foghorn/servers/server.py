"""Core DNS server orchestration and transport/failover helper utilities."""

import ipaddress
import logging
import random  # noqa: F401
import threading
from typing import Any

from dnslib import (  # noqa: F401  (re-exported for udp_server._ensure_edns)
    EDNS0,
    OPCODE,
    QTYPE,
    RCODE,
    RR,
    DNSHeader,
    DNSRecord,
    EDNSOption,
)

from foghorn.plugins.resolve import base as plugin_base  # noqa: F401
from foghorn.plugins.resolve.base import PluginContext, PluginDecision  # noqa: F401
from foghorn.plugins.resolve.zone_records import (
    _client_allowed_for_axfr,  # noqa: F401
    iter_axfr_messages,  # noqa: F401
)
from foghorn.servers.recursive_resolver import RecursiveResolver  # noqa: F401
from foghorn.servers.transports.dot import DoTError, get_dot_pool
from foghorn.servers.transports.tcp import (
    TCPError,
    get_tcp_pool,
    tcp_query,
)
from foghorn.utils.register_caches import registered_lru_cache

from .dns_runtime_state import DNSRuntimeState  # noqa: F401
from .edns_utils import (
    synthesize_ecs_from_client_ip,
)
from .server_failover import (
    _UPSTREAM_SKIP_LOCK,  # noqa: F401
    _UPSTREAM_SKIP_WARNED,  # noqa: F401
    _reset_upstream_skip_warning,  # noqa: F401
    _send_query_with_failover_impl,
    _upstream_key_for_skip_warning,  # noqa: F401
    _warn_upstream_skip_once,  # noqa: F401
)
from .server_opcode import _handle_non_query_opcode, _ResolveCoreResult
from .server_resolve_cache import _try_cache_hit
from .server_resolve_context import (  # noqa: F401
    ResolutionContext,
    _build_handler_from_snapshot,
    _finish_early_result,
)
from .server_resolve_enrich import (
    _apply_ecs_processing,
    _apply_search_domain_qualification,
)
from .server_resolve_finalize import _finalize_resolved_response
from .server_resolve_gates import (
    _handle_dns_cookies,
    _handle_local_blocked,
    _handle_refuse_any,
    _handle_tsig,
)
from .server_resolve_plugins import _run_post_plugins, _run_pre_plugins
from .server_resolve_upstream import _resolve_upstream
from .server_response_utils import (  # noqa: F401
    _attach_ede_option,
    _bind_response_cookie_to_request,
    _build_badcookie_response,
    _classify_request_cookie,
    _compute_negative_ttl,
    _echo_client_edns,
    _ensure_edns_request,
    _set_response_id,
    _strip_response_cookie_options,
    compute_effective_ttl,
)
from .server_runtime import DNSServer  # noqa: F401
from .server_upstream_health import _UPSTREAM_HEALTH, _UpstreamHealth  # noqa: F401

logger = logging.getLogger("foghorn.server")


# Thread-local flag used to bypass cache lookups when performing background
# refresh queries. When bypass_cache is True, _resolve_core skips the cache
# hit path and always treats the query as a miss.
_CACHE_LOCAL = threading.local()

_BG_LOCK = threading.Lock()
# Coalescing set for background cache refresh tasks (keyed by the original
# query wire bytes). This prevents redundant upstream work when multiple clients
# ask the same question around the same time.
_BG_CACHE_INFLIGHT: set[bytes] = set()
_RFC1918_V4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_DNSSEC_SEARCH_QUALIFICATION_EXCLUDED_QTYPES: frozenset[int] = frozenset(
    int(code)
    for code in (
        getattr(QTYPE, "DS", 43),
        getattr(QTYPE, "DNSKEY", 48),
        getattr(QTYPE, "RRSIG", 46),
        getattr(QTYPE, "NSEC", 47),
        getattr(QTYPE, "NSEC3", 50),
        getattr(QTYPE, "NSEC3PARAM", 51),
        getattr(QTYPE, "CDS", 59),
        getattr(QTYPE, "CDNSKEY", 60),
    )
)


def _qtype_label_for_stats(qtype: object) -> str:
    """Brief: Return a bounded qtype label for stats and query-log aggregation.

    Inputs:
      - qtype: Raw DNS qtype value (typically an integer from dnslib).

    Outputs:
      - str: Canonical qtype name when known, otherwise ``UNKNOWN``.

    Notes:
      - Unknown numeric qtypes are collapsed to ``UNKNOWN`` so untrusted query
        traffic cannot create unbounded qtype-cardinality in stats keys.
    """

    try:
        qtype_num = int(qtype)
    except Exception:
        return "UNKNOWN"

    try:
        return str(QTYPE[qtype_num])
    except Exception:
        return "UNKNOWN"


@registered_lru_cache(maxsize=2048)
def _is_rfc1918_ptr_query_name(qname: str) -> bool:
    """Brief: Determine whether qname is an IPv4 PTR under RFC1918 space.

    Inputs:
      - qname: Lowercase owner name with no trailing dot.

    Outputs:
      - bool: True when qname is a full IPv4 in-addr.arpa PTR owner for
        10/8, 172.16/12, or 192.168/16.
    """

    labels = str(qname or "").split(".")
    if len(labels) != 6:
        return False
    if labels[-2:] != ["in-addr", "arpa"]:
        return False

    octets = labels[:-2]
    try:
        if not all(0 <= int(part) <= 255 for part in octets):
            return False
    except Exception:
        return False

    try:
        addr = ipaddress.IPv4Address(".".join(reversed(octets)))
    except ValueError:
        return False

    return any(addr in network for network in _RFC1918_V4_NETWORKS)


@registered_lru_cache(maxsize=4096)
def _is_forward_local_blocked_query(qname: str, qtype: int) -> bool:
    """Brief: Determine whether forward_local gate should block this query.

    Inputs:
      - qname: Lowercase owner name with no trailing dot.
      - qtype: Numeric DNS QTYPE value.

    Outputs:
      - bool: True when qname is `.local`/`local` or a PTR in RFC1918 space.
    """

    if qname.endswith(".local") or qname == "local":
        return True
    return qtype == QTYPE.PTR and _is_rfc1918_ptr_query_name(qname)


@registered_lru_cache(maxsize=4096)
def _parse_trusted_ecs_network(cidr_text: str) -> ipaddress._BaseNetwork | None:
    """Brief: Parse a trusted ECS CIDR string into an ipaddress network object.

    Inputs:
      - cidr_text: CIDR text from runtime ECS trust configuration.

    Outputs:
      - ipaddress network object when valid, otherwise None.
    """

    try:
        text = str(cidr_text or "").strip()
    except Exception:
        return None
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _is_listener_trusted_for_ecs(
    listener: str | None,
    secure: bool | None,
    trusted_listeners: list[str],
) -> bool:
    """Brief: Determine whether inbound listener metadata qualifies ECS as trusted.

    Inputs:
      - listener: Logical listener name for the current query.
      - secure: Optional transport security flag.
      - trusted_listeners: Runtime allowlist of trusted listener names.

    Outputs:
      - bool: True when listener/secure metadata indicates a trusted source.
    """

    normalized = {
        str(value).strip().lower()
        for value in (trusted_listeners or [])
        if str(value).strip()
    }
    if not normalized:
        return False

    listener_name = str(listener or "").strip().lower()
    if listener_name:
        return listener_name in normalized

    if secure is True:
        return "dot" in normalized or "doh" in normalized
    if secure is False:
        return "udp" in normalized or "tcp" in normalized
    return False


def _is_source_ip_trusted_for_ecs(client_ip: str, trusted_cidrs: list[str]) -> bool:
    """Brief: Determine whether transport source IP is in trusted ECS CIDRs.

    Inputs:
      - client_ip: Transport source IP text.
      - trusted_cidrs: Runtime allowlist CIDRs for trusted inbound ECS.

    Outputs:
      - bool: True when client_ip belongs to any trusted CIDR.
    """

    if not trusted_cidrs:
        return False
    try:
        source_ip = ipaddress.ip_address(str(client_ip or "").strip())
    except Exception:
        return False

    for cidr_text in trusted_cidrs:
        network = _parse_trusted_ecs_network(str(cidr_text))
        if network is None:
            continue
        try:
            if source_ip in network:
                return True
        except Exception:
            continue
    return False


def _synthesize_ecs_for_source_ip(
    client_ip: str,
    *,
    source_prefix_v4: int,
    source_prefix_v6: int,
    scope_prefix_v4: int,
    scope_prefix_v6: int,
) -> dict[str, Any] | None:
    """Brief: Synthesize an ECS mapping from transport source IP.

    Inputs:
      - client_ip: Transport source IP text.
      - source_prefix_v4/v6: ECS source-prefix values for synthesis.
      - scope_prefix_v4/v6: ECS scope-prefix values for synthesis.

    Outputs:
      - ECS mapping dict when source IP is valid; otherwise None.
    """

    try:
        source_ip = ipaddress.ip_address(str(client_ip or "").strip())
    except Exception:
        return None

    if int(source_ip.version) == 4:
        scope_prefix = max(0, min(32, int(scope_prefix_v4)))
    else:
        scope_prefix = max(0, min(128, int(scope_prefix_v6)))

    return synthesize_ecs_from_client_ip(
        str(source_ip),
        ipv4_prefix=int(source_prefix_v4),
        ipv6_prefix=int(source_prefix_v6),
        scope_prefix=int(scope_prefix),
    )


def _build_request_result_meta(
    *,
    source_ip: str,
    effective_target_ip: str,
    listener: str | None,
    secure: bool | None,
    inbound_ecs: dict[str, Any] | None,
    inbound_ecs_trusted: bool,
    outbound_ecs: dict[str, Any] | None,
    ecs_cache_bypass: bool,
) -> dict[str, Any]:
    """Brief: Build per-query source/ECS metadata for query_log result payloads.

    Inputs:
      - source_ip: Transport source IP (client_ip).
      - effective_target_ip: Trust-aware targeting IP used by plugins.
      - listener: Optional listener name.
      - secure: Optional transport security flag.
      - inbound_ecs: Parsed inbound ECS option (if present).
      - inbound_ecs_trusted: Whether inbound ECS was trusted.
      - outbound_ecs: ECS mapping applied to upstream query (if any).
      - ecs_cache_bypass: Whether ECS context bypassed cache lookup/storage.

    Outputs:
      - dict: Metadata safe to merge into result context payloads.
    """

    meta: dict[str, Any] = {
        "source_ip": str(source_ip or ""),
        "effective_target_ip": str(effective_target_ip or source_ip or ""),
    }
    if listener is not None:
        meta["listener"] = listener
    if secure is not None:
        meta["secure"] = bool(secure)

    ecs_meta: dict[str, Any] = {}
    if inbound_ecs is not None:
        ecs_meta["inbound"] = dict(inbound_ecs)
        ecs_meta["inbound_trusted"] = bool(inbound_ecs_trusted)
    if outbound_ecs is not None:
        ecs_meta["outbound"] = dict(outbound_ecs)
    if ecs_cache_bypass:
        ecs_meta["cache_bypass"] = True
    if ecs_meta:
        meta["ecs"] = ecs_meta

    return meta


# Cache of pre/post plugin ordering to avoid sorting on every query.
_PLUGIN_ORDER_LOCK = threading.Lock()
# Keyed by (kind, token). kind is 'snap' (token=generation) or 'state'
# (token=id(plugins_list)).
_PLUGIN_ORDER_CACHE: dict[tuple[str, int], tuple[list[object], list[object]]] = {}
_PLUGIN_ORDER_CACHE_MAX_SNAP_GENERATIONS = 32
_PLUGIN_ORDER_CACHE_MAX_STATE_KEYS = 64


def _prune_plugin_order_cache_locked() -> None:
    """Brief: Prune plugin-order cache keys to keep bounded memory usage.

    Inputs:
      - None.

    Outputs:
      - None; mutates _PLUGIN_ORDER_CACHE in place.

    Notes:
      - Keeps only recent runtime snapshot generations (kind='snap').
      - Keeps a bounded number of DNSRuntimeState list-id entries (kind='state').
      - Caller must hold _PLUGIN_ORDER_LOCK.
    """

    snap_tokens = sorted(
        token for (kind, token) in _PLUGIN_ORDER_CACHE if kind == "snap"
    )
    snap_overflow = len(snap_tokens) - int(_PLUGIN_ORDER_CACHE_MAX_SNAP_GENERATIONS)
    if snap_overflow > 0:
        min_keep_token = int(snap_tokens[snap_overflow])
        for key in list(_PLUGIN_ORDER_CACHE.keys()):
            if key[0] == "snap" and int(key[1]) < min_keep_token:
                _PLUGIN_ORDER_CACHE.pop(key, None)

    state_keys = [key for key in _PLUGIN_ORDER_CACHE if key[0] == "state"]
    state_overflow = len(state_keys) - int(_PLUGIN_ORDER_CACHE_MAX_STATE_KEYS)
    if state_overflow > 0:
        for key in state_keys[:state_overflow]:
            _PLUGIN_ORDER_CACHE.pop(key, None)


def _get_ordered_plugins(
    *,
    plugins: list[object],
    token_kind: str,
    token: int,
) -> tuple[list[object], list[object]]:
    """Brief: Return pre/post plugin lists ordered by priority with caching.

    Inputs:
      - plugins: Current plugin instances.
      - token_kind: 'snap' for runtime snapshots or 'state' for DNSRuntimeState.
      - token: Generation number or a stable id() for the plugins list.

    Outputs:
      - (pre_plugins, post_plugins) ordered lists.

    Notes:
      - This is hot-path sensitive; it avoids O(n log n) sorting on every query.
      - For snapshots we key by generation; for DNSRuntimeState by id(list).
    """
    normalized_kind = "snap" if str(token_kind) == "snap" else "state"
    cache_key = (normalized_kind, int(token))
    with _PLUGIN_ORDER_LOCK:
        cached = _PLUGIN_ORDER_CACHE.get(cache_key)
        if cached is not None:
            return cached

    pre = sorted(plugins, key=lambda p: getattr(p, "pre_priority", 50))
    post = sorted(plugins, key=lambda p: getattr(p, "post_priority", 50))

    with _PLUGIN_ORDER_LOCK:
        _PLUGIN_ORDER_CACHE[cache_key] = (pre, post)
        _prune_plugin_order_cache_locked()

    return pre, post


def _bg_submit(key: object, fn) -> bool:
    """Brief: Submit a bounded background task with best-effort coalescing.

    Inputs:
      - key: Hashable identifier for coalescing (e.g., zone name or (query, ip)).
      - fn: Zero-arg callable to execute.

    Outputs:
      - bool: True when accepted for execution, False when dropped/rejected.

    Notes:
      - Uses bg_executor admission control to bound outstanding tasks. When
        capacity is exhausted, the task is dropped.
    """

    try:
        from .bg_executor import submit_bg_executor_task

        _ = key
        future = submit_bg_executor_task(fn)
        return future is not None
    except Exception:
        logger.debug("Failed to submit background task", exc_info=True)
        return False


def _record_suppressed_query_log_drop_candidate(
    stats_obj: object,
    *,
    rcode: str | None,
    status: str | None,
) -> None:
    """Brief: Forward suppressed query-log candidates to stats drop accounting.

    Inputs:
      - stats_obj: Stats collector instance or compatible object.
      - rcode: Optional DNS response code for the suppressed row.
      - status: Optional query status for the suppressed row.

    Outputs:
      - None; best-effort forwarding only.
    """

    try:
        handler = getattr(stats_obj, "record_suppressed_query_log_drop_candidate", None)
    except Exception:
        return
    if not callable(handler):
        return
    try:
        handler(rcode=rcode, status=status)
    except Exception:
        pass


def _schedule_notify_axfr_refresh(zone_name: str, upstream: dict) -> None:
    """Backward-compat wrapper for ZoneRecords-owned NOTIFY refresh scheduling."""
    from foghorn.plugins.resolve.zone_records import (
        _schedule_notify_axfr_refresh as _impl,
    )

    _impl(zone_name, upstream)


def _schedule_cache_refresh(data: bytes, client_ip: str) -> None:
    """Brief: Schedule a background cache refresh for a given query.

    Inputs:
      - data: Original wire-format DNS query bytes.
      - client_ip: Client IP string used when reissuing the query (typically
        the same as the original requester so stats attribution is consistent).

    Outputs:
      - None; best-effort background refresh that bypasses cache on the next
        resolve_query_bytes() call for this thread.
    """

    def _worker() -> None:
        try:
            _CACHE_LOCAL.bypass_cache = True
            try:
                # Use the shared resolver so cache, plugins, and stats are all
                # kept consistent with normal query handling.
                resolve_query_bytes(data, client_ip)
            finally:
                _CACHE_LOCAL.bypass_cache = False
        except Exception:
            # Background refresh failures must never impact the caller; log
            # at debug level only.
            logger.debug("Cache refresh failed", exc_info=True)

    # Coalesce refreshes per query (not per client) to prevent redundant work.
    key = bytes(data)
    with _BG_LOCK:
        if key in _BG_CACHE_INFLIGHT:
            return
        _BG_CACHE_INFLIGHT.add(key)

    def _wrapped() -> None:
        try:
            _worker()
        finally:
            with _BG_LOCK:
                _BG_CACHE_INFLIGHT.discard(key)

    try:
        submit_result = _bg_submit(
            key, _wrapped
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        submitted = submit_result is not False
    except (
        Exception
    ):  # pragma: no cover - defensive/metrics path excluded from coverage
        submitted = False
    if not submitted:
        with _BG_LOCK:
            _BG_CACHE_INFLIGHT.discard(key)
        logger.debug("Failed to schedule cache refresh task")

    # Periodic upstream health cleanup can be called via DNSUDPHandler._cleanup_upstream_health


@registered_lru_cache(maxsize=1024)
def _resolve_notify_sender_upstream(sender_ip: str) -> dict | None:
    """Backward-compat wrapper for ZoneRecords-owned NOTIFY sender lookup."""
    from foghorn.plugins.resolve.zone_records import (
        _resolve_notify_sender_upstream as _impl,
    )

    return _impl(sender_ip)


def send_query_with_failover(
    query: DNSRecord,
    upstreams: list[dict],
    timeout_ms: int,
    qname: str,
    qtype: int,
    max_concurrent: int = 1,
) -> tuple[bytes | None, dict | None, str]:
    """Compatibility wrapper preserving server-module patch points for transports.

    Inputs:
      - query: DNS request record to forward.
      - upstreams: Ordered list of upstream endpoint mappings.
      - timeout_ms: Per-upstream timeout budget in milliseconds.
      - qname: Query owner name (for logging context).
      - qtype: Query type code (for logging context).
      - max_concurrent: Maximum number of parallel upstream attempts.

    Outputs:
      - (response_wire, used_upstream, reason) tuple from failover logic.
    """
    return _send_query_with_failover_impl(
        query,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=max_concurrent,
        get_dot_pool_fn=get_dot_pool,
        get_tcp_pool_fn=get_tcp_pool,
        tcp_query_fn=tcp_query,
        dot_error_cls=DoTError,
        tcp_error_cls=TCPError,
    )


# Compatibility re-exports are imported above to preserve legacy server-module
# patch/import points used by tests and plugin code.


def _pack_minimal_dns_response_header(query_wire: bytes, rcode: int) -> bytes:
    """Brief: Construct a minimal DNS response header without parsing.

    Inputs:
      - query_wire: Original request bytes (may be malformed/short).
      - rcode: Integer response code (0-15).

    Outputs:
      - bytes: 12-byte DNS response header with QR=1 and RCODE set.

    Notes:
      - Intended only as a last-resort safe fallback when dnslib parsing/packing
        cannot be trusted.
      - Preserves the request transaction ID when present.
      - Mirrors the RD bit from the request header when present.
    """

    try:
        rid = int.from_bytes(query_wire[0:2], "big") if len(query_wire) >= 2 else 0
    except Exception:
        rid = 0

    try:
        req_flags = (
            int.from_bytes(query_wire[2:4], "big") if len(query_wire) >= 4 else 0
        )
    except Exception:
        req_flags = 0

    rd = bool(req_flags & 0x0100)

    try:
        rc = int(rcode) & 0xF
    except Exception:
        rc = int(RCODE.SERVFAIL) & 0xF

    # QR=1, RA=1, RD mirrored.
    flags = 0x8000
    flags |= 0x0080
    if rd:
        flags |= 0x0100
    flags |= rc

    # QD/AN/NS/AR all zero.
    return (
        int(rid).to_bytes(2, "big")
        + int(flags).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
    )


def _sanitize_upstream_url(url: str) -> str:
    """Brief: Remove credentials (userinfo) from a URL for safe logging.

    Inputs:
      - url: Upstream URL string (may include embedded credentials).

    Outputs:
      - str: URL with any username/password removed from netloc.

    Example:
      >>> _sanitize_upstream_url('https://u:p@example.com/dns-query')
      'https://example.com/dns-query'
    """

    raw = str(url or "").strip()
    if not raw:
        return ""

    try:
        from urllib.parse import urlparse, urlunparse

        p = urlparse(raw)
        host = p.hostname or ""
        port = p.port
        if port is not None:
            netloc = f"{host}:{int(port)}" if host else f":{int(port)}"
        else:
            netloc = host
        return urlunparse(p._replace(netloc=netloc))
    except Exception:
        return raw


def _resolve_plugin_label(decision: object, plugin: object) -> str:
    """Brief: Resolve a short, stable label for per-plugin stats.

    Inputs:
      - decision: PluginDecision (or similar) that may carry plugin_label/plugin.
      - plugin: Plugin instance that produced the decision.

    Outputs:
      - str: Lowercase label suffix (no prefix), or '' when unavailable.
    """

    label_suffix = getattr(decision, "plugin_label", None)
    if not label_suffix:
        plugin_cls = getattr(decision, "plugin", None) or type(plugin)
        plugin_name = getattr(plugin_cls, "__name__", "plugin").lower()
        aliases: list[str] = []
        try:
            aliases = list(getattr(plugin_cls, "get_aliases", list)())
        except Exception:
            aliases = []
        if aliases:
            label_suffix = str(aliases[0]).strip().lower()
        else:
            label_suffix = plugin_name

    return str(label_suffix).strip().lower() if label_suffix else ""


def _classify_dnssec_status_for_response(
    handler: object,
    qname: str,
    qtype: int,
    response_wire: bytes,
) -> str | None:
    """Brief: Classify DNSSEC status for a prepared response wire payload.

    Inputs:
      - handler: Runtime handler/snapshot-like object carrying DNSSEC settings.
      - qname: Query owner name text without trailing dot.
      - qtype: Numeric DNS QTYPE value.
      - response_wire: Wire-format DNS response bytes to classify.

    Outputs:
      - Optional[str]: DNSSEC status label, or None on failure/disabled mode.
    """

    try:
        from ..dnssec.dnssec_validate import classify_dnssec_status

        mode = str(getattr(handler, "dnssec_mode", "ignore"))
        validation = str(getattr(handler, "dnssec_validation", "upstream_ad"))
        edns_udp_payload = int(getattr(handler, "edns_udp_payload", 1232))
        return classify_dnssec_status(
            dnssec_mode=mode,
            dnssec_validation=validation,
            qname_text=qname,
            qtype_num=qtype,
            response_wire=response_wire,
            udp_payload_size=edns_udp_payload,
        )
    except Exception:
        return None


def _apply_dnssec_ad_bit(
    handler: object,
    dnssec_status: str | None,
    response_wire: bytes,
) -> bytes:
    """Brief: Set/clear AD on a DNS response when dnssec.mode is validate.

    Inputs:
      - handler: Runtime handler/snapshot-like object carrying DNSSEC mode.
      - dnssec_status: Classified DNSSEC status for the response.
      - response_wire: Wire-format DNS response bytes.

    Outputs:
      - bytes: Response wire bytes with AD adjusted when applicable.
    """

    try:
        mode = str(getattr(handler, "dnssec_mode", "ignore")).lower()
    except Exception:
        mode = "ignore"
    if mode != "validate":
        return response_wire

    secure_statuses = {"dnssec_secure", "dnssec_zone_secure", "secure"}
    desired_ad = 1 if str(dnssec_status or "") in secure_statuses else 0

    try:
        msg = DNSRecord.parse(response_wire)
        if int(getattr(msg.header, "ad", 0)) == int(desired_ad):
            return response_wire
        msg.header.ad = int(desired_ad)
        return msg.pack()
    except Exception:
        return response_wire


def _is_signed_authoritative_response(response_wire: bytes) -> bool:
    """Brief: Determine whether a response is authoritative and DNSSEC-signed.

    Inputs:
      - response_wire: Wire-format DNS response bytes.

    Outputs:
      - bool: True when AA=1 and the message carries RRSIG plus answer data.
    """

    try:
        msg = DNSRecord.parse(response_wire)
        if int(getattr(msg.header, "aa", 0)) != 1:
            return False
        rrsets = list(getattr(msg, "rr", []) or [])
        auth_rrsets = list(getattr(msg, "auth", []) or [])
        has_rrsig = any(
            int(getattr(rr, "rtype", 0)) == int(QTYPE.RRSIG)
            for rr in rrsets + auth_rrsets
        )
        has_answer_data = any(
            int(getattr(rr, "rtype", 0)) != int(QTYPE.RRSIG) for rr in rrsets
        )
        return bool(has_rrsig and has_answer_data)
    except Exception:
        return False


def _resolve_core(
    data: bytes,
    client_ip: str,
    listener: str | None = None,
    secure: bool | None = None,
) -> _ResolveCoreResult:
    """Shared resolution pipeline used by UDP and non-UDP callers.

    Inputs:
      - data: Wire-format DNS query bytes.
      - client_ip: Client IP string for plugin context and stats.
      - listener: Optional logical inbound listener/transport identifier.
      - secure: Optional transport security flag.

    Outputs:
      - _ResolveCoreResult with final wire bytes and metadata.
    """
    import time as _time  # Local import to avoid impacting module import time

    try:
        from foghorn.runtime_config import get_runtime_snapshot

        snap = get_runtime_snapshot()
    except Exception:
        snap = None

    handler = _build_handler_from_snapshot(snap)

    stats = getattr(handler, "stats_collector", None)
    t0 = _time.perf_counter() if stats is not None else None
    # Optional EDE info-code/text for logging and metrics when responses carry
    # Extended DNS Errors (RFC 8914). This is populated in specific branches
    # (for example, DNSSEC bogus classification) and mirrored into stats and
    # query_log result payloads when present.
    ede_code_for_logs: int | None = None
    ede_text_for_logs: str | None = None
    request_result_meta = _build_request_result_meta(
        source_ip=str(client_ip or ""),
        effective_target_ip=str(client_ip or ""),
        listener=listener,
        secure=secure,
        inbound_ecs=None,
        inbound_ecs_trusted=False,
        outbound_ecs=None,
        ecs_cache_bypass=False,
    )

    try:
        # Compute opcode from header bits without parsing the full message. This
        # allows us to handle UPDATE messages containing empty RRs (used for
        # prerequisites/deletes) which dnslib cannot parse.
        try:
            if isinstance(data, (bytes, bytearray)) and len(data) >= 4:
                flags = int.from_bytes(data[2:4], "big")
                opcode = (flags >> 11) & 0x0F
            else:
                opcode = 0
        except Exception:
            opcode = 0

        non_query_result = _handle_non_query_opcode(
            opcode=opcode,
            data=data,
            client_ip=client_ip,
            listener=listener,
            secure=secure,
            handler=handler,
        )
        if non_query_result is not None:
            return non_query_result

        req = DNSRecord.parse(data)
        if not getattr(req, "questions", None):
            # QDCOUNT=0 is syntactically valid. Treat it as a format error and
            # reply with a minimal FORMERR without attempting additional parsing.
            wire = _pack_minimal_dns_response_header(data, int(RCODE.FORMERR))
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="FORMERR",
            )

        # Downstream DNS COOKIE (RFC 7873) require_udp short-circuit.
        # Runs before cache/plugins/upstream so invalid UDP cookies are cheap.
        cookie_result = _handle_dns_cookies(
            req=req,
            handler=handler,
            client_ip=client_ip,
            listener=listener,
            stats=stats,
            t0=t0,
        )
        if cookie_result is not None:
            return cookie_result

        # Downstream QUERY TSIG (RFC 2845) gate.
        # After cookies require_udp; before cache/plugins/upstream.
        tsig_ctx, tsig_result = _handle_tsig(
            data=data,
            req=req,
            handler=handler,
            client_ip=client_ip,
            listener=listener,
            stats=stats,
            t0=t0,
            request_result_meta=request_result_meta,
        )
        if tsig_result is not None:
            return tsig_result

        q = req.questions[0]
        # Normalize the parsed qname by stripping the wire/root trailing dot.
        # DNS wire format does not preserve whether the original client input
        # included a textual trailing dot, so qualification decisions should be
        # based on the normalized name.
        qname = str(q.qname).rstrip(".")
        qtype = q.qtype

        # Search-domain qualification and ECS enrichment.
        qname = _apply_search_domain_qualification(
            qname=qname,
            qtype=qtype,
            snap=snap,
            excluded_qtypes=_DNSSEC_SEARCH_QUALIFICATION_EXCLUDED_QTYPES,
        )
        (
            inbound_ecs,
            inbound_ecs_trusted,
            trusted_inbound_ecs,
            outbound_ecs,
            effective_target_ip,
            ecs_cache_bypass,
            request_result_meta,
        ) = _apply_ecs_processing(
            req=req,
            handler=handler,
            client_ip=client_ip,
            listener=listener,
            secure=secure,
            is_listener_trusted_for_ecs=_is_listener_trusted_for_ecs,
            is_source_ip_trusted_for_ecs=_is_source_ip_trusted_for_ecs,
            synthesize_ecs_for_source_ip=_synthesize_ecs_for_source_ip,
            build_request_result_meta=_build_request_result_meta,
        )
        # Preserve TSIG metadata set by the earlier gate when present.
        if tsig_ctx.get("ok"):
            request_result_meta["tsig_ok"] = True
            if tsig_ctx.get("keyname") is not None:
                request_result_meta["tsig_key_name"] = tsig_ctx.get("keyname")

        cache_key = (qname.lower(), qtype)

        # Record query stats (mirrors DNSUDPHandler.handle)
        if stats is not None:
            try:
                from foghorn.servers.resolve_telemetry import (
                    ResolveEvent,
                    ResolveEventKind,
                    telemetry_from_stats,
                )

                qtype_name = _qtype_label_for_stats(qtype)
                telemetry_from_stats(stats).emit(
                    ResolveEvent(
                        kind=ResolveEventKind.QUERY_RECEIVED,
                        client_ip=client_ip,
                        qname=qname,
                        qtype_label=qtype_name,
                        t0=t0,
                        request_result_meta=dict(request_result_meta),
                    )
                )
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        # Optional amplification mitigation: refuse QTYPE ANY (255).
        refuse_result = _handle_refuse_any(
            req=req,
            handler=handler,
            client_ip=client_ip,
            qname=qname,
            qtype=qtype,
            qtype_label_fn=_qtype_label_for_stats,
            stats=stats,
            t0=t0,
            request_result_meta=request_result_meta,
        )
        if refuse_result is not None:
            return refuse_result

        # Pre plugins
        pre_plugins, post_plugins, pre_result = _run_pre_plugins(
            data=data,
            req=req,
            client_ip=client_ip,
            listener=listener,
            secure=secure,
            qname=qname,
            qtype=qtype,
            trusted_inbound_ecs=trusted_inbound_ecs,
            effective_target_ip=effective_target_ip,
            handler=handler,
            snap=snap,
            stats=stats,
            t0=t0,
            request_result_meta=request_result_meta,
            get_ordered_plugins=_get_ordered_plugins,
            resolve_plugin_label=_resolve_plugin_label,
            qtype_label_fn=_qtype_label_for_stats,
            record_suppressed_query_log_drop_candidate=_record_suppressed_query_log_drop_candidate,
            classify_dnssec_status_for_response=_classify_dnssec_status_for_response,
            apply_dnssec_ad_bit=_apply_dnssec_ad_bit,
            is_signed_authoritative_response=_is_signed_authoritative_response,
        )
        if pre_result is not None:
            return pre_result

        # Cache lookup (with optional stale-while-revalidate prefetch).
        cache_hit = _try_cache_hit(
            data=data,
            req=req,
            client_ip=client_ip,
            qname=qname,
            qtype=qtype,
            cache_key=cache_key,
            handler=handler,
            stats=stats,
            t0=t0,
            request_result_meta=request_result_meta,
            tsig_ctx=tsig_ctx,
            ecs_cache_bypass=ecs_cache_bypass,
            cache_local=_CACHE_LOCAL,
            schedule_cache_refresh=_schedule_cache_refresh,
            qtype_label_fn=_qtype_label_for_stats,
        )
        if cache_hit is not None:
            return cache_hit

        # Block forwarding of .local queries and RFC1918 reverse PTRs unless
        # forward_local is True.
        # RFC 6762 reserves .local for mDNS; forwarding to upstream resolvers
        # can cause delays and incorrect answers. RFC1918 reverse PTRs are
        # often locally-served and should follow the same gate.
        local_blocked_result = _handle_local_blocked(
            req=req,
            handler=handler,
            client_ip=client_ip,
            qname=qname,
            qtype=qtype,
            qtype_label_fn=_qtype_label_for_stats,
            is_forward_local_blocked_query=_is_forward_local_blocked_query,
            is_rfc1918_ptr_query_name=_is_rfc1918_ptr_query_name,
            stats=stats,
            t0=t0,
            request_result_meta=request_result_meta,
        )
        if local_blocked_result is not None:
            return local_blocked_result

        reply: bytes | None = None
        used_upstream: dict | None = None
        reason: str | None = None
        upstream_url = ""

        (
            reply,
            used_upstream,
            reason,
            upstream_url,
            upstream_id,
            ede_code_for_logs,
            ede_text_for_logs,
            upstream_early,
        ) = _resolve_upstream(
            req=req,
            data=data,
            client_ip=client_ip,
            qname=qname,
            qtype=qtype,
            handler=handler,
            snap=snap,
            stats=stats,
            t0=t0,
            request_result_meta=request_result_meta,
            ede_code_for_logs=ede_code_for_logs,
            ede_text_for_logs=ede_text_for_logs,
            send_query_with_failover=send_query_with_failover,
            ensure_edns_request=_ensure_edns_request,
            sanitize_upstream_url=_sanitize_upstream_url,
            qtype_label_fn=_qtype_label_for_stats,
        )
        if upstream_early is not None:
            return upstream_early

        # Post plugins
        out, post_early = _run_post_plugins(
            reply=reply,
            req=req,
            client_ip=client_ip,
            listener=listener,
            secure=secure,
            qname=qname,
            qtype=qtype,
            trusted_inbound_ecs=trusted_inbound_ecs,
            effective_target_ip=effective_target_ip,
            post_plugins=post_plugins,
            upstream_id=upstream_id,
            stats=stats,
            record_suppressed_query_log_drop_candidate=_record_suppressed_query_log_drop_candidate,
        )
        if post_early is not None:
            return post_early

        # Cache store, DNSSEC, TSIG/cookie bind, and stats finalize.
        return _finalize_resolved_response(
            out=out,
            req=req,
            client_ip=client_ip,
            qname=qname,
            qtype=qtype,
            cache_key=cache_key,
            handler=handler,
            stats=stats,
            t0=t0,
            request_result_meta=request_result_meta,
            tsig_ctx=tsig_ctx,
            ecs_cache_bypass=ecs_cache_bypass,
            upstream_id=upstream_id,
            upstream_url=upstream_url,
            ede_code_for_logs=ede_code_for_logs,
            ede_text_for_logs=ede_text_for_logs,
            classify_dnssec_status_for_response=_classify_dnssec_status_for_response,
            apply_dnssec_ad_bit=_apply_dnssec_ad_bit,
            is_signed_authoritative_response=_is_signed_authoritative_response,
            qtype_label_fn=_qtype_label_for_stats,
        )
    except Exception as e:
        logger.exception(
            "Unhandled resolver exception (client_ip=%s listener=%s secure=%s query_size=%s)",
            client_ip,
            listener,
            secure,
            len(data) if isinstance(data, (bytes, bytearray)) else "unknown",
        )
        # Outer exception handler: synthesize SERVFAIL and record stats.
        try:
            req = DNSRecord.parse(data)
            r = req.reply()
            r.header.rcode = RCODE.SERVFAIL
            # Echo client EDNS(0) OPT, when present, into this synthetic SERVFAIL,
            # and, when enabled, attach a generic EDE "Other" code so clients
            # can distinguish internal errors from upstream failures.
            _echo_client_edns(req, r)
            ede_code = 0
            ede_text = "internal server error"
            _attach_ede_option(req, r, ede_code, ede_text)  # Other
            wire = _set_response_id(r.pack(), req.header.id)
            if stats is not None:
                try:
                    if hasattr(stats, "record_ede_code"):
                        try:
                            stats.record_ede_code(ede_code)
                        except Exception:  # pragma: no cover - defensive metrics hook
                            pass
                    stats.record_response_rcode("SERVFAIL")
                    # Attempt to recover qname/qtype for logging when present.
                    if getattr(req, "questions", None):
                        q = req.questions[0]
                        qname = str(q.qname).rstrip(".")
                        qtype = q.qtype
                        qtype_name = _qtype_label_for_stats(qtype)
                    else:
                        qname = ""
                        qtype_name = ""
                    result_ctx = {"source": "server", "error": "unhandled_exception"}
                    result_ctx.update(request_result_meta)
                    if qtype_name:
                        stats.record_query_result(
                            client_ip=client_ip,
                            qname=qname,
                            qtype=qtype_name,
                            rcode="SERVFAIL",
                            upstream_id=None,
                            status="error",
                            error=str(e),
                            first=None,
                            result=result_ctx,
                        )
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass
            if stats is not None and t0 is not None:
                try:
                    t1 = _time.perf_counter()
                    stats.record_latency(t1 - t0)
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="SERVFAIL",
            )
        except Exception:
            # Worst-case fallback: never reflect the original query bytes.
            wire = _pack_minimal_dns_response_header(data, int(RCODE.SERVFAIL))
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="SERVFAIL",
            )


def resolve_query_bytes(
    data: bytes,
    client_ip: str,
    *,
    listener: str | None = None,
    secure: bool | None = None,
) -> bytes:
    """Resolve a single DNS wire query and return wire response.

    Inputs:
      - data: Wire-format DNS query bytes.
      - client_ip: String client IP for plugin context, logging, and statistics.
      - listener: Optional logical inbound listener/transport identifier
        ("udp", "tcp", "dot", or "doh").
      - secure: Optional transport security flag (True for TLS-backed
        listeners, False for plain UDP/TCP, None when unspecified).
    Outputs:
      - bytes: Wire-format DNS response.

    This helper reuses DNSUDPHandler's class-level configuration (plugins,
    upstreams, DNSSEC knobs, and optional StatsCollector) so that TCP/DoT/DoH
    and other non-UDP callers share the same behavior and statistics pipeline.

    DNS response caching is provided by `foghorn.plugins.resolve.base.DNS_CACHE`.

    Example:
      >>> resp = resolve_query_bytes(query_bytes, '127.0.0.1')
    """
    return _resolve_core(data, client_ip, listener=listener, secure=secure).wire
