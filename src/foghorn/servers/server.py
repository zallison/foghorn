"""Core DNS server orchestration and transport/failover helper utilities."""

import ipaddress

import logging
import random
import threading
from typing import Dict, List, Optional, Tuple
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

from foghorn.plugins.resolve import base as plugin_base
from foghorn.plugins.resolve.zone_records import (
    _client_allowed_for_axfr,  # noqa: F401
    iter_axfr_messages,  # noqa: F401
)
from foghorn.plugins.resolve.base import PluginContext, PluginDecision
from foghorn.servers.recursive_resolver import RecursiveResolver
from foghorn.servers.transports.dot import DoTError, get_dot_pool  # noqa: F401
from foghorn.servers.transports.tcp import (
    TCPError,
    get_tcp_pool,
    tcp_query,
)  # noqa: F401
from foghorn.utils.register_caches import registered_lru_cache
from .dns_runtime_state import DNSRuntimeState

from .server_opcode import _ResolveCoreResult, _handle_non_query_opcode
from .server_runtime import DNSServer  # noqa: F401
from .server_upstream_health import _UPSTREAM_HEALTH, _UpstreamHealth  # noqa: F401
from .server_failover import (
    _UPSTREAM_SKIP_LOCK,  # noqa: F401
    _UPSTREAM_SKIP_WARNED,  # noqa: F401
    _reset_upstream_skip_warning,  # noqa: F401
    _send_query_with_failover_impl,
    _upstream_key_for_skip_warning,  # noqa: F401
    _warn_upstream_skip_once,  # noqa: F401
)
from .server_response_utils import (
    _attach_ede_option,
    _bind_response_cookie_to_request,
    _compute_negative_ttl,
    _echo_client_edns,
    _ensure_edns_request,  # noqa: F401
    _strip_response_cookie_options,
    _set_response_id,
    compute_effective_ttl,  # noqa: F401
)

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
        token for (kind, token) in _PLUGIN_ORDER_CACHE.keys() if kind == "snap"
    )
    snap_overflow = len(snap_tokens) - int(_PLUGIN_ORDER_CACHE_MAX_SNAP_GENERATIONS)
    if snap_overflow > 0:
        min_keep_token = int(snap_tokens[snap_overflow])
        for key in list(_PLUGIN_ORDER_CACHE.keys()):
            if key[0] == "snap" and int(key[1]) < min_keep_token:
                _PLUGIN_ORDER_CACHE.pop(key, None)

    state_keys = [key for key in _PLUGIN_ORDER_CACHE.keys() if key[0] == "state"]
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
    rcode: Optional[str],
    status: Optional[str],
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


def _schedule_notify_axfr_refresh(zone_name: str, upstream: Dict) -> None:
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
            setattr(_CACHE_LOCAL, "bypass_cache", True)
            try:
                # Use the shared resolver so cache, plugins, and stats are all
                # kept consistent with normal query handling.
                resolve_query_bytes(data, client_ip)
            finally:
                setattr(_CACHE_LOCAL, "bypass_cache", False)
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
def _resolve_notify_sender_upstream(sender_ip: str) -> Optional[Dict]:
    """Backward-compat wrapper for ZoneRecords-owned NOTIFY sender lookup."""
    from foghorn.plugins.resolve.zone_records import (
        _resolve_notify_sender_upstream as _impl,
    )

    return _impl(sender_ip)


def send_query_with_failover(
    query: DNSRecord,
    upstreams: List[Dict],
    timeout_ms: int,
    qname: str,
    qtype: int,
    max_concurrent: int = 1,
) -> Tuple[Optional[bytes], Optional[Dict], str]:
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
            aliases = list(getattr(plugin_cls, "get_aliases", lambda: [])())
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
) -> Optional[str]:
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
    dnssec_status: Optional[str],
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
    listener: Optional[str] = None,
    secure: Optional[bool] = None,
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
    from types import SimpleNamespace

    handler = DNSRuntimeState
    try:
        from foghorn.runtime_config import get_runtime_snapshot

        snap = get_runtime_snapshot()
    except Exception:
        snap = None

    if snap is not None:
        handler = SimpleNamespace(
            stats_collector=snap.stats_collector,
            plugins=list(snap.plugins or []),
            upstream_addrs=list(snap.upstream_addrs or []),
            upstream_backup_addrs=list(snap.upstream_backup_addrs or []),
            upstream_health=snap.upstream_health,
            timeout_ms=int(snap.timeout_ms),
            upstream_strategy=str(snap.upstream_strategy or "failover").lower(),
            upstream_max_concurrent=max(1, int(snap.upstream_max_concurrent or 1)),
            resolver_mode=str(snap.resolver_mode or "forward").lower(),
            recursive_max_depth=int(snap.recursive_max_depth),
            recursive_timeout_ms=int(snap.recursive_timeout_ms),
            recursive_per_try_timeout_ms=int(snap.recursive_per_try_timeout_ms),
            dnssec_mode=str(snap.dnssec_mode or "ignore"),
            dnssec_validation=str(snap.dnssec_validation or "upstream_ad"),
            edns_udp_payload=max(512, int(snap.edns_udp_payload)),
            enable_ede=bool(snap.enable_ede),
            forward_local=bool(snap.forward_local),
            min_cache_ttl=max(0, int(snap.min_cache_ttl)),
            cache_prefetch_enabled=bool(snap.cache_prefetch_enabled),
            cache_prefetch_min_ttl=max(0, int(snap.cache_prefetch_min_ttl)),
            cache_prefetch_max_ttl=max(0, int(snap.cache_prefetch_max_ttl)),
            cache_prefetch_refresh_before_expiry=max(
                0.0, float(snap.cache_prefetch_refresh_before_expiry)
            ),
            cache_prefetch_allow_stale_after_expiry=max(
                0.0, float(snap.cache_prefetch_allow_stale_after_expiry)
            ),
            _upstream_id=DNSRuntimeState._upstream_id,
            _ensure_edns=getattr(DNSRuntimeState, "_ensure_edns", None),
        )

    stats = getattr(handler, "stats_collector", None)
    t0 = _time.perf_counter() if stats is not None else None
    # Optional EDE info-code/text for logging and metrics when responses carry
    # Extended DNS Errors (RFC 8914). This is populated in specific branches
    # (for example, DNSSEC bogus classification) and mirrored into stats and
    # query_log result payloads when present.
    ede_code_for_logs: Optional[int] = None
    ede_text_for_logs: Optional[str] = None

    try:
        rcode_name = "UNKNOWN"

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

        q = req.questions[0]
        # Normalize the parsed qname by stripping the wire/root trailing dot.
        # DNS wire format does not preserve whether the original client input
        # included a textual trailing dot, so qualification decisions should be
        # based on the normalized name.
        qname = str(q.qname).rstrip(".")
        qtype = q.qtype

        # Search-domain qualification: when a search domain is configured and
        # the qname matches one of the configured gates, append the suffix.
        # Applied before cache key, stats, plugins, and forwarding so everything
        # downstream sees the effective (qualified) name consistently.
        try:
            if snap is not None:
                _search = str(getattr(snap, "search_domain", "") or "")
                if _search:
                    try:
                        _qtype_num = int(qtype)
                    except Exception:
                        _qtype_num = int(qtype or 0)
                    if _qtype_num in _DNSSEC_SEARCH_QUALIFICATION_EXCLUDED_QTYPES:
                        _search = ""
                if _search:
                    from foghorn.utils.dns_names import should_qualify, qualify_name

                    _qual = should_qualify(
                        qname,
                        qualify_single_label=bool(
                            getattr(snap, "qualify_single_label", True)
                        ),
                        qualify_non_proper_tld=getattr(
                            snap, "qualify_non_proper_tld", False
                        ),
                        non_proper_tld_mode=str(
                            getattr(snap, "non_proper_tld_mode", "suffix") or "suffix"
                        ),
                    )
                    if _qual:
                        _qualified = qualify_name(qname, _search)
                        if _qualified is not None:
                            qname = _qualified
        except (
            Exception
        ):  # pragma: no cover - defensive: qualification failure is non-fatal
            pass

        cache_key = (qname.lower(), qtype)

        # Record query stats (mirrors DNSUDPHandler.handle)
        if stats is not None:
            try:
                qtype_name = _qtype_label_for_stats(qtype)
                stats.record_query(client_ip, qname, qtype_name)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        # Pre plugins
        ctx = PluginContext(client_ip=client_ip, listener=listener, secure=secure)
        # Attach qname so BasePlugin domain-targeting helpers can use it.
        try:
            ctx.qname = qname
        except Exception:  # pragma: no cover - defensive
            pass
        plugins_list = list(getattr(handler, "plugins", []) or [])
        if snap is not None and hasattr(snap, "generation"):
            pre_plugins, post_plugins = _get_ordered_plugins(
                plugins=plugins_list,
                token_kind="snap",
                token=int(getattr(snap, "generation", 0) or 0),
            )
        else:
            pre_plugins, post_plugins = _get_ordered_plugins(
                plugins=plugins_list,
                token_kind="state",
                token=int(id(getattr(handler, "plugins", plugins_list))),
            )

        for p in pre_plugins:
            # Skip plugins that do not target this qtype when they opt in via
            # BasePlugin.target_qtypes.
            try:
                if hasattr(p, "targets_qtype") and not p.targets_qtype(
                    qtype
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    continue
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                # On failure, fall back to running the plugin to avoid hiding
                # errors behind targeting decisions.
                pass

            try:
                decision = p.pre_resolve(qname, qtype, data, ctx)
            except Exception:
                logger.error(
                    "pre_resolve failed for plugin %s", type(p).__name__, exc_info=True
                )
                decision = None
            if isinstance(decision, PluginDecision):
                if decision.action == "drop":
                    if stats is not None:
                        _record_suppressed_query_log_drop_candidate(
                            stats,
                            rcode="DROP",
                            status="drop",
                        )
                    # Pre-plugin timeout/drop: return sentinel empty wire so UDP
                    # handlers and othefoghorn.servers.transports can choose not to reply.
                    return _ResolveCoreResult(
                        wire=b"",
                        dnssec_status=None,
                        upstream_id=None,
                        rcode_name="DROP",
                    )
                if decision.action == "deny":
                    # NXDOMAIN deny path
                    r = req.reply()
                    r.header.rcode = RCODE.NXDOMAIN
                    # Echo client EDNS(0) OPT, when present, into synthetic NXDOMAIN
                    # and, when enabled, attach an EDE option describing the
                    # policy-based deny.
                    _echo_client_edns(req, r)
                    # Allow plugins to override the EDE info-code/text via
                    # optional PluginDecision.ede_code / ede_text attributes,
                    # falling back to a default mapping based on stat when
                    # they are not provided.
                    try:
                        ede_code_hint = getattr(
                            decision, "ede_code", None
                        )  # pragma: no cover - defensive/metrics path excluded from coverage
                    except (
                        Exception
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        ede_code_hint = None
                    try:
                        ede_text_hint = getattr(
                            decision, "ede_text", None
                        )  # pragma: no cover - defensive/metrics path excluded from coverage
                    except (
                        Exception
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        ede_text_hint = None
                    if ede_code_hint is not None:
                        ede_code = int(ede_code_hint)
                        ede_text = (
                            str(ede_text_hint)
                            if ede_text_hint is not None
                            else "policy deny"
                        )
                    else:
                        try:
                            stat_label = getattr(
                                decision, "stat", None
                            )  # pragma: no cover - defensive/metrics path excluded from coverage
                        except (
                            Exception
                        ):  # pragma: no cover - defensive/metrics path excluded from coverage
                            stat_label = None
                        # Use "Not Ready" (14) for explicit rate limiting when
                        # decision.stat == "rate_limit"; otherwise treat this as a
                        # generic policy block (15).
                        if stat_label == "rate_limit":
                            ede_code = 14  # Not Ready
                            ede_text = "rate limit exceeded"
                        else:
                            ede_code = 15  # Blocked
                            ede_text = "blocked by policy"
                    _attach_ede_option(req, r, ede_code, ede_text)
                    wire = _set_response_id(r.pack(), req.header.id)
                    if stats is not None:
                        try:
                            qtype_name = _qtype_label_for_stats(qtype)
                            # Track the EDE info-code used for this synthetic
                            # NXDOMAIN so metrics and warm-loaded aggregates can
                            # expose EDE volumes alongside rcodes.
                            deny_source = "pre_plugin"
                            try:
                                if hasattr(stats, "record_ede_code"):
                                    stats.record_ede_code(ede_code)
                            except (
                                Exception
                            ):  # pragma: no cover - defensive metrics hook
                                pass
                            try:
                                # Pre-plugin deny bypasses cache; count it as
                                # a cache_null response and bump the
                                # cache_deny_pre total for live counters.
                                stats.record_cache_null(qname, status="deny_pre")
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            # When plugins provide a decision.stat label,
                            # mirror it into cache statistics so the HTML
                            # dashboard can expose per-decision tallies.
                            try:
                                stat_label = getattr(decision, "stat", None)
                                if (
                                    stat_label
                                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                                    stats.record_cache_stat(str(stat_label))
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            # Also record per-plugin pre-deny totals so
                            # stats.totals exposes pre_deny_<name> keys. Prefer
                            # the originating plugin instance label when
                            # available, falling back to alias/class naming.
                            try:
                                short = _resolve_plugin_label(decision, p)
                                label = (
                                    f"pre_deny_{short}" if short else "pre_deny_plugin"
                                )
                                if short:
                                    deny_source = short
                                stats.record_cache_pre_plugin(label)
                            except Exception:  # pragma: no cover - defensive
                                pass
                            stats.record_response_rcode("NXDOMAIN", qname)
                            # Skip persistent query-log insert when the
                            # plugin signals suppress_query_log (e.g.
                            # rate-limit denies under flood).
                            _suppress_qlog = bool(
                                getattr(decision, "suppress_query_log", False)
                            )
                            if not _suppress_qlog:
                                result_ctx = {
                                    "source": deny_source,
                                    "action": "deny",
                                    "ede_code": int(ede_code),
                                    "ede_text": str(ede_text),
                                }
                                if deny_source != "pre_plugin":
                                    result_ctx["plugin"] = deny_source
                                if listener is not None:
                                    result_ctx["listener"] = listener
                                if secure is not None:
                                    result_ctx["secure"] = bool(secure)
                                stats.record_query_result(
                                    client_ip=client_ip,
                                    qname=qname,
                                    qtype=qtype_name,
                                    rcode="NXDOMAIN",
                                    upstream_id=None,
                                    status="deny_pre",
                                    error=None,
                                    first=None,
                                    result=result_ctx,
                                )
                            else:
                                _record_suppressed_query_log_drop_candidate(
                                    stats,
                                    rcode="NXDOMAIN",
                                    status="deny_pre",
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
                        rcode_name="NXDOMAIN",
                    )
                if decision.action == "override" and decision.response is not None:
                    # Allow plugins to supply a full wire response, but ensure we
                    # still echo client EDNS(0) when the override does not carry
                    # its own OPT record.
                    resp_wire = decision.response
                    try:
                        override_msg = DNSRecord.parse(resp_wire)
                        _echo_client_edns(req, override_msg)
                        resp_wire = override_msg.pack()
                    except Exception:  # pragma: no cover - defensive: parse failure
                        pass
                    dnssec_status = _classify_dnssec_status_for_response(
                        handler=handler,
                        qname=qname,
                        qtype=qtype,
                        response_wire=resp_wire,
                    )
                    if stats is not None and dnssec_status is not None:
                        try:
                            stats.record_dnssec_status(dnssec_status)
                        except (
                            Exception
                        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                            pass
                    try:
                        dnssec_mode = str(
                            getattr(handler, "dnssec_mode", "ignore")
                        ).lower()
                    except Exception:
                        dnssec_mode = "ignore"
                    if (
                        dnssec_mode == "validate"
                        and dnssec_status in (None, "dnssec_unsigned", "dnssec_bogus")
                        and _is_signed_authoritative_response(resp_wire)
                    ):
                        dnssec_status = "dnssec_zone_secure"
                    resp_wire = _apply_dnssec_ad_bit(
                        handler=handler,
                        dnssec_status=dnssec_status,
                        response_wire=resp_wire,
                    )
                    wire = _set_response_id(resp_wire, req.header.id)
                    if stats is not None:
                        try:
                            parsed = DNSRecord.parse(wire)
                            rcode_name = RCODE.get(
                                parsed.header.rcode, str(parsed.header.rcode)
                            )
                            try:
                                # Pre-plugin override also bypasses cache; count
                                # it as a cache_null response and bump the
                                # cache_override_pre total for live counters.
                                stats.record_cache_null(qname, status="override_pre")
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            # Mirror any decision.stat label into cache stats
                            # so per-decision tallies are available in Totals.
                            try:
                                stat_label = getattr(decision, "stat", None)
                                if (
                                    stat_label
                                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                                    stats.record_cache_stat(str(stat_label))
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            # Also record per-plugin pre-override totals so
                            # stats.totals exposes pre_override_<name>. Prefer
                            # the originating plugin instance label when
                            # available, falling back to alias/class naming.
                            override_source = "pre_plugin_override"
                            try:
                                short = _resolve_plugin_label(decision, p)
                                if short:
                                    label = f"pre_override_{short}"
                                    override_source = short
                                else:
                                    label = "pre_override_plugin"
                                stats.record_cache_pre_plugin(label)
                            except Exception:  # pragma: no cover - defensive
                                pass
                            stats.record_response_rcode(rcode_name, qname)

                            # Skip persistent query-log insert when the
                            # plugin signals suppress_query_log.
                            _suppress_qlog = bool(
                                getattr(decision, "suppress_query_log", False)
                            )
                            if not _suppress_qlog:
                                answers = [
                                    {
                                        "name": str(rr.rname),
                                        "type": QTYPE.get(rr.rtype, str(rr.rtype)),
                                        "ttl": int(getattr(rr, "ttl", 0)),
                                        "rdata": str(rr.rdata),
                                    }
                                    for rr in (parsed.rr or [])
                                ]
                                first = answers[0]["rdata"] if answers else None
                                result_ctx = {
                                    "source": override_source,
                                    "answers": answers,
                                }
                                if override_source != "pre_plugin_override":
                                    result_ctx["plugin"] = override_source
                                if listener is not None:
                                    result_ctx["listener"] = listener
                                if secure is not None:
                                    result_ctx["secure"] = bool(secure)
                                qtype_name = _qtype_label_for_stats(qtype)
                                stats.record_query_result(
                                    client_ip=client_ip,
                                    qname=qname,
                                    qtype=qtype_name,
                                    rcode=rcode_name,
                                    upstream_id=None,
                                    status="override_pre",
                                    error=None,
                                    first=str(first) if first is not None else None,
                                    result=result_ctx,
                                )
                            else:
                                _record_suppressed_query_log_drop_candidate(
                                    stats,
                                    rcode=rcode_name,
                                    status="override_pre",
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
                        dnssec_status=dnssec_status,
                        upstream_id=None,
                        rcode_name=rcode_name,
                    )
                if decision.action == "allow":
                    # Explicit allow: stop evaluating further pre plugins but
                    # continue normal resolution (cache/upstream).
                    break

        # Cache lookup (with optional stale-while-revalidate prefetch).
        cache = getattr(plugin_base, "DNS_CACHE", None)
        cached: Optional[bytes] = None
        seconds_remaining: Optional[float] = None
        ttl_original: Optional[int] = None
        bypass_cache = bool(getattr(_CACHE_LOCAL, "bypass_cache", False))
        prefetch_enabled = bool(getattr(handler, "cache_prefetch_enabled", False))
        window_after = float(
            getattr(
                handler,
                "cache_prefetch_allow_stale_after_expiry",
                0.0,
            )
            or 0.0
        )

        if cache is not None and not bypass_cache:
            # Prefer get_with_meta() for stale-while-revalidate behavior. Allow a
            # fallback to get() for transitional/custom cache implementations.
            try:
                value, remaining, ttl_val = cache.get_with_meta(cache_key)
                if value is not None:
                    cached = value
                    seconds_remaining = remaining
                    ttl_original = ttl_val  # pragma: no cover - defensive/metrics path excluded from coverage
            except (
                NotImplementedError
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                try:  # pragma: no cover - defensive/metrics path excluded from coverage
                    cached = cache.get(
                        cache_key
                    )  # pragma: no cover - defensive/metrics path excluded from coverage
                except (
                    NotImplementedError
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    cached = None
            except (
                Exception
            ):  # pragma: no cover - defensive: cache implementation detail
                cached = None
        if (
            cached is not None
            and seconds_remaining is not None
            and seconds_remaining < 0.0
            and not (
                prefetch_enabled
                and window_after > 0.0
                and (-window_after <= seconds_remaining < 0.0)
            )
        ):
            cached = None

        if cached is not None:
            # Record cache hit statistics
            if stats is not None:
                try:
                    stats.record_cache_hit(qname)
                    parsed_cached = DNSRecord.parse(cached)
                    rcode_name = RCODE.get(
                        parsed_cached.header.rcode,
                        str(parsed_cached.header.rcode),
                    )
                    stats.record_response_rcode(rcode_name, qname)

                    answers = [
                        {
                            "name": str(rr.rname),
                            "type": QTYPE.get(rr.rtype, str(rr.rtype)),
                            "ttl": int(getattr(rr, "ttl", 0)),
                            "rdata": str(rr.rdata),
                        }
                        for rr in (parsed_cached.rr or [])
                    ]
                    first = answers[0]["rdata"] if answers else None
                    result_ctx = {"source": "cache", "answers": answers}
                    if listener is not None:
                        result_ctx["listener"] = listener
                    if secure is not None:
                        result_ctx["secure"] = bool(secure)
                    qtype_name = _qtype_label_for_stats(qtype)
                    stats.record_query_result(
                        client_ip=client_ip,
                        qname=qname,
                        qtype=qtype_name,
                        rcode=rcode_name,
                        upstream_id=None,
                        status="cache_hit",
                        error=None,
                        first=str(first) if first is not None else None,
                        result=result_ctx,
                    )
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass

            # Decide whether to schedule a background refresh for this cache hit
            min_ttl = int(getattr(handler, "cache_prefetch_min_ttl", 0) or 0)
            max_ttl = int(getattr(handler, "cache_prefetch_max_ttl", 0) or 0)
            window_before = float(
                getattr(
                    handler,
                    "cache_prefetch_refresh_before_expiry",
                    0.0,
                )
                or 0.0
            )

            should_refresh = False
            if (
                prefetch_enabled
                and seconds_remaining is not None
                and ttl_original is not None
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                ttl_ok = True  # pragma: no cover - defensive/metrics path excluded from coverage
                if (
                    ttl_original < min_ttl
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    ttl_ok = False  # pragma: no cover - defensive/metrics path excluded from coverage
                if (
                    max_ttl > 0 and ttl_original > max_ttl
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    ttl_ok = False  # pragma: no cover - defensive/metrics path excluded from coverage
                if (
                    ttl_ok
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    if (
                        0.0 <= seconds_remaining <= window_before
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        should_refresh = True  # pragma: no cover - defensive/metrics path excluded from coverage
                    elif (
                        window_after > 0.0 and -window_after <= seconds_remaining < 0.0
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        should_refresh = True

            if (
                should_refresh and not bypass_cache
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                _schedule_cache_refresh(data, client_ip)

            cached = _bind_response_cookie_to_request(req, cached)
            wire = _set_response_id(cached, req.header.id)
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
                rcode_name=rcode_name,
            )

        # Cache miss
        if stats is not None:
            try:
                stats.record_cache_miss(qname)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        # Block forwarding of .local queries and RFC1918 reverse PTRs unless
        # forward_local is True.
        # RFC 6762 reserves .local for mDNS; forwarding to upstream resolvers
        # can cause delays and incorrect answers. RFC1918 reverse PTRs are
        # often locally-served and should follow the same gate.
        forward_local = bool(getattr(handler, "forward_local", False))
        qname_lower = qname.lower()
        is_rfc1918_ptr_query = qtype == QTYPE.PTR and _is_rfc1918_ptr_query_name(
            qname_lower
        )
        if not forward_local and _is_forward_local_blocked_query(qname_lower, qtype):
            r = req.reply()
            r.header.rcode = RCODE.NXDOMAIN
            _echo_client_edns(req, r)
            ede_text = ".local not forwarded (RFC 6762)"
            if is_rfc1918_ptr_query:
                ede_text = "RFC1918 PTR not forwarded"
            _attach_ede_option(req, r, 21, ede_text)  # Not Authoritative
            wire = _set_response_id(r.pack(), req.header.id)
            if stats is not None:
                try:
                    qtype_name = _qtype_label_for_stats(qtype)
                    stats.record_response_rcode("NXDOMAIN", qname)
                    stats.record_query_result(
                        client_ip=client_ip,
                        qname=qname,
                        qtype=qtype_name,
                        rcode="NXDOMAIN",
                        upstream_id=None,
                        status="local_blocked",
                        error=None,
                        first=None,
                        result={"source": "local_blocked"},
                    )
                except Exception:  # pragma: no cover - defensive
                    pass
            if stats is not None and t0 is not None:
                try:
                    t1 = _time.perf_counter()
                    stats.record_latency(t1 - t0)
                except Exception:  # pragma: no cover - defensive
                    pass
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="NXDOMAIN",
            )

        reply: Optional[bytes] = None
        used_upstream: Optional[Dict] = None
        reason: Optional[str] = None

        # Decide between forwarding, recursion, and authoritative-only (no
        # forwarding) based on resolver_mode.
        resolver_mode = str(getattr(handler, "resolver_mode", "forward")).lower()
        # Backward-compatible alias: "none" historically meant authoritative-only
        # mode (no forwarding), which is now called "master".
        if resolver_mode == "none":
            resolver_mode = "master"

        if resolver_mode == "recursive":
            # In recursive mode we bypass configured upstreams and instead walk
            # from the root using RecursiveResolver. We still honour the
            # dnssec_mode when constructing the query (RD bit and EDNS DO bit
            # are already handled earlier in the pipeline) and we reuse
            # DNSUDPHandler's recursion knobs.
            try:
                max_depth = int(getattr(handler, "recursive_max_depth", 12) or 12)
            except Exception:  # pragma: no cover - defensive
                max_depth = 12
            try:
                recursion_timeout_ms = int(
                    getattr(
                        handler,
                        "recursive_timeout_ms",
                        getattr(handler, "timeout_ms", 2000),
                    )
                    or getattr(handler, "timeout_ms", 2000)
                )
            except Exception:  # pragma: no cover - defensive
                recursion_timeout_ms = int(getattr(handler, "timeout_ms", 2000) or 2000)
            try:
                per_try_ms = int(
                    getattr(
                        handler,
                        "recursive_per_try_timeout_ms",
                        recursion_timeout_ms,
                    )
                    or recursion_timeout_ms
                )
            except Exception:  # pragma: no cover - defensive
                per_try_ms = recursion_timeout_ms

            resolver = RecursiveResolver(
                cache=getattr(plugin_base, "DNS_CACHE", None),
                stats=stats,
                max_depth=max_depth,
                timeout_ms=recursion_timeout_ms,
                per_try_timeout_ms=per_try_ms,
            )

            # Perform iterative resolution. RecursiveResolver is responsible for
            # talking to upstream authorities; we only receive the final wire
            # and an optional upstream identifier for stats.
            reply, upstream_id = resolver.resolve(req)
            reason = "ok" if reply is not None else "all_failed"
        elif resolver_mode == "master":
            # Authoritative-only mode: do not forward or recurse. Plugins still
            # run (pre/post), but any cache miss falls through to REFUSED.
            upstream_id = None
            r = req.reply()
            r.header.rcode = RCODE.REFUSED
            # Echo client EDNS(0) OPT and attach an EDE explaining the policy
            # when enabled.
            _echo_client_edns(req, r)
            ede_code_for_logs = 15
            ede_text_for_logs = "forwarding disabled (resolver.mode=master)"
            _attach_ede_option(req, r, ede_code_for_logs, ede_text_for_logs)  # Blocked
            reply = r.pack()
            reason = "no_forwarding"
        else:
            # Classic forwarding: EDNS/DNSSEC adjustments (mirror
            # DNSUDPHandler behaviour) followed by send_query_with_failover.
            # When no upstreams are configured we skip EDNS normalization so that
            # synthesized SERVFAIL responses can echo the client's original OPT
            # record unchanged.
            primary_upstreams = list(getattr(handler, "upstream_addrs", []) or [])
            backup_upstreams = list(getattr(handler, "upstream_backup_addrs", []) or [])
            probe_percent = 1.0
            probe_min_percent = 1.0
            probe_max_percent = 50.0
            probe_increase = 1.0
            probe_decrease = 2.0
            try:
                health_cfg = getattr(handler, "upstream_health", None)
                probe_percent = float(getattr(health_cfg, "probe_percent", 1.0) or 1.0)
                probe_min_percent = float(
                    getattr(health_cfg, "probe_min_percent", 1.0) or 1.0
                )
                probe_max_percent = float(
                    getattr(health_cfg, "probe_max_percent", 50.0) or 50.0
                )
                probe_increase = float(
                    getattr(health_cfg, "probe_increase", 1.0) or 1.0
                )
                probe_decrease = float(
                    getattr(health_cfg, "probe_decrease", 2.0) or 2.0
                )
            except Exception:
                probe_percent = 1.0
                probe_min_percent = 1.0
                probe_max_percent = 50.0
                probe_increase = 1.0
                probe_decrease = 2.0
            if probe_min_percent > probe_max_percent:
                probe_min_percent, probe_max_percent = (
                    probe_max_percent,
                    probe_min_percent,
                )
            probe_min_percent = max(0.0, min(100.0, probe_min_percent))
            probe_max_percent = max(probe_min_percent, min(100.0, probe_max_percent))
            probe_increase = max(0.0, probe_increase)
            probe_decrease = max(0.0, probe_decrease)
            probe_percent = max(
                probe_min_percent, min(probe_max_percent, probe_percent)
            )
            current_probe_percent = DNSRuntimeState.upstream_probe_percent
            if current_probe_percent is None:
                current_probe_percent = probe_percent
            current_probe_percent = max(
                probe_min_percent,
                min(probe_max_percent, float(current_probe_percent)),
            )

            def _select_upstreams_with_probe(
                candidates: List[Dict],
            ) -> tuple[List[Dict], int]:
                now = _time.time()
                selected: List[Dict] = []
                healthy_count = 0
                for upstream in candidates or []:
                    if not isinstance(upstream, dict):
                        continue
                    up_id = DNSRuntimeState._upstream_id(upstream)
                    if not up_id:
                        selected.append(upstream)
                        healthy_count += 1
                        continue
                    entry = DNSRuntimeState.upstream_health.get(up_id)
                    down_until = (
                        float(entry.get("down_until", 0.0))
                        if isinstance(entry, dict)
                        else 0.0
                    )
                    if down_until > now:
                        if current_probe_percent > 0.0:
                            try:
                                if random.random() * 100.0 < current_probe_percent:
                                    selected.append(upstream)
                            except Exception:
                                pass
                        continue
                    selected.append(upstream)
                    healthy_count += 1
                return selected, healthy_count

            def _all_primaries_degraded(candidates: List[Dict]) -> bool:
                """Brief: True when all primary upstreams are degraded/down.

                Inputs:
                  - candidates: List of primary upstream mappings.

                Outputs:
                  - bool: True when no primary is fully healthy.
                """
                now = _time.time()
                saw_primary = False
                for upstream in candidates or []:
                    if not isinstance(upstream, dict):
                        continue
                    saw_primary = True
                    up_id = DNSRuntimeState._upstream_id(upstream)
                    if not up_id:
                        return False
                    entry = DNSRuntimeState.upstream_health.get(up_id)
                    if not isinstance(entry, dict):
                        return False
                    try:
                        down_until = float(entry.get("down_until", 0.0) or 0.0)
                    except Exception:
                        down_until = 0.0
                    if down_until <= now:
                        return False
                return True if saw_primary else True

            primary_selected, primary_healthy_count = _select_upstreams_with_probe(
                primary_upstreams
            )
            backup_selected, _backup_healthy_count = _select_upstreams_with_probe(
                backup_upstreams
            )
            # Backup upstreams are only considered when all primaries are
            # degraded (or none configured). Otherwise failover stays within
            # the primary list order.
            primaries_degraded = _all_primaries_degraded(primary_upstreams)
            if (
                primary_selected
                and primary_healthy_count > 0
                and not primaries_degraded
            ):
                upstreams = primary_selected
            elif backup_selected:
                upstreams = backup_selected
            else:
                upstreams = primary_selected
            try:
                strategy = str(
                    getattr(handler, "upstream_strategy", "failover")
                ).lower()
            except Exception:
                strategy = "failover"
            if strategy == "round_robin" and upstreams:
                try:
                    idx = int(getattr(DNSRuntimeState, "_upstream_rr_index", 0) or 0)
                except Exception:
                    idx = 0
                offset = idx % len(upstreams)
                upstreams = upstreams[offset:] + upstreams[:offset]
                DNSRuntimeState._upstream_rr_index = (idx + 1) % len(upstreams)
            elif strategy == "random" and len(upstreams) > 1:
                upstreams = list(upstreams)
                try:
                    random.shuffle(upstreams)
                except Exception:
                    pass
            try:
                mode = str(getattr(handler, "dnssec_mode", "ignore")).lower()
                if mode in ("ignore", "passthrough", "validate") and upstreams:
                    edns_helper = type("_H", (), {})()
                    edns_helper.dnssec_mode = getattr(handler, "dnssec_mode", "ignore")
                    edns_helper.edns_udp_payload = getattr(
                        handler, "edns_udp_payload", 1232
                    )
                    ensure = getattr(handler, "_ensure_edns", None)
                    if callable(ensure):
                        ensure(edns_helper, req)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

            # Forward with failover using the same helper as UDP handlers. Tests
            # frequently monkeypatch send_query_with_failover directly, so we call
            # it here rather than DNSUDPHandler._forward_with_failover_helper.
            upstream_id = None
            timeout_ms = getattr(handler, "timeout_ms", 2000)
            try:
                max_concurrent = int(
                    getattr(handler, "upstream_max_concurrent", 1) or 1
                )  # pragma: no cover - defensive/metrics path excluded from coverage
            except (
                Exception
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                max_concurrent = 1
            if (
                max_concurrent < 1
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                max_concurrent = 1
            reply, used_upstream, reason = send_query_with_failover(
                req,
                upstreams,
                timeout_ms,
                qname,
                qtype,
                max_concurrent=max_concurrent,
            )
            upstream_url = ""
            if isinstance(used_upstream, dict):
                try:
                    raw_upstream_url = str(used_upstream.get("url", "")).strip()
                except Exception:
                    raw_upstream_url = ""
                if raw_upstream_url:
                    upstream_url = _sanitize_upstream_url(raw_upstream_url)
            # Keep upstream health state in sync for admin/status payloads.
            # The UDP handler delegates to this shared resolver path, so health
            # updates must happen here as well.
            if reply is None:
                DNSRuntimeState._mark_upstreams_down(upstreams, reason)
                DNSRuntimeState.upstream_probe_percent = min(
                    probe_max_percent,
                    max(
                        probe_min_percent,
                        float(current_probe_percent) + float(probe_increase),
                    ),
                )
            else:
                DNSRuntimeState._mark_upstream_ok(used_upstream)
                DNSRuntimeState.upstream_probe_percent = min(
                    probe_max_percent,
                    max(
                        probe_min_percent,
                        float(current_probe_percent) - float(probe_decrease),
                    ),
                )

        # Record upstream result, even when all upstreams ultimately fail.
        if stats is not None and used_upstream:
            try:
                host = str(used_upstream.get("host", ""))
                port = int(used_upstream.get("port", 0))
                # For DoH-style upstreams identified by URL, prefer that as the
                # upstream_id so stats can distinguish endpoints consistently.
                url = str(upstream_url or "").strip()
                if url:
                    upstream_id = url
                else:
                    upstream_id = (
                        f"{host}:{port}" if host or port else host or "unknown"
                    )
                outcome = "success" if reason == "ok" else str(reason)
                stats.record_upstream_result(upstream_id, outcome)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        if reply is None:
            r = req.reply()
            r.header.rcode = RCODE.SERVFAIL

            # When synthesizing SERVFAIL (for example, when there are no
            # upstreams or all upstreams fail), echo any client EDNS(0) OPT RR
            # into the response so payload size and flags are preserved, and
            # attach an EDE option describing the upstream/network failure when
            # enabled.
            _echo_client_edns(req, r)
            ede_code = 23
            ede_text = "all upstreams failed"
            _attach_ede_option(req, r, ede_code, ede_text)  # Network Error

            wire = _set_response_id(r.pack(), req.header.id)
            if stats is not None:
                try:
                    # Record both rcode and EDE info-code for this synthetic
                    # SERVFAIL so that metrics and query_log consumers can
                    # distinguish upstream/network failures from other errors.
                    if hasattr(stats, "record_ede_code"):
                        try:
                            stats.record_ede_code(ede_code)
                        except Exception:  # pragma: no cover - defensive metrics hook
                            pass
                    stats.record_response_rcode("SERVFAIL", qname)
                    if upstream_id:
                        try:
                            stats.record_upstream_rcode(upstream_id, "SERVFAIL")
                        except (
                            Exception
                        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                            pass
                    qtype_name = _qtype_label_for_stats(qtype)
                    status = str(reason or "all_failed")
                    result_ctx = {
                        "source": "upstream",
                        "status": status,
                        "error": "all_upstreams_failed",
                        "ede_code": int(ede_code),
                        "ede_text": str(ede_text),
                    }
                    if upstream_id:
                        result_ctx["upstream"] = str(upstream_id)
                    if upstream_url:
                        result_ctx["upstream_url"] = str(upstream_url)
                    if listener is not None:
                        result_ctx["listener"] = listener
                    if secure is not None:
                        result_ctx["secure"] = bool(secure)
                    stats.record_query_result(
                        client_ip=client_ip,
                        qname=qname,
                        qtype=qtype_name,
                        rcode="SERVFAIL",
                        upstream_id=upstream_id,
                        status=status,
                        error="all_upstreams_failed",
                        first=None,
                        result=result_ctx,
                    )
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass
                # Record latency for the all-upstreams-failed path as well so
                # stats callers see a duration for every resolved query.
                if t0 is not None:
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
                upstream_id=upstream_id,
                rcode_name="SERVFAIL",
            )

        # Post plugins
        ctx2 = PluginContext(client_ip=client_ip, listener=listener, secure=secure)
        try:
            ctx2.qname = qname
        except Exception:  # pragma: no cover - defensive
            pass
        out = reply
        for p in post_plugins:
            # Skip plugins that do not target this qtype when they opt in via
            # BasePlugin.target_qtypes.
            try:
                if hasattr(p, "targets_qtype") and not p.targets_qtype(
                    qtype
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    continue
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                pass

            try:
                decision = p.post_resolve(qname, qtype, out, ctx2)
            except Exception:
                logger.error(
                    "post_resolve failed for plugin %s", type(p).__name__, exc_info=True
                )
                decision = None
            if isinstance(decision, PluginDecision):
                if decision.action == "drop":
                    if stats is not None:
                        _record_suppressed_query_log_drop_candidate(
                            stats,
                            rcode="DROP",
                            status="drop",
                        )
                    # Post-plugin timeout/drop: do not send a response.
                    return _ResolveCoreResult(
                        wire=b"",
                        dnssec_status=None,
                        upstream_id=upstream_id,
                        rcode_name="DROP",
                    )
                if decision.action == "deny":
                    r = req.reply()
                    r.header.rcode = RCODE.NXDOMAIN
                    # Echo client EDNS(0) OPT into post-plugin NXDOMAIN replies
                    # and, when enabled, attach an EDE option describing the
                    # post-resolve policy deny.
                    _echo_client_edns(req, r)
                    # Allow plugins to override the EDE info-code/text via
                    # optional PluginDecision.ede_code / ede_text attributes,
                    # falling back to a default mapping based on stat when
                    # they are not provided.
                    try:
                        ede_code_hint = getattr(
                            decision, "ede_code", None
                        )  # pragma: no cover - defensive/metrics path excluded from coverage
                    except (
                        Exception
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        ede_code_hint = None
                    try:
                        ede_text_hint = getattr(
                            decision, "ede_text", None
                        )  # pragma: no cover - defensive/metrics path excluded from coverage
                    except (
                        Exception
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        ede_text_hint = None
                    if ede_code_hint is not None:
                        ede_code = int(ede_code_hint)
                        ede_text = (
                            str(ede_text_hint)
                            if ede_text_hint is not None
                            else "policy deny"
                        )
                    else:
                        try:
                            stat_label = getattr(
                                decision, "stat", None
                            )  # pragma: no cover - defensive/metrics path excluded from coverage
                        except (
                            Exception
                        ):  # pragma: no cover - defensive/metrics path excluded from coverage
                            stat_label = None
                        if (
                            stat_label == "rate_limit"
                        ):  # pragma: no cover - defensive/metrics path excluded from coverage
                            ede_code = 14  # Not Ready  # pragma: no cover - defensive/metrics path excluded from coverage
                            ede_text = "rate limit exceeded"
                        else:
                            ede_code = 15  # Blocked
                            ede_text = "blocked by policy"
                    _attach_ede_option(req, r, ede_code, ede_text)
                    out = r.pack()
                    break
                if decision.action == "override" and decision.response is not None:
                    # Allow plugins to override the wire response while still
                    # echoing client EDNS(0) when the override does not carry an
                    # OPT RR of its own.
                    resp_wire = decision.response
                    try:
                        override_msg = DNSRecord.parse(resp_wire)
                        _echo_client_edns(req, override_msg)
                        out = override_msg.pack()
                    except Exception:  # pragma: no cover - defensive: parse failure
                        out = resp_wire
                    break  # pragma: no cover - defensive/metrics path excluded from coverage
                if decision.action == "allow":
                    # Explicit allow: stop evaluating further post plugins but
                    # leave the upstream response unchanged.
                    break

        # Cache store positive answers, negative responses (NXDOMAIN/NODATA), and
        # delegations/referrals using TTLs derived from SOA/NS records where
        # possible, following RFC 2308 guidance.

        # DNSSEC classification for non-UDP transports (TCP/DoT/DoH) shares the
        # same helper as UDP handlers so stats/query_log carry consistent status.
        dnssec_status = _classify_dnssec_status_for_response(
            handler=handler,
            qname=qname,
            qtype=qtype,
            response_wire=out,
        )
        if stats is not None and dnssec_status is not None:
            try:
                stats.record_dnssec_status(dnssec_status)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
        # When DNSSEC validation classifies a response as bogus under
        # dnssec_mode='validate', attach an RFC 8914 EDE code 6 (DNSSEC Bogus)
        # so clients and metrics can distinguish these failures.
        if dnssec_status == "dnssec_bogus":
            ede_code_for_logs = 6
            ede_text_for_logs = "DNSSEC validation failed (bogus)"
        try:
            dnssec_mode = str(getattr(handler, "dnssec_mode", "ignore")).lower()
        except Exception:
            dnssec_mode = "ignore"
        if (
            dnssec_mode == "validate"
            and upstream_id is None
            and dnssec_status in (None, "dnssec_unsigned", "dnssec_bogus")
            and _is_signed_authoritative_response(out)
        ):
            dnssec_status = "dnssec_zone_secure"
        out = _apply_dnssec_ad_bit(
            handler=handler,
            dnssec_status=dnssec_status,
            response_wire=out,
        )

        try:
            r = DNSRecord.parse(out)
            rcode = r.header.rcode
            ttl: Optional[int] = None

            # Positive answers: cache when we have an answer RRset.
            if rcode == RCODE.NOERROR and r.rr:
                ttls = [
                    int(getattr(rr, "ttl", 0))
                    for rr in r.rr
                    if isinstance(getattr(rr, "ttl", None), (int, float))
                ]
                ttl = min(ttls) if ttls else 300

                # Apply cache TTL floor and cap.
                min_cache_ttl = max(0, int(getattr(handler, "min_cache_ttl", 0) or 0))
                ttl = max(int(ttl), int(min_cache_ttl))
                try:
                    cache_obj = getattr(plugin_base, "DNS_CACHE", None)
                    raw_max = getattr(cache_obj, "max_cache_ttl", None)
                    max_cache_ttl = int(raw_max) if raw_max is not None else 86400
                except Exception:
                    max_cache_ttl = 86400
                if int(max_cache_ttl) > 0:
                    ttl = min(int(ttl), int(max_cache_ttl))
            else:
                auth_rrs = getattr(r, "auth", None) or []
                has_soa = any(rr.rtype == QTYPE.SOA for rr in auth_rrs)
                has_ns = any(rr.rtype == QTYPE.NS for rr in auth_rrs)

                # Negative caching per RFC 2308: NXDOMAIN or NODATA responses
                # with an SOA in the authority section.
                if has_soa and (
                    rcode == RCODE.NXDOMAIN or (rcode == RCODE.NOERROR and not r.rr)
                ):
                    ttl = _compute_negative_ttl(r, getattr(handler, "min_cache_ttl", 0))
                # Delegation / referral caching: NOERROR with no answers but NS
                # in the authority section.
                elif has_ns and rcode == RCODE.NOERROR and not r.rr:
                    ttl = _compute_negative_ttl(r, getattr(handler, "min_cache_ttl", 0))

            if ttl is not None and ttl > 0:
                cache = getattr(plugin_base, "DNS_CACHE", None)
                if cache is not None:
                    cache_payload = _strip_response_cookie_options(out)
                    cache.set(cache_key, int(ttl), cache_payload)

            # Attach a DNSSEC-related EDE only for explicitly bogus
            # classifications. This is done after caching decisions so TTL
            # handling remains unchanged.
            if dnssec_status == "dnssec_bogus" and ede_code_for_logs is not None:
                try:
                    _attach_ede_option(
                        req,
                        r,
                        int(ede_code_for_logs),
                        str(ede_text_for_logs or "DNSSEC validation failed (bogus)"),
                    )
                    out = r.pack()
                except Exception:  # pragma: no cover - defensive: best-effort only
                    pass
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

        out = _bind_response_cookie_to_request(req, out)
        wire = _set_response_id(out, req.header.id)

        # Record response rcode and append to persistent query_log when enabled.
        rcode_name = "UNKNOWN"
        if stats is not None:
            try:
                parsed = DNSRecord.parse(wire)
                rcode_name = RCODE.get(parsed.header.rcode, str(parsed.header.rcode))
                # Mirror any attached EDE info-code into stats totals when
                # available so that EDE volumes can be graphed alongside rcodes.
                if ede_code_for_logs is not None and hasattr(
                    stats, "record_ede_code"
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    try:  # pragma: no cover - defensive/metrics path excluded from coverage
                        stats.record_ede_code(ede_code_for_logs)
                    except Exception:  # pragma: no cover - defensive metrics hook
                        pass
                stats.record_response_rcode(rcode_name, qname)
                if upstream_id:
                    try:
                        stats.record_upstream_rcode(upstream_id, rcode_name)
                    except (
                        Exception
                    ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                        pass

                answers = [
                    {
                        "name": str(rr.rname),
                        "type": QTYPE.get(rr.rtype, str(rr.rtype)),
                        "ttl": int(getattr(rr, "ttl", 0)),
                        "rdata": str(rr.rdata),
                    }
                    for rr in (parsed.rr or [])
                ]
                first = answers[0]["rdata"] if answers else None
                result_ctx = {"source": "upstream", "answers": answers}
                if upstream_id:
                    result_ctx["upstream"] = str(upstream_id)
                if upstream_url:
                    result_ctx["upstream_url"] = str(upstream_url)
                if dnssec_status is not None:
                    result_ctx["dnssec_status"] = dnssec_status
                if (
                    ede_code_for_logs is not None
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    result_ctx["ede_code"] = int(
                        ede_code_for_logs
                    )  # pragma: no cover - defensive/metrics path excluded from coverage
                    if (
                        ede_text_for_logs is not None
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        result_ctx["ede_text"] = str(ede_text_for_logs)
                if listener is not None:
                    result_ctx["listener"] = listener
                if secure is not None:
                    result_ctx["secure"] = bool(secure)
                qtype_name = _qtype_label_for_stats(qtype)
                status = "ok" if rcode_name == "NOERROR" else "error"
                stats.record_query_result(
                    client_ip=client_ip,
                    qname=qname,
                    qtype=qtype_name,
                    rcode=rcode_name,
                    upstream_id=upstream_id,
                    status=status,
                    error=None,
                    first=str(first) if first is not None else None,
                    result=result_ctx,
                )
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        # Latency tracking shared across alfoghorn.servers.transports
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
            dnssec_status=dnssec_status,
            upstream_id=upstream_id,
            rcode_name=rcode_name,
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
                    if (
                        listener is not None
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        result_ctx["listener"] = listener
                    if (
                        secure is not None
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        result_ctx["secure"] = bool(secure)
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
    listener: Optional[str] = None,
    secure: Optional[bool] = None,
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
