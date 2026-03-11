"""Core DNS server orchestration and transport/failover helper utilities."""

import logging
import random
import threading
from concurrent.futures import Future, ThreadPoolExecutor
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
from foghorn.utils.register_caches import registered_lru_cached
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
    _compute_negative_ttl,
    _echo_client_edns,
    _ensure_edns_request,  # noqa: F401
    _set_response_id,
    _set_response_id_bytes,  # noqa: F401
    compute_effective_ttl,  # noqa: F401
)

logger = logging.getLogger("foghorn.server")


# Thread-local flag used to bypass cache lookups when performing background
# refresh queries. When bypass_cache is True, _resolve_core skips the cache
# hit path and always treats the query as a miss.
_CACHE_LOCAL = threading.local()

# Bounded background executor used for best-effort work triggered by untrusted
# network events (NOTIFY and cache refresh). This avoids spawning unbounded
# threads under attack conditions.
_BG_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="foghorn-bg")
_BG_SEM = threading.Semaphore(128)
_BG_LOCK = threading.Lock()
_BG_NOTIFY_INFLIGHT: set[str] = set()
_BG_CACHE_INFLIGHT: set[tuple[bytes, str]] = set()


def _bg_submit(key: object, fn) -> None:
    """Brief: Submit a bounded background task with best-effort coalescing.

    Inputs:
      - key: Hashable identifier for coalescing (e.g., zone name or (query, ip)).
      - fn: Zero-arg callable to execute.

    Outputs:
      - None.

    Notes:
      - Uses a semaphore to bound outstanding tasks. When the semaphore cannot
        be acquired immediately, the task is dropped.
    """

    try:
        acquired = _BG_SEM.acquire(blocking=False)
    except Exception:
        acquired = False
    if not acquired:
        return

    def _done(_fut: Future) -> None:
        try:
            _BG_SEM.release()
        except Exception:
            pass

    try:
        fut = _BG_EXECUTOR.submit(fn)
        fut.add_done_callback(_done)
    except Exception:
        try:
            _BG_SEM.release()
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

    # Coalesce refreshes per (query, ip) tuple to prevent thread explosions.
    key = (bytes(data), str(client_ip))
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
        _bg_submit(
            key, _wrapped
        )  # pragma: no cover - defensive/metrics path excluded from coverage
    except (
        Exception
    ):  # pragma: no cover - defensive/metrics path excluded from coverage
        with _BG_LOCK:
            _BG_CACHE_INFLIGHT.discard(key)
        logger.debug("Failed to schedule cache refresh task", exc_info=True)

    # Periodic upstream health cleanup can be called via DNSUDPHandler._cleanup_upstream_health


@registered_lru_cached(maxsize=1024)
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
        q = req.questions[0]
        qname = str(q.qname).rstrip(".")
        qtype = q.qtype
        cache_key = (qname.lower(), qtype)

        # Record query stats (mirrors DNSUDPHandler.handle)
        if stats is not None:
            try:
                qtype_name = QTYPE.get(qtype, str(qtype))
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
        for p in sorted(handler.plugins, key=lambda p: getattr(p, "pre_priority", 50)):
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

            decision = p.pre_resolve(qname, qtype, data, ctx)
            if isinstance(decision, PluginDecision):
                if decision.action == "drop":
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
                            qtype_name = QTYPE.get(qtype, str(qtype))
                            # Track the EDE info-code used for this synthetic
                            # NXDOMAIN so metrics and warm-loaded aggregates can
                            # expose EDE volumes alongside rcodes.
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
                                label_suffix = getattr(decision, "plugin_label", None)
                                if not label_suffix:
                                    plugin_cls = getattr(
                                        decision, "plugin", None
                                    ) or type(p)
                                    plugin_name = getattr(
                                        plugin_cls, "__name__", "plugin"
                                    ).lower()
                                    aliases = []
                                    try:
                                        aliases = list(
                                            getattr(
                                                plugin_cls, "get_aliases", lambda: []
                                            )()
                                        )
                                    except (
                                        Exception
                                    ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                                        aliases = []
                                    if (
                                        aliases
                                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                                        label_suffix = str(aliases[0]).strip().lower()
                                    else:
                                        label_suffix = plugin_name

                                short = str(label_suffix).strip()
                                if short:
                                    label = f"pre_deny_{short}"
                                else:  # pragma: no cover - defensive/metrics path excluded from coverage
                                    label = "pre_deny_plugin"
                                stats.record_cache_pre_plugin(label)
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            stats.record_response_rcode("NXDOMAIN", qname)
                            result_ctx = {
                                "source": "pre_plugin",
                                "action": "deny",
                                "ede_code": int(ede_code),
                                "ede_text": str(ede_text),
                            }
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
                                label_suffix = getattr(decision, "plugin_label", None)
                                if not label_suffix:
                                    plugin_cls = getattr(
                                        decision, "plugin", None
                                    ) or type(p)
                                    plugin_name = getattr(
                                        plugin_cls, "__name__", "plugin"
                                    ).lower()
                                    aliases = []
                                    try:
                                        aliases = list(
                                            getattr(
                                                plugin_cls, "get_aliases", lambda: []
                                            )()
                                        )
                                    except (
                                        Exception
                                    ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                                        aliases = []
                                    if (
                                        aliases
                                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                                        label_suffix = str(aliases[0]).strip().lower()
                                    else:
                                        label_suffix = plugin_name

                                short = str(label_suffix).strip()
                                if short:
                                    label = f"pre_override_{short}"
                                    override_source = short
                                else:  # pragma: no cover - defensive/metrics path excluded from coverage
                                    label = "pre_override_plugin"
                                stats.record_cache_pre_plugin(label)
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            stats.record_response_rcode(rcode_name, qname)

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
                            qtype_name = QTYPE.get(qtype, str(qtype))
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
                    qtype_name = QTYPE.get(qtype, str(qtype))
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
            prefetch_enabled = bool(getattr(handler, "cache_prefetch_enabled", False))
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
            window_after = float(
                getattr(
                    handler,
                    "cache_prefetch_allow_stale_after_expiry",
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

        # Block forwarding of .local queries unless forward_local is True.
        # RFC 6762 reserves .local for mDNS; forwarding to upstream resolvers
        # can cause delays and incorrect answers.
        forward_local = bool(getattr(handler, "forward_local", False))
        qname_lower = qname.lower()
        if not forward_local and (
            qname_lower.endswith(".local") or qname_lower == "local"
        ):
            r = req.reply()
            r.header.rcode = RCODE.NXDOMAIN
            _echo_client_edns(req, r)
            _attach_ede_option(
                req, r, 21, ".local not forwarded (RFC 6762)"
            )  # Not Authoritative
            wire = _set_response_id(r.pack(), req.header.id)
            if stats is not None:
                try:
                    qtype_name = QTYPE.get(qtype, str(qtype))
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

            primary_selected, primary_healthy_count = _select_upstreams_with_probe(
                primary_upstreams
            )
            backup_selected, _backup_healthy_count = _select_upstreams_with_probe(
                backup_upstreams
            )
            # Backup upstreams are only considered when all primaries are
            # unhealthy. Otherwise failover stays within the primary list order.
            if primary_healthy_count > 0 and primary_selected:
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
                url = str(used_upstream.get("url", "")).strip()
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
                    qtype_name = QTYPE.get(qtype, str(qtype))
                    status = str(reason or "all_failed")
                    result_ctx = {
                        "source": "upstream",
                        "status": status,
                        "error": "all_upstreams_failed",
                        "ede_code": int(ede_code),
                        "ede_text": str(ede_text),
                    }
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
        for p in sorted(handler.plugins, key=lambda p: getattr(p, "post_priority", 50)):
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

            decision = p.post_resolve(qname, qtype, out, ctx2)
            if isinstance(decision, PluginDecision):
                if decision.action == "drop":
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

        # DNSSEC classification for non-UDfoghorn.servers.transports (TCP/DoT/DoH) now shares
        # the same helper as UDP handlers so stats and query_log entries carry a
        # consistent "secure"/"insecure" status when dnssec.mode is 'validate'.
        dnssec_status = None
        try:
            # Use the same DNSSEC classification helper as the UDP handler so
            # non-UDP callers (TCP/DoT/DoH and tests using _resolve_core
            # directly) see consistent dnssec_status values.
            from ..dnssec.dnssec_validate import classify_dnssec_status

            mode = str(getattr(handler, "dnssec_mode", "ignore"))
            validation = str(getattr(handler, "dnssec_validation", "upstream_ad"))
            edns_udp_payload = int(getattr(handler, "edns_udp_payload", 1232))
            dnssec_status = classify_dnssec_status(
                dnssec_mode=mode,
                dnssec_validation=validation,
                qname_text=qname,
                qtype_num=qtype,
                response_wire=out,
                udp_payload_size=edns_udp_payload,
            )
            if stats is not None and dnssec_status is not None:
                try:
                    stats.record_dnssec_status(dnssec_status)
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass
            # When DNSSEC validation classifies a response as bogus under
            # dnssec_mode='validate', attach an RFC 8914 EDE code 6 (DNSSEC
            # Bogus) so clients and metrics can distinguish these failures.
            if dnssec_status == "dnssec_bogus":
                ede_code_for_logs = 6
                ede_text_for_logs = "DNSSEC validation failed (bogus)"
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            dnssec_status = None

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
                    cache.set(cache_key, int(ttl), out)

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
                qtype_name = QTYPE.get(qtype, str(qtype))
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
                    # Attempt to recover qname/qtype for logging
                    q = req.questions[0]
                    qname = str(q.qname).rstrip(".")
                    qtype = q.qtype
                    qtype_name = QTYPE.get(qtype, str(qtype))
                    result_ctx = {"source": "server", "error": "unhandled_exception"}
                    if (
                        listener is not None
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        result_ctx["listener"] = listener
                    if (
                        secure is not None
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        result_ctx["secure"] = bool(secure)
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
            # Worst-case fallback
            return _ResolveCoreResult(
                wire=data,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="UNKNOWN",
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
