"""Failover transport helpers and upstream skip-warning de-duplication."""

from __future__ import annotations

import errno
import re
import time

import logging
import threading
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

from dnslib import QTYPE, RCODE, DNSRecord

from foghorn.servers.transports.dot import DoTError, get_dot_pool
from foghorn.servers.transports.tcp import TCPError, get_tcp_pool, tcp_query
from foghorn.utils import dns_names
from .dns_runtime_state import DNSRuntimeState

logger = logging.getLogger("foghorn.server")

# Track whether we've already emitted a warning for a given upstream being
# skipped. This prevents log spam when an upstream is repeatedly failing.
# The "warned" state is cleared the next time the upstream succeeds.
_MAX_SKIP_WARNED_ENTRIES = 1024
_UPSTREAM_SKIP_WARNED: "OrderedDict[str, bool]" = OrderedDict()
_UPSTREAM_SKIP_LOCK = threading.Lock()

# Shared executor used only for per-query upstream fanout when failover is in
# concurrent mode. This avoids per-query thread pool creation/destruction.
_FAILOVER_EXECUTOR: ThreadPoolExecutor | None = None
_FAILOVER_EXECUTOR_LOCK = threading.Lock()
_FAILOVER_EXECUTOR_MAX_WORKERS: int | None = 8


def shutdown_failover_executor(wait: bool = True) -> None:
    """Brief: Shut down the shared failover executor during teardown.

    Inputs:
      - wait: True to block until queued tasks finish.

    Outputs:
      - None.
    """
    global _FAILOVER_EXECUTOR
    with _FAILOVER_EXECUTOR_LOCK:
        if _FAILOVER_EXECUTOR is not None:
            _FAILOVER_EXECUTOR.shutdown(wait=bool(wait))
            _FAILOVER_EXECUTOR = None


def _get_failover_executor() -> ThreadPoolExecutor:
    """Brief: Return the shared ThreadPoolExecutor used for failover fan-out.

    Inputs:
      - None.

    Outputs:
      - ThreadPoolExecutor: Shared executor.

    Notes:
      - This executor is used only when max_concurrent > 1 in
        _send_query_with_failover_impl.
      - It is intentionally shared and bounded to avoid per-query thread pool
        creation under load.
    """

    global _FAILOVER_EXECUTOR

    if _FAILOVER_EXECUTOR is not None:
        return _FAILOVER_EXECUTOR

    with _FAILOVER_EXECUTOR_LOCK:
        if _FAILOVER_EXECUTOR is not None:
            return _FAILOVER_EXECUTOR

        max_workers = _FAILOVER_EXECUTOR_MAX_WORKERS
        if max_workers is None:
            max_workers = 8

        _FAILOVER_EXECUTOR = ThreadPoolExecutor(
            max_workers=int(max_workers),
            thread_name_prefix="foghorn-failover",
        )
        return _FAILOVER_EXECUTOR


def _upstream_key_for_skip_warning(
    upstream: Dict, host: str, port: int, transport: str
) -> str:
    """Brief: Compute a stable identifier for upstream skip warning de-duplication.

    Inputs:
      - upstream: Upstream configuration mapping.
      - host: Upstream host string (may be empty for DoH).
      - port: Upstream port integer (0 when unspecified).
      - transport: Transport label (e.g. "udp", "tcp", "dot", "doh").

    Outputs:
      - str: A stable-ish key used to de-duplicate skip warnings.

    Notes:
      - For DoH, prefer the URL/endpoint when present so distinct endpoints do
        not collide.
      - For DoT, include tls.server_name when configured so SNI-specific
        failures are distinguishable.
    """
    try:
        explicit_id = str(upstream.get("id") or "").strip()
    except Exception:
        explicit_id = ""
    if explicit_id:
        return f"{transport}:id:{explicit_id}"
    try:
        url = str(upstream.get("url") or upstream.get("endpoint") or "").strip()
    except Exception:
        url = ""
    if url:
        return f"{transport}:{url}"

    server_name = ""
    try:
        tls_cfg = (
            upstream.get("tls", {}) if isinstance(upstream.get("tls"), dict) else {}
        )
        server_name = str(tls_cfg.get("server_name") or "").strip()
    except Exception:
        server_name = ""

    if server_name:
        return f"{transport}:{host}:{port}:{server_name}"
    return f"{transport}:{host}:{port}"


def _upstream_identity_label(
    upstream: Dict,
    host: str,
    port: int,
    transport: str,
) -> str:
    """Brief: Build a human-readable upstream identity label for warning logs.

    Inputs:
      - upstream: Upstream configuration mapping.
      - host: Normalized upstream host string.
      - port: Normalized upstream port integer.
      - transport: Normalized transport label.

    Outputs:
      - str: Label preferring upstream id, then DoH URL, then host:port.
    """

    try:
        explicit_id = str(upstream.get("id") or "").strip()
    except Exception:
        explicit_id = ""
    try:
        url = str(upstream.get("url") or upstream.get("endpoint") or "").strip()
    except Exception:
        url = ""
    host_port = f"{host}:{int(port)}" if host or port else ""

    if explicit_id:
        if url:
            return f"id={explicit_id}, url={url}"
        if host_port:
            return f"id={explicit_id}, host={host_port}"
        return f"id={explicit_id}"

    if url:
        return f"url={url}"
    if host_port:
        return f"host={host_port}"
    return f"transport={transport}"


def _is_connection_refused_error(exc: Exception) -> bool:
    """Brief: Return True when an exception indicates connection refused.

    Inputs:
      - exc: Exception raised by a transport attempt.

    Outputs:
      - bool: True when errno/class indicate a refused connection.

    Notes:
      - Prefer errno- and type-based classification to avoid locale-dependent
        string matching.
      - Some libraries wrap OSErrors and/or collapse errno into generic
        exceptions; in that case, we fall back to best-effort message matching.
    """

    try:
        if isinstance(exc, ConnectionRefusedError):
            return True
    except Exception:
        pass

    try:
        err = int(getattr(exc, "errno", 0) or 0)
    except Exception:
        err = 0

    refused_errnos = {
        int(errno.ECONNREFUSED),
        # Treat other common network connection failures as "refused" for
        # operator-facing warning rate limiting.
        int(errno.ECONNRESET),
        int(errno.ETIMEDOUT),
        int(errno.EHOSTUNREACH),
        int(errno.ENETUNREACH),
    }

    if err in refused_errnos:
        return True

    # Last resort: message matching (may be locale-dependent).
    return "connection refused" in str(exc).lower()


def _upstream_fail_count(upstream: Dict) -> float:
    """Brief: Read best-effort fail_count for an upstream.

    Inputs:
      - upstream: Upstream configuration mapping.

    Outputs:
      - float: Current fail_count from DNSRuntimeState.upstream_health.

    Notes:
      - Uses DNSRuntimeState._upstream_id to find the upstream health entry.
      - Returns 0.0 if state is unavailable or malformed.
    """

    try:
        up_id = DNSRuntimeState._upstream_id(upstream)
    except Exception:
        return 0.0

    if not up_id:
        return 0.0

    try:
        entry = DNSRuntimeState.upstream_health.get(up_id)
    except Exception:
        entry = None

    if not isinstance(entry, dict):
        return 0.0

    try:
        return float(entry.get("fail_count", 0.0) or 0.0)
    except Exception:
        return 0.0


def _should_show_in_log(fail_count: float) -> bool:
    """Brief: Decide whether to emit a skip-upstream warning given fail_count.

    Inputs:
      - fail_count: Current upstream fail_count value.

    Outputs:
      - bool: True when warnings should be emitted for this failure.

    Notes:
      - Intended to reduce log spam for transient failures.
      - Emits warnings for counts 3..25 inclusive, and then every 25 thereafter.
    """

    try:
        fc = int(fail_count)
    except Exception:
        return True

    # For larger values, emit every 25th failure (but not at 0).
    if 3 <= fc <= 25:
        return True

    return fc > 0 and (fc % 25) == 0


def _upstream_health_context(upstream: Dict, now_ts: Optional[float] = None) -> str:
    """Brief: Format best-effort health context for an upstream warning log.

    Inputs:
      - upstream: Upstream configuration mapping.
      - now_ts: Optional current timestamp for deterministic callers/tests.

    Outputs:
      - str: Health context text including state/fail_count/down_until.

    Notes:
      - Reads DNSRuntimeState.upstream_health using DNSRuntimeState._upstream_id.
      - State values mirror admin health semantics: up/degraded/down.
    """

    now = float(now_ts) if now_ts is not None else time.time()
    fail_count = 0.0
    down_until = 0.0
    state = "up"
    up_id = ""

    try:
        up_id = DNSRuntimeState._upstream_id(upstream)
    except Exception:
        up_id = ""

    entry = None
    if up_id:
        try:
            entry = DNSRuntimeState.upstream_health.get(up_id)
        except Exception:
            entry = None

    if isinstance(entry, dict):
        try:
            fail_count = float(entry.get("fail_count", 0.0) or 0.0)
        except Exception:
            fail_count = 0.0
        try:
            down_until = float(entry.get("down_until", 0.0) or 0.0)
        except Exception:
            down_until = 0.0

    if down_until > now:
        state = "down"
    elif fail_count > 0:
        state = "degraded"

    if down_until > now:
        retry_in_s = max(0.0, down_until - now)
        return (
            f"state={state}, fail_count={fail_count:g}, "
            f"down_until={down_until:.3f}, retry_in_s={retry_in_s:.1f}"
        )

    if down_until > 0:
        return (
            f"state={state}, fail_count={fail_count:g}, "
            f"last_down_until={down_until:.3f}"
        )

    return f"state={state}, fail_count={fail_count:g}, down_until=none"


def _warn_upstream_skip_once_with_health(
    upstream_key: str,
    upstream_health: str,
    fmt: str,
    *args,
) -> None:
    """Brief: Emit deduplicated upstream skip warning with health context.

    Inputs:
      - upstream_key: Identifier returned by _upstream_key_for_skip_warning.
      - upstream_health: Pre-formatted health context for this upstream.
      - fmt: Logger format string for skip warning body.
      - *args: Logger formatting arguments for fmt.

    Outputs:
      - None. Delegates to _warn_upstream_skip_once.
    """
    _warn_upstream_skip_once(
        upstream_key, f"{fmt} [health: %s]", *args, upstream_health
    )


def _warn_upstream_skip_once(upstream_key: str, fmt: str, *args) -> None:
    """Brief: Log a skip warning only once per upstream until it succeeds again.

    Inputs:
      - upstream_key: Identifier returned by _upstream_key_for_skip_warning.
      - fmt: Logger format string.
      - *args: Logger formatting arguments.

    Outputs:
      - None. Emits a single warning for this upstream_key if not previously
        emitted since the last reset.
    """
    try:
        with _UPSTREAM_SKIP_LOCK:
            if _UPSTREAM_SKIP_WARNED.get(upstream_key):
                try:
                    _UPSTREAM_SKIP_WARNED.move_to_end(upstream_key, last=True)
                except Exception:  # pragma: no cover - defensive
                    pass
                return
            while len(_UPSTREAM_SKIP_WARNED) >= int(_MAX_SKIP_WARNED_ENTRIES):
                _UPSTREAM_SKIP_WARNED.popitem(last=False)
            _UPSTREAM_SKIP_WARNED[upstream_key] = True
    except Exception:  # pragma: no cover - defensive
        # If the de-dupe bookkeeping fails, fall back to logging.
        logger.debug(fmt, *args)
        logger.debug(
            "Upstream skip de-duplication bookkeeping failed; continuing without de-dupe",
            exc_info=True,
        )
        return

    logger.warning(fmt, *args)


def _reset_upstream_skip_warning(upstream_key: str) -> None:
    """Brief: Clear the de-dupe state for an upstream after a successful query.

    Inputs:
      - upstream_key: Identifier returned by _upstream_key_for_skip_warning.

    Outputs:
      - None. Removes any prior warning state so the next failure is logged.
    """
    try:
        with _UPSTREAM_SKIP_LOCK:
            _UPSTREAM_SKIP_WARNED.pop(upstream_key, None)
    except Exception:  # pragma: no cover - defensive
        pass


def _send_query_with_failover_impl(
    query: DNSRecord,
    upstreams: List[Dict],
    timeout_ms: int,
    qname: str,
    qtype: int,
    max_concurrent: int = 1,
    *,
    get_dot_pool_fn=get_dot_pool,
    get_tcp_pool_fn=get_tcp_pool,
    tcp_query_fn=tcp_query,
    dot_error_cls=DoTError,
    tcp_error_cls=TCPError,
) -> Tuple[Optional[bytes], Optional[Dict], str]:
    """Brief: Send a DNS query with upstream failover and optional fan-out.

    Inputs:
      - query: dnslib DNSRecord to send.
      - upstreams: List of upstream configuration mappings.
      - timeout_ms: Per-attempt timeout in milliseconds.
      - qname: Query name (logging/validation fallback).
      - qtype: Query type (logging/validation fallback).
      - max_concurrent: Max upstreams to query in parallel for this request.

    Outputs:
      - (response_wire_bytes, used_upstream, reason)
        - response_wire_bytes: bytes on success, None on failure.
        - used_upstream: The upstream mapping that succeeded (possibly with
          transport adjusted), or None.
        - reason: 'ok', 'no_upstreams', or 'all_failed'.

    Notes:
      - When max_concurrent > 1, attempts are capped to max_concurrent in-flight
        futures and the first successful response wins.
    """
    if not upstreams:
        return None, None, "no_upstreams"

    timeout_sec = timeout_ms / 1000.0
    last_exception: Optional[Exception] = None
    last_exception_lock = threading.Lock()
    attempted_upstream_labels: list[str] = []
    attempted_upstream_label_set: Set[str] = set()
    attempted_upstream_health: dict[str, str] = {}
    attempted_upstream_fail_counts: dict[str, float] = {}
    attempted_upstreams_lock = threading.Lock()

    def _set_last_exception(exc: Exception) -> None:
        """Brief: Track the latest upstream exception in a thread-safe way.

        Inputs:
          - exc: Exception raised by an upstream attempt.

        Outputs:
          - None.
        """
        nonlocal last_exception
        with last_exception_lock:
            last_exception = exc

    # Precompute whether the original query advertised EDNS(0) via an OPT RR in
    # the additional section. This is used by the EDNS fallback shim below.
    try:
        _query_has_opt = any(
            getattr(rr, "rtype", None) == QTYPE.OPT
            for rr in (getattr(query, "ar", None) or [])
        )
    except Exception:  # pragma: no cover - defensive: non-DNSRecord queries
        _query_has_opt = False

    try:
        max_c = int(max_concurrent or 1)
    except Exception:  # pragma: no cover - defensive: invalid caller input
        max_c = 1
    if max_c < 1:  # pragma: no cover - defensive/metrics path excluded from coverage
        max_c = 1

    def _response_matches_query(parsed: DNSRecord) -> bool:
        """Brief: Validate response TXID and question match the original query.

        Inputs:
          - parsed: Parsed DNSRecord response.

        Outputs:
          - bool: True when TXID matches query.header.id and the first question
            matches (qname, qtype). False otherwise.

        Notes:
          - This is a hardening check to reduce risk of accepting injected or
            mismatched packets during upstream failover.
        """

        # TXID validation when the caller passed a dnslib-style DNSRecord.
        query_header = getattr(query, "header", None)
        if query_header is not None:
            try:
                expected_id = int(getattr(query_header, "id"))
            except Exception:
                logger.debug(
                    "TXID validation failed due to missing/invalid query header id"
                )
                return False
            if int(getattr(parsed.header, "id", -1)) != expected_id:
                return False

        try:
            qs = getattr(parsed, "questions", None) or []
            if not qs:
                # Security hardening: a forwarded upstream response should echo
                # the question section. Accepting a zero-question response would
                # weaken cache-poisoning mitigation guidance in RFC 5452.
                return False
            q0 = qs[0]

            # Prefer the original DNSRecord question when present; otherwise
            # fall back to qname/qtype arguments (which some tests use
            # purely for logging).
            expected_qname = None
            expected_qtype = None

            try:
                req_qs = getattr(query, "questions", None) or []
                if req_qs:
                    req0 = req_qs[0]
                    expected_qname = str(getattr(req0, "qname", ""))
                    expected_qtype = getattr(req0, "qtype", None)
            except Exception:
                expected_qname = None
                expected_qtype = None

            if expected_qname is None:
                expected_qname = str(qname)
            if expected_qtype is None:
                expected_qtype = qtype

            resp_qname = dns_names.normalize_name(getattr(q0, "qname", ""))
            exp_qname_norm = dns_names.normalize_name(expected_qname)
            if resp_qname != exp_qname_norm:
                return False

            if int(getattr(q0, "qtype", -1)) != int(expected_qtype):
                return False
        except Exception:
            return False

        return True

    def _upstream_attempt_context(
        upstream: Dict,
    ) -> Tuple[str, int, str, str, Optional[str], str]:
        """Brief: Build immutable context used by a single upstream attempt.

        Inputs:
          - upstream: Mapping describing host/port/transport/TLS configuration.

        Outputs:
          - (host, port, transport, upstream_key, tls_ca_file_hint,
            upstream_label).
            host/port/transport are normalized for logging and transport
            selection, upstream_key is used for warning de-duplication, and
            tls_ca_file_hint is used for exception context formatting.
            upstream_label prefers upstream id, then url, then host:port.
        """
        # For DoH we may not have host/port; use safe defaults for logging
        host = str(upstream.get("host", ""))
        try:
            port = int(upstream.get("port", 0))
        except Exception:  # pragma: no cover - defensive: bad port value
            port = 0
        transport = str(upstream.get("transport", "udp")).lower()
        upstream_key = _upstream_key_for_skip_warning(upstream, host, port, transport)
        upstream_label = _upstream_identity_label(upstream, host, port, transport)

        # Capture any tls.ca_file path early so failures that lose their filename
        # (for example, exceptions wrapped/re-raised by libraries) still provide
        # actionable context.
        tls_ca_file_hint = None
        try:
            tls_cfg = (
                upstream.get("tls", {}) if isinstance(upstream.get("tls"), dict) else {}
            )
            tls_ca_file_hint = tls_cfg.get("ca_file")
        except Exception:  # pragma: no cover - defensive
            tls_ca_file_hint = None
        return host, port, transport, upstream_key, tls_ca_file_hint, upstream_label

    def _send_transport_query(
        upstream: Dict,
        host: str,
        port: int,
        transport: str,
    ) -> bytes:
        """Brief: Send a DNS query through the selected transport.

        Inputs:
          - upstream: Mapping describing transport-specific options.
          - host: Upstream host used by UDP/TCP/DoT transports.
          - port: Upstream port used by UDP/TCP/DoT transports.
          - transport: One of udp/tcp/dot/doh.

        Outputs:
          - bytes: Wire-format DNS response payload from the selected upstream.

        Notes:
          - Raises transport exceptions for the caller to classify/log.
          - Preserves the legacy UDP fallback path used by tests/mocks where
            query.pack is absent and query.send is available.
        """
        if transport == "dot":
            tls = (
                upstream.get("tls", {}) if isinstance(upstream.get("tls"), dict) else {}
            )
            server_name = tls.get("server_name")
            verify = bool(tls.get("verify", True))
            ca_file = tls.get("ca_file")
            pool_cfg = (
                upstream.get("pool", {})
                if isinstance(upstream.get("pool"), dict)
                else {}
            )
            pool = get_dot_pool_fn(host, int(port), server_name, verify, ca_file)
            try:
                pool.set_limits(
                    max_connections=pool_cfg.get("max_connections"),
                    idle_timeout_s=(
                        (int(pool_cfg.get("idle_timeout_ms")) // 1000)
                        if pool_cfg.get("idle_timeout_ms")
                        else None
                    ),
                )
            except Exception:  # pragma: no cover - defensive: pool tuning only
                pass
            return pool.send(query.pack(), timeout_ms, timeout_ms)

        if transport == "tcp":
            pool_cfg = (
                upstream.get("pool", {})
                if isinstance(upstream.get("pool"), dict)
                else {}
            )
            pool = get_tcp_pool_fn(host, int(port))
            try:
                pool.set_limits(
                    max_connections=pool_cfg.get("max_connections"),
                    idle_timeout_s=(
                        (int(pool_cfg.get("idle_timeout_ms")) // 1000)
                        if pool_cfg.get("idle_timeout_ms")
                        else None
                    ),
                )
            except Exception:  # pragma: no cover - defensive: pool tuning only
                pass
            return pool.send(query.pack(), timeout_ms, timeout_ms)

        if transport == "doh":
            doh_url = str(upstream.get("url") or upstream.get("endpoint") or "").strip()
            if not doh_url:
                raise Exception("missing DoH url in upstream config")
            doh_method = str(upstream.get("method", "POST"))
            doh_headers = (
                upstream.get("headers")
                if isinstance(upstream.get("headers"), dict)
                else {}
            )
            tls_cfg = (
                upstream.get("tls", {}) if isinstance(upstream.get("tls"), dict) else {}
            )
            verify = bool(tls_cfg.get("verify", True))
            ca_file = tls_cfg.get("ca_file")
            from foghorn.servers.transports.doh import (  # local import to avoid overhead
                doh_query,
            )

            body, _ = doh_query(
                doh_url,
                query.pack(),
                method=doh_method,
                headers=doh_headers,
                timeout_ms=timeout_ms,
                verify=verify,
                ca_file=ca_file,
            )
            return body

        # udp (default)
        # Use transport impl for consistency, but preserve legacy path for tests/mocks
        try:
            pack = getattr(query, "pack")
        except Exception:
            pack = None
        if callable(pack):
            from foghorn.servers.transports.udp import udp_query

            return udp_query(host, int(port), query.pack(), timeout_ms=timeout_ms)
        # Fallback to dnslib's convenience API (used in unit tests)
        return query.send(host, int(port), timeout=timeout_sec)

    def _classify_response(
        response_wire: bytes,
        upstream: Dict,
        host: str,
        port: int,
        transport: str,
        upstream_key: str,
        upstream_label: str,
    ) -> Tuple[Optional[bytes], Optional[Dict], str]:
        """Brief: Parse and classify a transport response with fallback behavior.

        Inputs:
          - response_wire: DNS response bytes returned by transport.
          - upstream: Original upstream mapping used for this attempt.
          - host/port/transport: Normalized transport context for logging and
            retries.
          - upstream_key: Key used by warning de-duplication bookkeeping.
          - upstream_label: Human-readable upstream identity (id/url/host).

        Outputs:
          - (response_wire, used_upstream, reason) where response_wire is None
            and reason is 'all_failed' for failures, or response bytes with
            reason 'ok' on success.
        """
        nonlocal last_exception
        upstream_health = _upstream_health_context(upstream)
        fail_count = _upstream_fail_count(upstream)
        should_warn = _should_show_in_log(fail_count)

        # Check for SERVFAIL, EDNS compatibility issues, or truncation to
        # trigger appropriate fallbacks.
        try:
            parsed_response = DNSRecord.parse(response_wire)

            # Hardening: ensure response TXID and question match the original.
            if not _response_matches_query(parsed_response):
                if should_warn:
                    _warn_upstream_skip_once_with_health(
                        upstream_key,
                        upstream_health,
                        "Skipping upstream %s (%s:%d via %s) (mismatched response)",
                        upstream_label,
                        host,
                        port,
                        transport,
                    )
                else:
                    logger.debug(
                        "Skipping upstream %s (%s:%d via %s) (mismatched response) [health: %s]",
                        upstream_label,
                        host,
                        port,
                        transport,
                        upstream_health,
                    )
                _set_last_exception(
                    Exception(f"mismatched response from {host}:{port} via {transport}")
                )
                return None, None, "all_failed"

            # EDNS(0) compatibility shim: if an upstream returns FORMERR in
            # response to an EDNS-enabled UDP query, retry once without
            # EDNS. This covers servers that mishandle OPT records.
            if (
                transport == "udp"
                and _query_has_opt
                and parsed_response.header.rcode == RCODE.FORMERR
            ):
                logger.debug(
                    "Upstream %s:%d returned FORMERR for EDNS query %s; retrying without EDNS",
                    host,
                    port,
                )
                try:
                    from foghorn.servers.transports.udp import (
                        udp_query as _udp_query,
                    )

                    no_edns_query = DNSRecord.parse(query.pack())
                    no_edns_query.ar = [
                        rr
                        for rr in (getattr(no_edns_query, "ar", None) or [])
                        if getattr(rr, "rtype", None) != QTYPE.OPT
                    ]
                    response_wire = _udp_query(
                        host,
                        int(port),
                        no_edns_query.pack(),
                        timeout_ms=timeout_ms,
                    )
                    parsed_response = DNSRecord.parse(response_wire)

                    if not _response_matches_query(parsed_response):
                        if should_warn:
                            _warn_upstream_skip_once_with_health(
                                upstream_key,
                                upstream_health,
                                "Skipping upstream %s (%s:%d via %s) (mismatched response after EDNS fallback)",
                                upstream_label,
                                host,
                                port,
                                transport,
                            )
                        else:
                            logger.debug(
                                "Skipping upstream %s (%s:%d via %s) (mismatched response after EDNS fallback) [health: %s]",
                                upstream_label,
                                host,
                                port,
                                transport,
                                upstream_health,
                            )
                        _set_last_exception(
                            Exception(
                                f"mismatched response from {host}:{port} without EDNS"
                            )
                        )
                        return None, None, "all_failed"
                except Exception as e2:  # pragma: no cover - defensive
                    _warn_upstream_skip_once_with_health(
                        upstream_key,
                        upstream_health,
                        "Skipping upstream %s (%s:%d via %s) (EDNS fallback failed): %s",
                        upstream_label,
                        host,
                        port,
                        transport,
                        e2,
                    )
                    _set_last_exception(e2)
                    return None, None, "all_failed"

                # After fallback, treat SERVFAIL as failure as usual.
                if parsed_response.header.rcode == RCODE.SERVFAIL:
                    if should_warn:
                        _warn_upstream_skip_once_with_health(
                            upstream_key,
                            upstream_health,
                            "Skipping upstream %s (%s:%d via %s) (SERVFAIL after EDNS fallback)",
                            upstream_label,
                            host,
                            port,
                            transport,
                        )
                    _set_last_exception(
                        Exception(f"FORMERR/SERVFAIL from {host}:{port} without EDNS")
                    )
                    return None, None, "all_failed"

                # Successful non-SERVFAIL response after EDNS fallback.
                _reset_upstream_skip_warning(upstream_key)
                return response_wire, upstream, "ok"

            if parsed_response.header.rcode == RCODE.SERVFAIL:
                if should_warn:
                    _warn_upstream_skip_once_with_health(
                        upstream_key,
                        upstream_health,
                        "Skipping upstream %s (%s:%d via %s) (returned SERVFAIL)",
                        upstream_label,
                        host,
                        port,
                        transport,
                    )
                else:
                    logger.debug(
                        "Skipping upstream %s (%s:%d via %s) (returned SERVFAIL) [health: %s]",
                        upstream_label,
                        host,
                        port,
                        transport,
                        upstream_health,
                    )
                _set_last_exception(Exception(f"SERVFAIL from {host}:{port}"))
                return None, None, "all_failed"

            # If UDP and TC=1, fallback to TCP for full response
            tc_flag = getattr(parsed_response.header, "tc", 0)
            if transport == "udp" and tc_flag == 1:
                logger.debug("Truncated UDP response from %s; retrying over TCP", host)
                try:
                    response_wire = tcp_query_fn(
                        host,
                        int(port),
                        query.pack(),
                        connect_timeout_ms=timeout_ms,
                        read_timeout_ms=timeout_ms,
                    )
                    try:
                        parsed_tcp = DNSRecord.parse(response_wire)
                        if not _response_matches_query(parsed_tcp):
                            raise ValueError("mismatched TCP response")
                    except Exception as e3:
                        _warn_upstream_skip_once_with_health(
                            upstream_key,
                            upstream_health,
                            "Skipping upstream %s (%s:%d via tcp) (mismatched TCP response after truncation): %s",
                            upstream_label,
                            host,
                            port,
                            e3,
                        )
                        _set_last_exception(e3)
                        return None, None, "all_failed"

                    _reset_upstream_skip_warning(upstream_key)
                    return response_wire, {**upstream, "transport": "tcp"}, "ok"
                except Exception as e2:  # pragma: no cover - defensive
                    _warn_upstream_skip_once_with_health(
                        upstream_key,
                        upstream_health,
                        "Skipping upstream %s (%s:%d via %s) (TCP retry after truncation failed): %s",
                        upstream_label,
                        host,
                        port,
                        transport,
                        e2,
                    )
                    _set_last_exception(e2)
                    return None, None, "all_failed"
        except Exception as e:  # pragma: no cover - defensive
            # If parsing fails, treat as a server failure
            _warn_upstream_skip_once_with_health(
                upstream_key,
                upstream_health,
                "Skipping upstream %s (%s:%d via %s) (failed to parse response): %s",
                upstream_label,
                host,
                port,
                transport,
                e,
            )
            _set_last_exception(e)
            return None, None, "all_failed"

        # Success (NOERROR, NXDOMAIN, etc.)
        _reset_upstream_skip_warning(upstream_key)
        return response_wire, upstream, "ok"

    def _format_transport_error_file_info(
        exc: Exception, tls_ca_file_hint: Optional[str]
    ) -> str:
        """Brief: Build optional filename context for transport exceptions.

        Inputs:
          - exc: Transport exception raised by upstream attempt.
          - tls_ca_file_hint: Optional upstream tls.ca_file path captured from
            config.

        Outputs:
          - str: Formatted file context suffix (possibly empty).
        """
        # Some exceptions (notably FileNotFoundError/OSError) carry an
        # associated filename that is not always present in str(exc).
        filename = getattr(exc, "filename", None)
        filename2 = getattr(exc, "filename2", None)
        if filename and filename2:
            file_info = f" (files: {filename!r}, {filename2!r})"
        elif filename:
            file_info = f" (file: {filename!r})"
        elif filename2:
            file_info = f" (file: {filename2!r})"
        else:
            file_info = ""

        # Fallback: if we didn't get a filename from the exception itself,
        # try to include the configured tls.ca_file for DoT/DoH upstreams.
        if not file_info and tls_ca_file_hint and isinstance(exc, OSError):
            try:
                if getattr(exc, "errno", None) == 2:
                    file_info = f" (file: {str(tls_ca_file_hint)!r})"
            except Exception:  # pragma: no cover - defensive
                pass

        return file_info

    def _sanitize_error_message(msg: str) -> str:
        """Brief: Remove sensitive URL details from exception message text.

        Inputs:
          - msg: Raw exception string.

        Outputs:
          - str: Message with URL userinfo/query redacted.
        """
        safe = str(msg or "")
        safe = re.sub(r"(https?://)([^/@\s]+)@", r"\1***@", safe, flags=re.IGNORECASE)
        safe = re.sub(r"(https?://[^\s\?]+)\?[^\s)]*", r"\1?...", safe)
        return safe

    def _try_single(upstream: Dict) -> Tuple[Optional[bytes], Optional[Dict], str]:
        """Send query to a single upstream and classify the result.

        Inputs:
          - upstream: Mapping describing host/port/transport configuration.

        Outputs:
          - (response_wire, used_upstream, reason) where response_wire is
            None when this upstream failed and reason is 'ok' on success or
            'all_failed' on per-upstream failure.
        """

        host, port, transport, upstream_key, tls_ca_file_hint, upstream_label = (
            _upstream_attempt_context(upstream)
        )
        upstream_health = _upstream_health_context(upstream)
        fail_count = _upstream_fail_count(upstream)
        should_warn = _should_show_in_log(fail_count)
        try:
            with attempted_upstreams_lock:
                if upstream_label not in attempted_upstream_label_set:
                    attempted_upstream_label_set.add(upstream_label)
                    attempted_upstream_labels.append(upstream_label)
                attempted_upstream_health[upstream_label] = upstream_health
                attempted_upstream_fail_counts[upstream_label] = fail_count
        except Exception:
            pass

        try:
            logger.debug(
                "Forwarding %s type %s via %s to %s:%d",
                qname,
                qtype,
                transport,
                host,
                port,
            )
            response_wire = _send_transport_query(upstream, host, port, transport)
            return _classify_response(
                response_wire,
                upstream,
                host,
                port,
                transport,
                upstream_key,
                upstream_label,
            )

        except (
            dot_error_cls,
            tcp_error_cls,
            Exception,
        ) as e:  # pragma: no cover - defensive: network/transport failure
            err_msg = _sanitize_error_message(str(e))
            file_info = _format_transport_error_file_info(e, tls_ca_file_hint)
            if should_warn:
                if _is_connection_refused_error(e):
                    _warn_upstream_skip_once_with_health(
                        upstream_key,
                        upstream_health,
                        "Skipping upstream %s (%s:%d via %s): connection refused (%s: %s%s)",
                        upstream_label,
                        host,
                        port,
                        transport,
                        type(e).__name__,
                        err_msg,
                        file_info,
                    )
                else:
                    _warn_upstream_skip_once_with_health(
                        upstream_key,
                        upstream_health,
                        "Skipping upstream %s (%s:%d via %s): %s: %s%s",
                        upstream_label,
                        host,
                        port,
                        transport,
                        type(e).__name__,
                        err_msg,
                        file_info,
                    )
            else:
                # Keep details available for troubleshooting, but avoid warning spam.
                if _is_connection_refused_error(e) and should_warn:
                    logger.debug(
                        "Skipping upstream %s (%s:%d via %s): connection refused (%s: %s%s) [health: %s]",
                        upstream_label,
                        host,
                        port,
                        transport,
                        type(e).__name__,
                        err_msg,
                        file_info,
                        upstream_health,
                    )
                else:
                    if should_warn:
                        logger.debug(
                            "Skipping upstream %s (%s:%d via %s): %s: %s%s [health: %s]",
                            upstream_label,
                            host,
                            port,
                            transport,
                            type(e).__name__,
                            err_msg,
                            file_info,
                            upstream_health,
                        )
                    else:
                        logger.debug(
                            "Skipping upstream %s (%s:%d via %s): %s: %s%s",
                            upstream_label,
                            host,
                            port,
                            transport,
                            type(e).__name__,
                            err_msg,
                            file_info,
                        )
            _set_last_exception(e)
            return None, None, "all_failed"

    # Sequential path: same semantics as the original implementation when
    # max_concurrent == 1.
    if max_c == 1 or len(upstreams) <= 1:
        for upstream in upstreams:
            resp, used, reason = _try_single(upstream)
            if resp is not None:
                return resp, used, reason
    else:
        # Concurrency path: keep at most max_c attempts in-flight at a time and
        # return on the first successful response. This avoids queueing all
        # upstreams immediately (which would effectively probe every upstream
        # even when an earlier attempt succeeds).
        workers = min(max_c, len(upstreams))
        executor = _get_failover_executor()
        pending: Dict[Future, int] = {}
        next_index = 0
        try:
            # Prime the first in-flight window.
            while next_index < workers:
                fut = executor.submit(_try_single, upstreams[next_index])
                pending[fut] = next_index
                next_index += 1

            while pending:
                # Process one completion at a time so we can refill the window
                # only after a failed attempt.
                completed = next(as_completed(list(pending.keys())))
                pending.pop(completed, None)
                try:
                    resp, used, reason = completed.result()
                except Exception as e:  # pragma: no cover - defensive
                    _set_last_exception(e)
                    resp, used, reason = None, None, "all_failed"

                if resp is not None:
                    # Cancel queued (not-yet-started) attempts; in-flight
                    # attempts may continue and will be bounded by workers.
                    for fut in pending:
                        try:
                            fut.cancel()
                        except Exception:
                            pass
                    return resp, used, reason

                if next_index < len(upstreams):
                    fut = executor.submit(_try_single, upstreams[next_index])
                    pending[fut] = next_index
                    next_index += 1
        except Exception as e:  # pragma: no cover - defensive: executor failure
            _set_last_exception(e)
        finally:
            # Shared executor: do not shut down per query.
            pass

    attempted_order = sorted(attempted_upstream_label_set)
    attempted_summary = ", ".join(attempted_order) or "none"
    health_summary = (
        ", ".join(
            f"{label} [{attempted_upstream_health.get(label, 'state=unknown')}]"
            for label in attempted_order
        )
        or "none"
    )

    try:
        all_failed_should_warn = any(
            int(fc) > 1 for fc in attempted_upstream_fail_counts.values()
        )
    except Exception:
        all_failed_should_warn = False

    all_failed_logger = logger.warning if all_failed_should_warn else logger.debug
    with last_exception_lock:
        last_error_snapshot = last_exception
    all_failed_logger(
        "All upstreams failed. qtype=%s. Last error: %s (attempted: %s health: %s)",
        qtype,
        _sanitize_error_message(str(last_error_snapshot)),
        attempted_summary,
        health_summary,
    )

    return None, None, "all_failed"
