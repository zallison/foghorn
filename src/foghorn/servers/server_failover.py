"""Failover transport helpers and upstream skip-warning de-duplication."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from dnslib import QTYPE, RCODE, DNSRecord

from foghorn.servers.transports.dot import DoTError, get_dot_pool
from foghorn.servers.transports.tcp import TCPError, get_tcp_pool, tcp_query

logger = logging.getLogger("foghorn.server")

# Track whether we've already emitted a warning for a given upstream being
# skipped. This prevents log spam when an upstream is repeatedly failing.
# The "warned" state is cleared the next time the upstream succeeds.
_UPSTREAM_SKIP_WARNED: Dict[str, bool] = {}
_UPSTREAM_SKIP_LOCK = threading.Lock()


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
                return
            _UPSTREAM_SKIP_WARNED[upstream_key] = True
    except Exception:  # pragma: no cover - defensive
        # If the de-dupe bookkeeping fails, fall back to logging.
        logger.debug(fmt, *args)
        logger.debug(
            "Upstream skip de-duplication bookkeeping failed; continuing without de-dupe",
            exc_info=True,
        )
        return

    logger.debug(fmt, *args)


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
    """
    Sends a DNS query to a list of upstream servers, with failover and optional
    per-query concurrency across multiple upstreams.

    Args:
        query: The DNSRecord to send.
        upstreams: A list of upstream server dicts to try.
        timeout_ms: The timeout in milliseconds for each attempt.
        qname: The query name (for logging).
        qtype: The query type (for logging).
        max_concurrent: Maximum number of upstreams to query in parallel for
            this request. Values <1 are treated as 1. When greater than 1,
            up to ``max_concurrent`` upstreams are queried concurrently and the
            first successful response is returned.

    Returns:
        A tuple of (response_wire_bytes, used_upstream, reason).
        reason is 'ok', 'no_upstreams', or 'all_failed'.
    """
    if not upstreams:
        return None, None, "no_upstreams"

    timeout_sec = timeout_ms / 1000.0
    last_exception: Optional[Exception] = None

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
        try:
            expected_id = getattr(getattr(query, "header", None), "id", None)
            if expected_id is not None and int(getattr(parsed.header, "id", -1)) != int(
                expected_id
            ):
                return False
        except Exception:
            # If we cannot determine the expected ID (legacy objects), skip
            # TXID validation.
            pass

        try:
            qs = getattr(parsed, "questions", None) or []
            if not qs:
                # Best-effort: if we cannot recover the response question
                # section, skip question validation rather than rejecting
                # the response outright (helps tests/mocks and unusual
                # upstreams).
                return True
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

            resp_qname = str(getattr(q0, "qname", "")).rstrip(".").lower()
            exp_qname_norm = str(expected_qname).rstrip(".").lower()
            if resp_qname != exp_qname_norm:
                return False

            if int(getattr(q0, "qtype", -1)) != int(expected_qtype):
                return False
        except Exception:
            return False

        return True

    def _upstream_attempt_context(
        upstream: Dict,
    ) -> Tuple[str, int, str, str, Optional[str]]:
        """Brief: Build immutable context used by a single upstream attempt.

        Inputs:
          - upstream: Mapping describing host/port/transport/TLS configuration.

        Outputs:
          - (host, port, transport, upstream_key, tls_ca_file_hint).
            host/port/transport are normalized for logging and transport
            selection, upstream_key is used for warning de-duplication, and
            tls_ca_file_hint is used for exception context formatting.
        """
        # For DoH we may not have host/port; use safe defaults for logging
        host = str(upstream.get("host", ""))
        try:
            port = int(upstream.get("port", 0))
        except Exception:  # pragma: no cover - defensive: bad port value
            port = 0
        transport = str(upstream.get("transport", "udp")).lower()
        upstream_key = _upstream_key_for_skip_warning(upstream, host, port, transport)

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
        return host, port, transport, upstream_key, tls_ca_file_hint

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
    ) -> Tuple[Optional[bytes], Optional[Dict], str]:
        """Brief: Parse and classify a transport response with fallback behavior.

        Inputs:
          - response_wire: DNS response bytes returned by transport.
          - upstream: Original upstream mapping used for this attempt.
          - host/port/transport: Normalized transport context for logging and
            retries.
          - upstream_key: Key used by warning de-duplication bookkeeping.

        Outputs:
          - (response_wire, used_upstream, reason) where response_wire is None
            and reason is 'all_failed' for failures, or response bytes with
            reason 'ok' on success.
        """
        nonlocal last_exception

        # Check for SERVFAIL, EDNS compatibility issues, or truncation to
        # trigger appropriate fallbacks.
        try:
            parsed_response = DNSRecord.parse(response_wire)

            # Hardening: ensure response TXID and question match the original.
            if not _response_matches_query(parsed_response):
                _warn_upstream_skip_once(
                    upstream_key,
                    "Skipping upstream %s:%d via %s for %s (mismatched response)",
                    host,
                    port,
                    transport,
                    qname,
                )
                last_exception = Exception(
                    f"mismatched response from {host}:{port} via {transport}"
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
                    qname,
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
                        _warn_upstream_skip_once(
                            upstream_key,
                            "Skipping upstream %s:%d via %s for %s (mismatched response after EDNS fallback)",
                            host,
                            port,
                            transport,
                            qname,
                        )
                        last_exception = Exception(
                            f"mismatched response from {host}:{port} without EDNS"
                        )
                        return None, None, "all_failed"
                except Exception as e2:  # pragma: no cover - defensive
                    _warn_upstream_skip_once(
                        upstream_key,
                        "Skipping upstream %s:%d via %s for %s (EDNS fallback failed): %s",
                        host,
                        port,
                        transport,
                        qname,
                        e2,
                    )
                    last_exception = e2
                    return None, None, "all_failed"

                # After fallback, treat SERVFAIL as failure as usual.
                if parsed_response.header.rcode == RCODE.SERVFAIL:
                    _warn_upstream_skip_once(
                        upstream_key,
                        "Skipping upstream %s:%d via %s for %s (SERVFAIL after EDNS fallback)",
                        host,
                        port,
                        transport,
                        qname,
                    )
                    last_exception = Exception(
                        f"FORMERR/SERVFAIL from {host}:{port} without EDNS"
                    )
                    return None, None, "all_failed"

                # Successful non-SERVFAIL response after EDNS fallback.
                _reset_upstream_skip_warning(upstream_key)
                return response_wire, upstream, "ok"

            if parsed_response.header.rcode == RCODE.SERVFAIL:
                _warn_upstream_skip_once(
                    upstream_key,
                    "Skipping upstream %s:%d via %s for %s (returned SERVFAIL)",
                    host,
                    port,
                    transport,
                    qname,
                )
                last_exception = Exception(f"SERVFAIL from {host}:{port}")
                return None, None, "all_failed"

            # If UDP and TC=1, fallback to TCP for full response
            tc_flag = getattr(parsed_response.header, "tc", 0)
            if transport == "udp" and tc_flag == 1:
                logger.debug("Truncated UDP response for %s; retrying over TCP", qname)
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
                        _warn_upstream_skip_once(
                            upstream_key,
                            "Skipping upstream %s:%d via tcp for %s (mismatched TCP response after truncation): %s",
                            host,
                            port,
                            qname,
                            e3,
                        )
                        last_exception = e3
                        return None, None, "all_failed"

                    _reset_upstream_skip_warning(upstream_key)
                    return response_wire, {**upstream, "transport": "tcp"}, "ok"
                except Exception as e2:  # pragma: no cover - defensive
                    _warn_upstream_skip_once(
                        upstream_key,
                        "Skipping upstream %s:%d via %s for %s (TCP retry after truncation failed): %s",
                        host,
                        port,
                        transport,
                        qname,
                        e2,
                    )
                    last_exception = e2
                    return None, None, "all_failed"
        except Exception as e:  # pragma: no cover - defensive
            # If parsing fails, treat as a server failure
            _warn_upstream_skip_once(
                upstream_key,
                "Skipping upstream %s:%d via %s for %s (failed to parse response): %s",
                host,
                port,
                transport,
                qname,
                e,
            )
            last_exception = e
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

    def _try_single(upstream: Dict) -> Tuple[Optional[bytes], Optional[Dict], str]:
        """Send query to a single upstream and classify the result.

        Inputs:
          - upstream: Mapping describing host/port/transport configuration.

        Outputs:
          - (response_wire, used_upstream, reason) where response_wire is
            None when this upstream failed and reason is 'ok' on success or
            'all_failed' on per-upstream failure.
        """

        nonlocal last_exception

        host, port, transport, upstream_key, tls_ca_file_hint = (
            _upstream_attempt_context(upstream)
        )

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
                response_wire, upstream, host, port, transport, upstream_key
            )

        except (
            dot_error_cls,
            tcp_error_cls,
            Exception,
        ) as e:  # pragma: no cover - defensive: network/transport failure
            file_info = _format_transport_error_file_info(e, tls_ca_file_hint)

            _warn_upstream_skip_once(
                upstream_key,
                "Skipping upstream %s:%d via %s for %s: %s: %s%s",
                host,
                port,
                transport,
                qname,
                type(e).__name__,
                str(e),
                file_info,
            )
            last_exception = e
            return None, None, "all_failed"

    # Sequential path: same semantics as the original implementation when
    # max_concurrent == 1.
    if max_c == 1 or len(upstreams) <= 1:
        for upstream in upstreams:
            resp, used, reason = _try_single(upstream)
            if resp is not None:
                return resp, used, reason
    else:
        # Concurrency path: query up to max_c upstreams in parallel and return
        # the first successful response.
        workers = min(max_c, len(upstreams))
        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(_try_single, up) for up in upstreams]
                for fut in as_completed(futures):
                    try:
                        resp, used, reason = fut.result()
                    except Exception as e:  # pragma: no cover - defensive
                        last_exception = e
                        continue
                    if resp is not None:
                        return resp, used, reason
        except Exception as e:  # pragma: no cover - defensive: executor failure
            last_exception = e

    logger.warning(
        "All upstreams failed for %s %s. Last error: %s", qname, qtype, last_exception
    )
    return None, None, "all_failed"
