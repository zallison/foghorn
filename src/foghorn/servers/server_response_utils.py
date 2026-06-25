"""DNS response, EDNS, and cache TTL helper utilities for server orchestration."""

from __future__ import annotations

import logging
from typing import Optional

from cachetools import TTLCache
from dnslib import QTYPE, RCODE, DNSRecord

from foghorn.utils.register_caches import registered_cached
from .edns_utils import (
    attach_ede_option,
    bind_response_cookie_to_request,
    echo_client_edns,
    ensure_edns_request,
    extract_client_cookie_from_request,
    strip_cookie_options_from_response_record,
    strip_response_cookie_options,
)

logger = logging.getLogger("foghorn.server")


def _compute_effective_ttl_cache_key(resp: object, min_cache_ttl: int) -> tuple:
    """Brief: Stable key for compute_effective_ttl caching.

    Inputs:
      - resp: Parsed DNSRecord-like object.
      - min_cache_ttl: Minimum TTL floor in seconds.

    Outputs:
      - tuple: Cache key.

    Notes:
      - Keyed only by fields that influence the computed TTL (rcode, presence of
        answers, and answer TTL values), plus the min_cache_ttl input.
      - This avoids id(resp)-based keys which can collide after GC and provides
        meaningful cache hits for repeated TTL patterns.
    """

    try:
        rcode = int(getattr(getattr(resp, "header", None), "rcode", 0) or 0)
    except Exception:
        rcode = 0

    rr_list = getattr(resp, "rr", None) or []
    has_answers = bool(rr_list)

    ttls: tuple[int, ...]
    try:
        ttls = tuple(
            int(getattr(rr, "ttl", 0) or 0)
            for rr in rr_list
            if isinstance(getattr(rr, "ttl", None), (int, float))
        )
    except Exception:
        ttls = ()

    return (rcode, has_answers, ttls, int(min_cache_ttl))


def _max_cache_ttl_seconds() -> int:
    """Brief: Resolve a maximum cache TTL cap for computed TTLs.

    Inputs:
      - None.

    Outputs:
      - int: Max TTL in seconds (>= 0). Default 86400.

    Notes:
      - Prefers the active DNS cache implementation's max_cache_ttl attribute
        when available; otherwise falls back to 86400 seconds.
    """

    try:
        from foghorn.plugins.resolve import base as plugin_base

        cache_obj = getattr(plugin_base, "DNS_CACHE", None)
        raw = getattr(cache_obj, "max_cache_ttl", None)
        if raw is None:
            return 86400
        val = int(raw)
        return max(0, val)
    except Exception:
        return 86400


@registered_cached(
    cache=TTLCache(maxsize=1024, ttl=60),
    key=_compute_effective_ttl_cache_key,
)
def compute_effective_ttl(resp: DNSRecord, min_cache_ttl: int) -> int:
    """
    Computes cache TTL with a min floor (and max cap) applied for any DNS response.

    Inputs:
      - resp: dnslib.DNSRecord, the parsed DNS response to cache
      - min_cache_ttl: int (seconds), minimum TTL floor

    Outputs:
      - int: effective TTL in seconds to use for cache expiry

    For NOERROR + answers: clamp(max(min(answer.ttl), min_cache_ttl), max_cache_ttl)
    For all other cases: min_cache_ttl

    Cache key semantics:
      - (rcode, has_answers, tuple(answer_ttls), min_cache_ttl)

    Example:
      >>> # Mock resp with NOERROR and answer RRs with TTL 30, min_cache_ttl=60
      >>> ttl = compute_effective_ttl(resp_with_low_ttl, 60)
      >>> ttl
      60
    """
    try:
        rcode = resp.header.rcode
        has_answers = bool(resp.rr)
        if rcode == RCODE.NOERROR and has_answers:
            answer_min_ttl = min(rr.ttl for rr in resp.rr)
            ttl = max(int(answer_min_ttl), int(min_cache_ttl))
            max_cache_ttl = _max_cache_ttl_seconds()
            if max_cache_ttl > 0:
                ttl = min(int(ttl), int(max_cache_ttl))
            return max(0, int(ttl))
        return max(0, int(min_cache_ttl))
    except Exception:
        # Defensive: on parsing error, fall back to min_cache_ttl
        return max(0, int(min_cache_ttl))


def _compute_negative_ttl(resp: DNSRecord, fallback_ttl: int) -> int:
    """Compute TTL for negative or referral caching using SOA/NS where possible.

    Inputs:
      - resp: Parsed DNSRecord from upstream.
      - fallback_ttl: Fallback TTL (seconds) when no suitable SOA/NS TTL exists.

    Outputs:
      - int TTL in seconds (>= 0) to use for negative/referral cache entries.

    Notes:
      - For NXDOMAIN/NODATA with an SOA in the authority section, we use the
        minimum of the SOA RR TTL and the SOA minimum TTL field when present.
      - For delegation/referral responses without SOA but with NS records, we
        fall back to the minimum NS TTL.
      - If neither SOA nor NS TTLs are available, fallback_ttl is used.
    """
    try:
        auth_rrs = getattr(resp, "auth", None) or []
        soa_ttls = []
        ns_ttls = []
        for rr in auth_rrs:
            if rr.rtype == QTYPE.SOA:
                try:
                    ttl_val = getattr(rr, "ttl", None)
                    if isinstance(ttl_val, (int, float)):
                        soa_ttls.append(int(ttl_val))
                    rdata = getattr(rr, "rdata", None)
                    minimum = getattr(rdata, "minttl", None)
                    if minimum is None:
                        minimum = getattr(rdata, "minimum", None)
                    if minimum is None:
                        # dnslib SOA stores the RFC 2308 negative caching TTL as
                        # the 5th element of rdata.times when provided.
                        try:
                            times = getattr(rdata, "times", None)
                            if isinstance(times, tuple) and len(times) >= 5:
                                minimum = times[4]
                        except Exception:
                            minimum = None
                    if isinstance(
                        minimum, (int, float)
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        soa_ttls.append(int(minimum))
                except (
                    Exception
                ):  # pragma: nocover - defensive: authority SOA parsing failure falls back to fallback_ttl
                    continue
            elif rr.rtype == QTYPE.NS:
                try:
                    ttl_val = getattr(rr, "ttl", None)
                    if isinstance(ttl_val, (int, float)):
                        ns_ttls.append(int(ttl_val))
                except (
                    Exception
                ):  # pragma: nocover - defensive: authority NS parsing failure falls back to fallback_ttl
                    continue

        # Prefer SOA-derived TTLs for true negative caching per RFC 2308.
        candidates = [t for t in soa_ttls if t >= 0]
        if candidates:
            return max(0, min(candidates))

        # Fall back to NS TTLs for delegation / referral caching.
        candidates = [t for t in ns_ttls if t >= 0]
        if candidates:
            return max(0, min(candidates))

        return max(0, int(fallback_ttl))
    except (
        Exception
    ):  # pragma: nocover - defensive: negative TTL computation failure falls back to caller-provided TTL
        return max(0, int(fallback_ttl))


def _set_response_id(wire: bytes, req_id: int) -> bytes:
    """Ensure the response DNS ID matches the request ID.

    Inputs:
      - wire: bytes-like DNS response (bytes, bytearray, or memoryview).
      - req_id: int request ID to set in the first two bytes.

    Outputs:
      - bytes: response with corrected ID.

    Fast path: DNS ID is the first 2 bytes (big-endian). We rewrite them
    without parsing to avoid any packing differences. For non-bytes inputs we
    return the original object unchanged so callers can rely on a best-effort
    behaviour without hard failures.
    """
    # Non-bytes inputs (e.g., None in defensive tests) are returned unchanged
    # but still trigger an error log so callers can diagnose misuse.
    if not isinstance(wire, (bytes, bytearray, memoryview)):
        logger.error("Failed to set response id: non-bytes wire %r", type(wire))
        return wire
    try:
        bwire = bytes(wire)
        if len(bwire) < 2:
            return bwire
        hi = (int(req_id) >> 8) & 0xFF
        lo = int(req_id) & 0xFF
        return bytes([hi, lo]) + bwire[2:]
    except Exception as e:  # pragma: no cover - defensive: error-handling path
        logger.error("Failed to set response id: %s", e)
        # Fall back to returning the original value when rewriting fails.
        return wire


def _extract_client_cookie_from_request(req: DNSRecord) -> Optional[bytes]:
    """Brief: Extract normalized client-cookie bytes from request EDNS options.

    Inputs:
      - req: Parsed DNS query DNSRecord.

    Outputs:
      - Optional[bytes]: 8-byte client-cookie when present and valid, else None.

    Notes:
      - DNS COOKIE uses EDNS option-code 10.
      - This helper returns only the client-cookie portion (first 8 bytes).
    """

    return extract_client_cookie_from_request(req)


def _strip_cookie_options_from_response_record(resp: DNSRecord) -> bool:
    """Brief: Remove COOKIE options from response OPT records.

    Inputs:
      - resp: Parsed DNS response DNSRecord (mutated in-place).

    Outputs:
      - bool: True when at least one COOKIE option was removed.
    """

    return strip_cookie_options_from_response_record(resp)


def _strip_response_cookie_options(response_wire: bytes) -> bytes:
    """Brief: Strip COOKIE options from a packed DNS response.

    Inputs:
      - response_wire: Wire-format DNS response bytes.

    Outputs:
      - bytes: Response bytes with COOKIE options removed.
    """

    return strip_response_cookie_options(response_wire)


def _bind_response_cookie_to_request(req: DNSRecord, response_wire: bytes) -> bytes:
    """Brief: Rebind response COOKIE to the active request client-cookie.

    Inputs:
      - req: Parsed DNS query DNSRecord.
      - response_wire: Wire-format DNS response bytes.

    Outputs:
      - bytes: Response bytes with stale COOKIE removed and request cookie bound.

    Notes:
      - When the request has no COOKIE option, this removes response COOKIE.
      - Non-COOKIE EDNS options are preserved.
    """

    return bind_response_cookie_to_request(req, response_wire)


def _ensure_edns_request(
    req: DNSRecord, *, dnssec_mode: str, edns_udp_payload: int
) -> None:
    """Brief: Preserve client EDNS(0) OPT and DO bit; do not add EDNS.

    Inputs:
      - req: DNSRecord request to mutate in-place.
      - dnssec_mode: DNSSEC mode string ("ignore", "passthrough", "validate").
      - edns_udp_payload: Server-side advertised UDP payload size (bytes).

    Outputs:
      - None; mutates req to align payload size and DO bit when an OPT RR exists.

    Example:
      >>> req = DNSRecord.question("example.com", "A")
      >>> _ensure_edns_request(req, dnssec_mode="validate", edns_udp_payload=1232)
    """
    ensure_edns_request(
        req,
        dnssec_mode=dnssec_mode,
        edns_udp_payload=edns_udp_payload,
    )


def _echo_client_edns(req: DNSRecord, resp: DNSRecord) -> None:
    """Ensure a synthetic response echoes client EDNS(0) OPT when present.

    Inputs:
      - req: Parsed DNSRecord representing the original client query.
      - resp: DNSRecord being constructed as the response (mutated in-place).

    Outputs:
      - None; best-effort injection of an OPT RR from the client when the
        response does not already contain one.

    This helper is intentionally conservative:
      - If the client did not send EDNS(0), resp is left unchanged.
      - If resp already carries an OPT RR, it is left unchanged so upstream or
        plugin-provided EDNS semantics are preserved.
    """
    echo_client_edns(req, resp)


def _attach_ede_option(
    req: DNSRecord,
    resp: DNSRecord,
    info_code: int,
    text: Optional[str] = None,
) -> None:
    """Brief: Attach an RFC 8914 Extended DNS Error (EDE) option when enabled.

    Inputs:
      - req: Original client DNS query (parsed DNSRecord).
      - resp: DNSRecord being constructed as the response (mutated in-place).
      - info_code: Integer EDE info-code value (0-65535).
      - text: Optional short UTF-8 string providing human-readable context.

    Outputs:
      - None; best-effort mutation of resp. On any error, resp is left unchanged.

    Behaviour:
      - Only runs when DNSUDPHandler.enable_ede is truthy.
      - Only attaches EDE when the client advertised EDNS(0) via an OPT RR.
      - Reuses an existing OPT in resp when present; otherwise copies the first
        client OPT into resp before appending the EDE option.
      - EXTRA-TEXT is truncated to 255 UTF-8 bytes.
    """

    attach_ede_option(
        req,
        resp,
        info_code,
        text=text,
    )
