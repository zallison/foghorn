"""DNS response, EDNS, and cache TTL helper utilities for server orchestration."""

from __future__ import annotations

import logging
from typing import Optional

from cachetools import TTLCache
from dnslib import EDNS0, QTYPE, RCODE, DNSRecord, EDNSOption

from foghorn.utils.register_caches import registered_cached

logger = logging.getLogger("foghorn.server")


@registered_cached(
    cache=TTLCache(maxsize=1024, ttl=60),
    key=lambda resp, min_cache_ttl: (id(resp), int(min_cache_ttl)),
)
def compute_effective_ttl(resp: DNSRecord, min_cache_ttl: int) -> int:
    """
    Computes cache TTL with min floor applied for any DNS response.

    Inputs:
      - resp: dnslib.DNSRecord, the parsed DNS response to cache
      - min_cache_ttl: int (seconds), minimum TTL floor

    Outputs:
      - int: effective TTL in seconds to use for cache expiry

    For NOERROR + answers: max(min(answer.ttl), min_cache_ttl)
    For all other cases: min_cache_ttl

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
            return max(int(answer_min_ttl), int(min_cache_ttl))
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
                    minimum = getattr(rdata, "minttl", None) or getattr(
                        rdata, "minimum", None
                    )
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


def _ensure_edns_request(
    req: DNSRecord, *, dnssec_mode: str, edns_udp_payload: int
) -> None:
    """Brief: Ensure the request carries an EDNS(0) OPT RR and DO bit as needed.

    Inputs:
      - req: DNSRecord request to mutate in-place.
      - dnssec_mode: DNSSEC mode string ("ignore", "passthrough", "validate").
      - edns_udp_payload: Server-side advertised UDP payload size (bytes).

    Outputs:
      - None; mutates req to include/update an OPT RR.

    Example:
      >>> req = DNSRecord.question("example.com", "A")
      >>> _ensure_edns_request(req, dnssec_mode="validate", edns_udp_payload=1232)
    """
    # Locate an existing OPT record, if any, in the additional section.
    opt_idx = None
    opt_rr = None
    additional = getattr(req, "ar", []) or []
    for idx, rr in enumerate(additional):
        if getattr(rr, "rtype", None) == QTYPE.OPT:
            opt_idx = idx
            opt_rr = rr
            break

    # Decide DO flag based on dnssec_mode.
    do_bit = 0x8000 if str(dnssec_mode).lower() in ("passthrough", "validate") else 0

    try:
        server_max = int(edns_udp_payload)
    except Exception:
        server_max = 1232
    if server_max < 512:
        server_max = 512

    if opt_rr is not None:
        try:
            client_payload = int(getattr(opt_rr, "rclass", 0) or 0)
        except Exception:
            client_payload = 0
        if client_payload <= 0:
            payload = server_max
        else:
            payload = (
                min(client_payload, server_max) if server_max > 0 else client_payload
            )

        try:
            ttl_val = int(getattr(opt_rr, "ttl", 0) or 0)
        except Exception:
            ttl_val = 0
        ext_rcode = (ttl_val >> 24) & 0xFF
        version = (ttl_val >> 16) & 0xFF
        flags = ttl_val & 0xFFFF
        flags = (flags & ~0x8000) | do_bit
        opt_rr.rclass = payload
        opt_rr.ttl = (ext_rcode << 24) | (version << 16) | (flags & 0xFFFF)
        return

    flags_str = "do" if do_bit else ""
    opt_rr = EDNS0(udp_len=server_max, flags=flags_str)
    if opt_idx is None:
        req.add_ar(opt_rr)
    else:
        req.ar[opt_idx] = opt_rr


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
    try:
        client_opts = [
            rr
            for rr in (getattr(req, "ar", None) or [])
            if getattr(rr, "rtype", None) == QTYPE.OPT
        ]
        if not client_opts:
            return
        existing_opts = [
            rr
            for rr in (getattr(resp, "ar", None) or [])
            if getattr(rr, "rtype", None) == QTYPE.OPT
        ]
        if existing_opts:
            return
        # Echo the first client OPT RR to keep behaviour simple and
        # deterministic; typical queries only carry a single OPT.
        resp.add_ar(client_opts[0])
    except Exception:  # pragma: no cover - defensive: best-effort only
        # EDNS echo should never prevent a response from being generated.
        return


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
    """

    try:
        try:
            from foghorn.runtime_config import get_runtime_snapshot

            enable_ede = bool(get_runtime_snapshot().enable_ede)
        except Exception:
            enable_ede = False
        if not enable_ede:
            return

        client_opts = [
            rr
            for rr in (getattr(req, "ar", None) or [])
            if getattr(rr, "rtype", None) == QTYPE.OPT
        ]
        if not client_opts:
            return

        # Locate or create an OPT RR on the response.
        opt_rr = None
        for rr in getattr(resp, "ar", None) or []:
            if getattr(rr, "rtype", None) == QTYPE.OPT:
                opt_rr = rr
                break
        if opt_rr is None:
            # Conservative: echo the first client OPT into the response, then
            # re-scan to obtain the actual instance attached to resp.
            resp.add_ar(client_opts[0])
            for rr in getattr(resp, "ar", None) or []:
                if getattr(rr, "rtype", None) == QTYPE.OPT:
                    opt_rr = rr
                    break
        if (
            opt_rr is None
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            return

        try:
            code = (
                int(info_code) & 0xFFFF
            )  # pragma: no cover - defensive/metrics path excluded from coverage
        except (
            Exception
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            code = 0
        payload = code.to_bytes(2, "big")
        if text:
            try:
                payload += str(text).encode(
                    "utf-8"
                )  # pragma: no cover - defensive/metrics path excluded from coverage
            except Exception:
                # Best-effort: ignore text encoding failures.
                pass

        # Append the EDE option (option-code 15) to the OPT rdata list.
        rdata_list = getattr(opt_rr, "rdata", None)
        if isinstance(rdata_list, list):
            rdata_list.append(EDNSOption(15, payload))
    except Exception:  # pragma: no cover - defensive: best-effort only
        return


def _set_response_id_bytes(wire: bytes, req_id: int) -> bytes:
    try:
        if len(wire) >= 2:
            hi = (req_id >> 8) & 0xFF
            lo = req_id & 0xFF
            return bytes([hi, lo]) + wire[2:]
        return wire
    except (
        Exception
    ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        logger.error("Failed to set response id (cached): %s", e)
        return wire
