"""Unified EDNS and ECS utility helpers used by resolver and transport paths."""

from __future__ import annotations

import copy
import ipaddress
import logging
import math
from typing import Any, Dict, Optional

from dnslib import EDNS0, QTYPE, DNSRecord, EDNSOption

logger = logging.getLogger("foghorn.server")

_EDNS_COOKIE_OPTION_CODE = 10
_DNS_COOKIE_CLIENT_BYTES = 8
_ECS_OPTION_CODE = 8
_EDNS_UDP_PAYLOAD_MIN = 512
_EDNS_UDP_PAYLOAD_MAX = 4096

_EDNS_PAYLOAD_CLAMP_WARNED: set[int] = set()


def _mask_prefix_bytes(raw: bytes, prefix_len: int, total_bits: int) -> bytes:
    """Brief: Mask host bits in a network-prefix byte sequence.

    Inputs:
      - raw: Prefix bytes to normalize.
      - prefix_len: Prefix length in bits.
      - total_bits: Address family width in bits (32 or 128).

    Outputs:
      - bytes: Prefix bytes with host bits beyond prefix_len zeroed.
    """

    if prefix_len <= 0:
        return b""
    if prefix_len >= total_bits:
        return bytes(raw)

    keep_bytes = int(math.ceil(float(prefix_len) / 8.0))
    out = bytearray(bytes(raw[:keep_bytes]).ljust(keep_bytes, b"\x00"))
    rem = int(prefix_len % 8)
    if rem > 0 and out:
        mask = (0xFF << (8 - rem)) & 0xFF
        out[-1] &= mask
    return bytes(out)


def _family_bits_and_class(
    family: int,
) -> tuple[int, type[ipaddress.IPv4Address] | type[ipaddress.IPv6Address]] | None:
    """Brief: Map ECS family code to address width and ipaddress class.

    Inputs:
      - family: ECS address family (1=IPv4, 2=IPv6).

    Outputs:
      - tuple[int, class] for recognized families, otherwise None.
    """

    if int(family) == 1:
        return 32, ipaddress.IPv4Address
    if int(family) == 2:
        return 128, ipaddress.IPv6Address
    return None


def parse_ecs_option_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """Brief: Parse EDNS Client Subnet option bytes.

    Inputs:
      - payload: Raw ECS option payload bytes (RFC 7871 format).

    Outputs:
      - dict with normalized ECS fields, or None when malformed/unsupported.

    Notes:
      - Invalid or truncated payloads are ignored (return None) instead of
        raising, so resolver query handling remains non-fatal.
    """

    try:
        data = bytes(payload or b"")
    except Exception:
        return None

    if len(data) < 4:
        return None

    family = int.from_bytes(data[0:2], "big")
    source_prefix = int(data[2])
    scope_prefix = int(data[3])

    family_info = _family_bits_and_class(family)
    if family_info is None:
        return None

    total_bits, addr_class = family_info
    if source_prefix < 0 or source_prefix > total_bits:
        return None
    if scope_prefix < 0 or scope_prefix > total_bits:
        return None

    needed = int(math.ceil(float(source_prefix) / 8.0))
    if len(data) < 4 + needed:
        return None

    addr_part = _mask_prefix_bytes(data[4 : 4 + needed], source_prefix, total_bits)
    full_len = 4 if total_bits == 32 else 16
    full_addr = addr_part.ljust(full_len, b"\x00")

    try:
        ip_obj = addr_class(full_addr)
    except Exception:
        return None

    try:
        network = ipaddress.ip_network(f"{ip_obj}/{source_prefix}", strict=False)
    except Exception:
        return None

    return {
        "family": int(family),
        "source_prefix": int(source_prefix),
        "scope_prefix": int(scope_prefix),
        "address": str(network.network_address),
        "subnet": str(network),
    }


def parse_ecs_option(option: object) -> Optional[Dict[str, Any]]:
    """Brief: Parse a dnslib EDNS option if it is ECS.

    Inputs:
      - option: Candidate EDNS option object.

    Outputs:
      - Parsed ECS dict for code 8 options, else None.
    """

    if not isinstance(option, EDNSOption):
        return None
    try:
        if int(getattr(option, "code", -1)) != int(_ECS_OPTION_CODE):
            return None
    except Exception:
        return None
    try:
        payload = bytes(getattr(option, "data", b"") or b"")
    except Exception:
        payload = b""
    return parse_ecs_option_payload(payload)


def parse_ecs_from_request(req: DNSRecord) -> Optional[Dict[str, Any]]:
    """Brief: Parse the first valid inbound ECS option from a DNS request.

    Inputs:
      - req: Parsed DNS request record.

    Outputs:
      - Parsed ECS dict, or None when absent/invalid.
    """

    try:
        for rr in getattr(req, "ar", None) or []:
            if getattr(rr, "rtype", None) != QTYPE.OPT:
                continue
            for opt in getattr(rr, "rdata", None) or []:
                ecs = parse_ecs_option(opt)
                if ecs is not None:
                    return ecs
    except Exception:
        return None
    return None


def serialize_ecs_option(ecs: Dict[str, Any]) -> Optional[EDNSOption]:
    """Brief: Serialize a normalized ECS mapping into a dnslib EDNS option.

    Inputs:
      - ecs: Mapping containing family/source_prefix/scope_prefix/address.

    Outputs:
      - EDNSOption(code=8, ...) when valid, otherwise None.
    """

    if not isinstance(ecs, dict):
        return None
    try:
        family = int(ecs.get("family"))
        source_prefix = int(ecs.get("source_prefix"))
        scope_prefix = int(ecs.get("scope_prefix", 0))
    except Exception:
        return None

    family_info = _family_bits_and_class(family)
    if family_info is None:
        return None
    total_bits, _addr_class = family_info
    if source_prefix < 0 or source_prefix > total_bits:
        return None
    if scope_prefix < 0 or scope_prefix > total_bits:
        return None

    address_text = str(ecs.get("address") or "")
    if not address_text:
        return None
    try:
        ip_obj = ipaddress.ip_address(address_text)
    except Exception:
        return None
    if int(getattr(ip_obj, "version", 0)) == 4 and family != 1:
        return None
    if int(getattr(ip_obj, "version", 0)) == 6 and family != 2:
        return None

    try:
        network = ipaddress.ip_network(f"{ip_obj}/{source_prefix}", strict=False)
    except Exception:
        return None

    needed = int(math.ceil(float(source_prefix) / 8.0))
    raw = bytes(network.network_address.packed[:needed])
    raw = _mask_prefix_bytes(raw, source_prefix, total_bits)
    payload = (
        int(family).to_bytes(2, "big")
        + bytes([int(source_prefix) & 0xFF, int(scope_prefix) & 0xFF])
        + raw
    )
    return EDNSOption(_ECS_OPTION_CODE, payload)


def synthesize_ecs_from_client_ip(
    client_ip: str,
    *,
    ipv4_prefix: int,
    ipv6_prefix: int,
    scope_prefix: int = 0,
) -> Optional[Dict[str, Any]]:
    """Brief: Create a normalized ECS mapping from a transport source IP.

    Inputs:
      - client_ip: Transport source IP text.
      - ipv4_prefix: Prefix bits for synthesized IPv4 ECS.
      - ipv6_prefix: Prefix bits for synthesized IPv6 ECS.
      - scope_prefix: ECS scope prefix bits.

    Outputs:
      - Parsed ECS mapping or None when source IP cannot be parsed.
    """

    try:
        ip_obj = ipaddress.ip_address(str(client_ip or "").strip())
    except Exception:
        return None

    if int(ip_obj.version) == 4:
        family = 1
        source_prefix = max(0, min(32, int(ipv4_prefix)))
        scope = max(0, min(32, int(scope_prefix)))
    else:
        family = 2
        source_prefix = max(0, min(128, int(ipv6_prefix)))
        scope = max(0, min(128, int(scope_prefix)))

    try:
        network = ipaddress.ip_network(f"{ip_obj}/{source_prefix}", strict=False)
    except Exception:
        return None

    return {
        "family": int(family),
        "source_prefix": int(source_prefix),
        "scope_prefix": int(scope),
        "address": str(network.network_address),
        "subnet": str(network),
    }


def upsert_ecs_option(
    req: DNSRecord,
    ecs: Dict[str, Any],
    *,
    create_opt_if_missing: bool = True,
    edns_udp_payload: int = 1232,
    preserve_do_bit: bool = True,
) -> bool:
    """Brief: Replace or append ECS option code 8 on a DNS request OPT RR.

    Inputs:
      - req: DNS request to mutate.
      - ecs: Normalized ECS mapping.
      - create_opt_if_missing: Whether to create an OPT RR when absent.
      - edns_udp_payload: UDP payload size used for created OPT RR.
      - preserve_do_bit: Whether to copy DO flag from existing OPT when creating.

    Outputs:
      - bool: True when ECS was applied, False when input is invalid.
    """

    ecs_opt = serialize_ecs_option(ecs)
    if ecs_opt is None:
        return False

    opt_rr = None
    try:
        for rr in getattr(req, "ar", None) or []:
            if getattr(rr, "rtype", None) == QTYPE.OPT:
                opt_rr = rr
                break
    except Exception:
        return False

    if opt_rr is None and not create_opt_if_missing:
        return False

    if opt_rr is None:
        do_flag = ""
        if preserve_do_bit:
            try:
                for rr in getattr(req, "ar", None) or []:
                    if getattr(rr, "rtype", None) == QTYPE.OPT:
                        ttl_val = int(getattr(rr, "ttl", 0) or 0)
                        if ttl_val & 0x8000:
                            do_flag = "do"
                        break
            except Exception:
                do_flag = ""
        payload = max(_EDNS_UDP_PAYLOAD_MIN, int(edns_udp_payload or 1232))
        req.add_ar(EDNS0(udp_len=payload, flags=do_flag))
        for rr in getattr(req, "ar", None) or []:
            if getattr(rr, "rtype", None) == QTYPE.OPT:
                opt_rr = rr
                break
        if opt_rr is None:
            return False

    rdata_list = getattr(opt_rr, "rdata", None)
    if not isinstance(rdata_list, list):
        opt_rr.rdata = []
        rdata_list = opt_rr.rdata

    filtered = []
    for opt in rdata_list:
        if isinstance(opt, EDNSOption):
            try:
                if int(getattr(opt, "code", -1)) == int(_ECS_OPTION_CODE):
                    continue
            except Exception:
                pass
        filtered.append(opt)
    filtered.append(ecs_opt)
    opt_rr.rdata = filtered
    return True


def strip_ecs_options_from_request(req: DNSRecord) -> bool:
    """Brief: Remove EDNS Client Subnet options from DNS request OPT records.

    Inputs:
      - req: DNS request to mutate.

    Outputs:
      - bool: True when one or more ECS options were removed.
    """

    changed = False
    try:
        for rr in getattr(req, "ar", None) or []:
            if getattr(rr, "rtype", None) != QTYPE.OPT:
                continue
            rdata_list = getattr(rr, "rdata", None)
            if not isinstance(rdata_list, list):
                continue
            filtered = []
            removed = False
            for opt in rdata_list:
                if isinstance(opt, EDNSOption):
                    try:
                        if int(getattr(opt, "code", -1)) == int(_ECS_OPTION_CODE):
                            removed = True
                            continue
                    except Exception:
                        pass
                filtered.append(opt)
            if removed:
                rr.rdata = filtered
                changed = True
    except Exception:
        return changed
    return changed


def client_udp_payload_limit(req: DNSRecord) -> int:
    """Brief: Return client-advertised EDNS UDP payload limit.

    Inputs:
      - req: Parsed DNS request.

    Outputs:
      - int: Advertised payload size, or 512 when EDNS is absent/invalid.
    """

    try:
        additional = getattr(req, "ar", None) or []
        for rr in additional:
            if getattr(rr, "rtype", None) == QTYPE.OPT:
                try:
                    payload = int(getattr(rr, "rclass", 0) or 0)
                except Exception:
                    payload = 0
                return max(_EDNS_UDP_PAYLOAD_MIN, payload) if payload > 0 else 512
    except Exception:
        return 512
    return 512


def ensure_edns_request(
    req: DNSRecord, *, dnssec_mode: str, edns_udp_payload: int
) -> None:
    """Brief: Preserve request EDNS envelope and clamp payload to server ceiling.

    Inputs:
      - req: DNSRecord request mutated in place.
      - dnssec_mode: DNSSEC mode string (unused for now; preserved for API parity).
      - edns_udp_payload: Server EDNS UDP payload ceiling.

    Outputs:
      - None.
    """

    _ = dnssec_mode
    opt_rr = None
    additional = getattr(req, "ar", []) or []
    for rr in additional:
        if getattr(rr, "rtype", None) == QTYPE.OPT:
            opt_rr = rr
            break
    if opt_rr is None:
        return

    try:
        ttl_val = int(getattr(opt_rr, "ttl", 0) or 0)
    except Exception:
        ttl_val = 0
    client_do = 0x8000 if (ttl_val & 0x8000) else 0

    try:
        server_max = int(edns_udp_payload)
    except Exception:
        server_max = 1232
    if server_max < _EDNS_UDP_PAYLOAD_MIN:
        server_max = _EDNS_UDP_PAYLOAD_MIN
    if server_max > _EDNS_UDP_PAYLOAD_MAX:
        if server_max not in _EDNS_PAYLOAD_CLAMP_WARNED:
            _EDNS_PAYLOAD_CLAMP_WARNED.add(server_max)
            logger.warning(
                "Clamping edns_udp_payload from %d to %d bytes",
                int(server_max),
                int(_EDNS_UDP_PAYLOAD_MAX),
            )
        server_max = _EDNS_UDP_PAYLOAD_MAX

    try:
        client_payload = int(getattr(opt_rr, "rclass", 0) or 0)
    except Exception:
        client_payload = 0
    if client_payload <= 0:
        payload = server_max
    else:
        payload = min(client_payload, server_max) if server_max > 0 else client_payload

    ext_rcode = (ttl_val >> 24) & 0xFF
    version = (ttl_val >> 16) & 0xFF
    flags = ttl_val & 0xFFFF
    flags = (flags & ~0x8000) | client_do
    opt_rr.rclass = payload
    opt_rr.ttl = (ext_rcode << 24) | (version << 16) | (flags & 0xFFFF)


def echo_client_edns(req: DNSRecord, resp: DNSRecord) -> None:
    """Brief: Copy request OPT RR into response when response has no OPT.

    Inputs:
      - req: Client DNS request.
      - resp: DNS response mutated in place.

    Outputs:
      - None.
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
        resp.add_ar(copy.deepcopy(client_opts[0]))
    except Exception:
        return


def attach_ede_option(
    req: DNSRecord,
    resp: DNSRecord,
    info_code: int,
    text: Optional[str] = None,
    *,
    enable_ede: Optional[bool] = None,
) -> None:
    """Brief: Attach RFC 8914 EDE option to response when enabled and EDNS exists.

    Inputs:
      - req: Original DNS request.
      - resp: DNS response mutated in place.
      - info_code: EDE info code.
      - text: Optional EDE text.
      - enable_ede: Optional explicit gate override.

    Outputs:
      - None.
    """

    try:
        if enable_ede is None:
            try:
                from foghorn.runtime_config import get_runtime_snapshot

                enable_ede = bool(get_runtime_snapshot().enable_ede)
            except Exception:
                enable_ede = False
        if not bool(enable_ede):
            return

        client_opts = [
            rr
            for rr in (getattr(req, "ar", None) or [])
            if getattr(rr, "rtype", None) == QTYPE.OPT
        ]
        if not client_opts:
            return

        opt_rr = None
        for rr in getattr(resp, "ar", None) or []:
            if getattr(rr, "rtype", None) == QTYPE.OPT:
                opt_rr = rr
                break
        if opt_rr is None:
            resp.add_ar(copy.deepcopy(client_opts[0]))
            for rr in getattr(resp, "ar", None) or []:
                if getattr(rr, "rtype", None) == QTYPE.OPT:
                    opt_rr = rr
                    break
        if opt_rr is None:
            return

        try:
            code = int(info_code) & 0xFFFF
        except Exception:
            code = 0
        payload = code.to_bytes(2, "big")
        if text:
            try:
                encoded = str(text).encode("utf-8")
                if len(encoded) > 255:
                    encoded = encoded[:255].decode("utf-8", "ignore").encode("utf-8")
                payload += encoded
            except Exception:
                pass

        rdata_list = getattr(opt_rr, "rdata", None)
        if isinstance(rdata_list, list):
            rdata_list.append(EDNSOption(15, payload))
    except Exception:
        return


def extract_client_cookie_from_request(req: DNSRecord) -> Optional[bytes]:
    """Brief: Extract normalized client-cookie bytes from request EDNS options.

    Inputs:
      - req: Parsed DNS request record.

    Outputs:
      - Optional[bytes]: Eight-byte client-cookie value.
    """

    try:
        for rr in getattr(req, "ar", None) or []:
            if getattr(rr, "rtype", None) != QTYPE.OPT:
                continue
            for opt in getattr(rr, "rdata", None) or []:
                if not isinstance(opt, EDNSOption):
                    continue
                try:
                    if int(getattr(opt, "code", -1)) != _EDNS_COOKIE_OPTION_CODE:
                        continue
                except Exception:
                    continue
                try:
                    raw = bytes(getattr(opt, "data", b"") or b"")
                except Exception:
                    raw = b""
                if len(raw) < _DNS_COOKIE_CLIENT_BYTES:
                    return None
                return raw[:_DNS_COOKIE_CLIENT_BYTES]
    except Exception:
        return None
    return None


def strip_cookie_options_from_response_record(resp: DNSRecord) -> bool:
    """Brief: Remove COOKIE options from response OPT records.

    Inputs:
      - resp: Parsed DNS response mutated in place.

    Outputs:
      - bool: True when COOKIE options were removed.
    """

    changed = False
    for rr in getattr(resp, "ar", None) or []:
        if getattr(rr, "rtype", None) != QTYPE.OPT:
            continue
        rdata_list = getattr(rr, "rdata", None)
        if not isinstance(rdata_list, list):
            continue
        filtered = []
        removed = False
        for opt in rdata_list:
            if isinstance(opt, EDNSOption) and int(getattr(opt, "code", -1)) == int(
                _EDNS_COOKIE_OPTION_CODE
            ):
                removed = True
                continue
            filtered.append(opt)
        if removed:
            rr.rdata = filtered
            changed = True
    return changed


def strip_response_cookie_options(response_wire: bytes) -> bytes:
    """Brief: Strip COOKIE options from a packed DNS response.

    Inputs:
      - response_wire: Wire-format DNS response bytes.

    Outputs:
      - bytes: Response with COOKIE options removed.
    """

    if not isinstance(response_wire, (bytes, bytearray, memoryview)):
        return response_wire
    try:
        msg = DNSRecord.parse(bytes(response_wire))
        changed = strip_cookie_options_from_response_record(msg)
        if not changed:
            return bytes(response_wire)
        return msg.pack()
    except Exception:
        return response_wire


def bind_response_cookie_to_request(req: DNSRecord, response_wire: bytes) -> bytes:
    """Brief: Rebind response COOKIE to current request client-cookie.

    Inputs:
      - req: Parsed DNS request.
      - response_wire: Wire-format DNS response bytes.

    Outputs:
      - bytes: Updated response wire bytes.
    """

    if not isinstance(response_wire, (bytes, bytearray, memoryview)):
        return response_wire
    try:
        msg = DNSRecord.parse(bytes(response_wire))
        changed = strip_cookie_options_from_response_record(msg)

        client_cookie = extract_client_cookie_from_request(req)
        if client_cookie is None:
            if changed:
                return msg.pack()
            return bytes(response_wire)

        opt_rr = None
        for rr in getattr(msg, "ar", None) or []:
            if getattr(rr, "rtype", None) == QTYPE.OPT:
                opt_rr = rr
                break

        if opt_rr is None:
            client_opts = [
                rr
                for rr in (getattr(req, "ar", None) or [])
                if getattr(rr, "rtype", None) == QTYPE.OPT
            ]
            if not client_opts:
                if changed:
                    return msg.pack()
                return bytes(response_wire)
            msg.add_ar(copy.deepcopy(client_opts[0]))
            changed = True
            for rr in getattr(msg, "ar", None) or []:
                if getattr(rr, "rtype", None) == QTYPE.OPT:
                    opt_rr = rr
                    break
            if opt_rr is None:
                if changed:
                    return msg.pack()
                return bytes(response_wire)

        rdata_list = getattr(opt_rr, "rdata", None)
        if not isinstance(rdata_list, list):
            opt_rr.rdata = []
            rdata_list = opt_rr.rdata
        rdata_list.append(EDNSOption(_EDNS_COOKIE_OPTION_CODE, bytes(client_cookie)))
        changed = True

        if changed:
            return msg.pack()
        return bytes(response_wire)
    except Exception:
        return response_wire
