"""Unified EDNS and ECS utility helpers used by resolver and transport paths."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import ipaddress
import logging
import math
import os
import struct
import time
from typing import Any, Dict, Optional, Tuple

from dnslib import EDNS0, QTYPE, DNSHeader, DNSRecord, EDNSOption

logger = logging.getLogger("foghorn.server")

_EDNS_COOKIE_OPTION_CODE = 10
_DNS_COOKIE_CLIENT_BYTES = 8
_DNS_COOKIE_SERVER_BYTES = 16
_DNS_COOKIE_VERSION = 1
_DNS_COOKIE_KEY_ID_CURRENT = 0
_DNS_COOKIE_KEY_ID_OLD = 1
_DNS_COOKIE_FUTURE_SKEW_SECONDS = 60
RCODE_BADCOOKIE = 23
_ECS_OPTION_CODE = 8
_EDNS_UDP_PAYLOAD_MIN = 512
_EDNS_UDP_PAYLOAD_MAX = 4096

_EDNS_PAYLOAD_CLAMP_WARNED: set[int] = set()
_EPHEMERAL_COOKIE_SECRET: bytes | None = None


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


def decode_cookie_secret(value: object) -> Optional[bytes]:
    """Brief: Decode a configured cookie secret into raw key bytes.

    Inputs:
      - value: Secret as bytes, base64/hex/utf-8 string, or None.

    Outputs:
      - bytes key when usable, else None.
    """

    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return raw if raw else None
    text = str(value).strip()
    if not text:
        return None
    # Prefer base64, then hex, then raw UTF-8.
    try:
        decoded = base64.b64decode(text, validate=False)
        if decoded:
            return decoded
    except Exception:
        pass
    try:
        cleaned = text.replace(":", "").replace(" ", "")
        if len(cleaned) % 2 == 0 and all(
            ch in "0123456789abcdefABCDEF" for ch in cleaned
        ):
            decoded = bytes.fromhex(cleaned)
            if decoded:
                return decoded
    except Exception:
        pass
    return text.encode("utf-8")


def get_or_create_ephemeral_cookie_secret() -> bytes:
    """Brief: Return a process-local ephemeral cookie secret.

    Inputs:
      - None.

    Outputs:
      - bytes: 32-byte secret stable for the process lifetime.
    """

    global _EPHEMERAL_COOKIE_SECRET
    if _EPHEMERAL_COOKIE_SECRET is None:
        _EPHEMERAL_COOKIE_SECRET = os.urandom(32)
    return _EPHEMERAL_COOKIE_SECRET


def _canonical_client_ip_bytes(client_ip: object) -> bytes:
    """Brief: Canonicalize a client IP for cookie MAC input.

    Inputs:
      - client_ip: Transport client IP string.

    Outputs:
      - bytes: Packed IP when parseable, else lowercased UTF-8 text.
    """

    text = str(client_ip or "").strip()
    if not text:
        return b""
    try:
        return ipaddress.ip_address(text).packed
    except Exception:
        return text.lower().encode("utf-8")


def parse_cookie_option_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """Brief: Parse a DNS COOKIE option payload into client/server parts.

    Inputs:
      - payload: Raw COOKIE option bytes.

    Outputs:
      - dict with client_cookie and optional server_cookie, or None if malformed.
    """

    try:
        data = bytes(payload or b"")
    except Exception:
        return None
    if len(data) < _DNS_COOKIE_CLIENT_BYTES:
        return None
    # RFC 7873: client cookie is 8 bytes; server cookie is 8..32 when present.
    if len(data) == _DNS_COOKIE_CLIENT_BYTES:
        return {"client_cookie": data, "server_cookie": None}
    server = data[_DNS_COOKIE_CLIENT_BYTES:]
    if len(server) < 8 or len(server) > 32:
        return None
    return {
        "client_cookie": data[:_DNS_COOKIE_CLIENT_BYTES],
        "server_cookie": server,
    }


def parse_cookie_from_request(req: DNSRecord) -> Optional[Dict[str, Any]]:
    """Brief: Parse the first COOKIE option from a DNS request.

    Inputs:
      - req: Parsed DNS request.

    Outputs:
      - Parsed cookie dict or None when absent/invalid.
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
                parsed = parse_cookie_option_payload(raw)
                if parsed is not None:
                    return parsed
    except Exception:
        return None
    return None


def extract_client_cookie_from_request(req: DNSRecord) -> Optional[bytes]:
    """Brief: Extract normalized client-cookie bytes from request EDNS options.

    Inputs:
      - req: Parsed DNS request record.

    Outputs:
      - Optional[bytes]: Eight-byte client-cookie value.
    """

    parsed = parse_cookie_from_request(req)
    if not parsed:
        return None
    client = parsed.get("client_cookie")
    if not isinstance(client, (bytes, bytearray)):
        return None
    if len(client) != _DNS_COOKIE_CLIENT_BYTES:
        return None
    return bytes(client)


def generate_server_cookie(
    *,
    client_cookie: bytes,
    client_ip: object,
    secret: bytes,
    key_id: int = _DNS_COOKIE_KEY_ID_CURRENT,
    now: Optional[int] = None,
) -> bytes:
    """Brief: Generate a versioned server cookie bound to client cookie + IP.

    Inputs:
      - client_cookie: 8-byte client cookie.
      - client_ip: Transport client IP.
      - secret: HMAC key bytes.
      - key_id: 0=current secret, 1=old secret.
      - now: Optional unix timestamp override.

    Outputs:
      - bytes: Fixed-length server cookie payload.
    """

    cc = bytes(client_cookie or b"")
    if len(cc) != _DNS_COOKIE_CLIENT_BYTES:
        raise ValueError("client_cookie must be 8 bytes")
    secret_b = bytes(secret or b"")
    if not secret_b:
        raise ValueError("secret must be non-empty")
    ts = int(time.time() if now is None else now) & 0xFFFFFFFF
    kid = int(key_id) & 0xFF
    version = int(_DNS_COOKIE_VERSION) & 0xFF
    header = bytes([version, kid]) + struct.pack("!I", ts)
    mac_input = header + cc + _canonical_client_ip_bytes(client_ip)
    digest = hmac.new(secret_b, mac_input, hashlib.sha256).digest()
    # 2 + 4 + 10 = 16 byte server cookie
    return header + digest[:10]


def validate_server_cookie(
    *,
    client_cookie: bytes,
    server_cookie: bytes,
    client_ip: object,
    secret: Optional[bytes],
    secret_old: Optional[bytes] = None,
    lifetime_seconds: int = 86400,
    now: Optional[int] = None,
) -> bool:
    """Brief: Validate a server cookie against current/old secrets.

    Inputs:
      - client_cookie: 8-byte client cookie from the request.
      - server_cookie: Server cookie bytes from the request.
      - client_ip: Transport client IP.
      - secret: Current HMAC secret.
      - secret_old: Optional previous secret for rollover.
      - lifetime_seconds: Maximum cookie age.
      - now: Optional unix timestamp override.

    Outputs:
      - bool: True when the cookie is valid under at least one secret.
    """

    try:
        sc = bytes(server_cookie or b"")
        cc = bytes(client_cookie or b"")
    except Exception:
        return False
    if len(cc) != _DNS_COOKIE_CLIENT_BYTES:
        return False
    if len(sc) != _DNS_COOKIE_SERVER_BYTES:
        return False
    version = int(sc[0])
    key_id = int(sc[1])
    if version != _DNS_COOKIE_VERSION:
        return False
    if key_id not in (_DNS_COOKIE_KEY_ID_CURRENT, _DNS_COOKIE_KEY_ID_OLD):
        return False
    ts = int(struct.unpack("!I", sc[2:6])[0])
    now_i = int(time.time() if now is None else now)
    try:
        lifetime = max(1, int(lifetime_seconds))
    except Exception:
        lifetime = 86400
    if ts > now_i + int(_DNS_COOKIE_FUTURE_SKEW_SECONDS):
        return False
    if ts + lifetime < now_i:
        return False

    candidates: list[Tuple[int, bytes]] = []
    if secret:
        candidates.append((_DNS_COOKIE_KEY_ID_CURRENT, bytes(secret)))
    if secret_old:
        candidates.append((_DNS_COOKIE_KEY_ID_OLD, bytes(secret_old)))
    # Also accept current secret under key_id old during misconfig, but prefer
    # matching key_id first.
    for kid, key in candidates:
        if kid != key_id:
            continue
        try:
            expected = generate_server_cookie(
                client_cookie=cc,
                client_ip=client_ip,
                secret=key,
                key_id=kid,
                now=ts,
            )
        except Exception:
            continue
        if hmac.compare_digest(expected, sc):
            return True
    # Fallback: try all secrets regardless of key_id tag.
    for kid, key in candidates:
        try:
            expected = generate_server_cookie(
                client_cookie=cc,
                client_ip=client_ip,
                secret=key,
                key_id=key_id,
                now=ts,
            )
        except Exception:
            continue
        if hmac.compare_digest(expected, sc):
            return True
    return False


def classify_request_cookie(
    req: DNSRecord,
    *,
    client_ip: object,
    secret: Optional[bytes],
    secret_old: Optional[bytes] = None,
    lifetime_seconds: int = 86400,
    now: Optional[int] = None,
) -> str:
    """Brief: Classify inbound COOKIE state for require/learn policy.

    Inputs:
      - req: Parsed DNS request.
      - client_ip: Transport client IP.
      - secret/secret_old/lifetime_seconds/now: Validation inputs.

    Outputs:
      - str: one of none | client_only | valid | invalid
    """

    parsed = parse_cookie_from_request(req)
    if not parsed:
        return "none"
    client = parsed.get("client_cookie")
    server = parsed.get("server_cookie")
    if not isinstance(client, (bytes, bytearray)):
        return "none"
    if server is None:
        return "client_only"
    if validate_server_cookie(
        client_cookie=bytes(client),
        server_cookie=bytes(server),
        client_ip=client_ip,
        secret=secret,
        secret_old=secret_old,
        lifetime_seconds=lifetime_seconds,
        now=now,
    ):
        return "valid"
    return "invalid"


def build_badcookie_response(
    req: DNSRecord,
    *,
    client_ip: object,
    secret: bytes,
    now: Optional[int] = None,
) -> bytes:
    """Brief: Build a BADCOOKIE (RCODE 23) response with a fresh server cookie.

    Inputs:
      - req: Parsed client request.
      - client_ip: Transport client IP for cookie binding.
      - secret: Current cookie secret.
      - now: Optional timestamp override.

    Outputs:
      - bytes: Wire-format BADCOOKIE response.
    """

    try:
        req_id = int(getattr(getattr(req, "header", None), "id", 0) or 0)
    except Exception:
        req_id = 0
    try:
        resp = req.reply()
    except Exception:
        resp = DNSRecord(DNSHeader(id=req_id, qr=1, ra=1))
        try:
            if getattr(req, "q", None) is not None:
                resp.add_question(req.q)
        except Exception:
            pass
    # BADCOOKIE is RCODE 23: low 4 bits in header, high bits in OPT EXTENDED-RCODE.
    try:
        resp.header.rcode = int(RCODE_BADCOOKIE) & 0x0F
    except Exception:
        pass

    # Ensure OPT exists when client sent EDNS, then attach cookie.
    try:
        echo_client_edns(req, resp)
    except Exception:
        pass
    strip_cookie_options_from_response_record(resp)

    # Set EDNS extended RCODE high bits for full RCODE 23.
    try:
        opt_rr = None
        for rr in getattr(resp, "ar", None) or []:
            if getattr(rr, "rtype", None) == QTYPE.OPT:
                opt_rr = rr
                break
        if opt_rr is None:
            # Ensure an OPT exists so extended RCODE can be carried.
            client_opts = [
                rr
                for rr in (getattr(req, "ar", None) or [])
                if getattr(rr, "rtype", None) == QTYPE.OPT
            ]
            if client_opts:
                resp.add_ar(copy.deepcopy(client_opts[0]))
            else:
                resp.add_ar(EDNS0(udp_len=1232))
            for rr in getattr(resp, "ar", None) or []:
                if getattr(rr, "rtype", None) == QTYPE.OPT:
                    opt_rr = rr
                    break
        if opt_rr is not None:
            try:
                ttl_val = int(getattr(opt_rr, "ttl", 0) or 0) & 0xFFFFFFFF
            except Exception:
                ttl_val = 0
            ext_hi = (int(RCODE_BADCOOKIE) >> 4) & 0xFF
            version = (ttl_val >> 16) & 0xFF
            flags = ttl_val & 0xFFFF
            opt_rr.ttl = (ext_hi << 24) | (version << 16) | (flags & 0xFFFF)
    except Exception:
        pass

    client_cookie = extract_client_cookie_from_request(req)
    if client_cookie is not None and secret:
        try:
            server_cookie = generate_server_cookie(
                client_cookie=client_cookie,
                client_ip=client_ip,
                secret=secret,
                key_id=_DNS_COOKIE_KEY_ID_CURRENT,
                now=now,
            )
            opt_rr = None
            for rr in getattr(resp, "ar", None) or []:
                if getattr(rr, "rtype", None) == QTYPE.OPT:
                    opt_rr = rr
                    break
            if opt_rr is None:
                # Client had a cookie so it had EDNS; synthesize a minimal OPT.
                opt_rr = EDNS0(udp_len=1232)
                resp.add_ar(opt_rr)
            rdata_list = getattr(opt_rr, "rdata", None)
            if not isinstance(rdata_list, list):
                opt_rr.rdata = []
                rdata_list = opt_rr.rdata
            rdata_list.append(
                EDNSOption(
                    _EDNS_COOKIE_OPTION_CODE,
                    bytes(client_cookie) + bytes(server_cookie),
                )
            )
        except Exception:
            pass
    try:
        return resp.pack()
    except Exception:
        # Minimal fallback header-only BADCOOKIE.
        header = bytearray(12)
        header[0:2] = int(req_id).to_bytes(2, "big")
        header[2] = 0x80  # QR=1
        header[3] = int(RCODE_BADCOOKIE) & 0x0F
        return bytes(header)


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


def bind_response_cookie_to_request(
    req: DNSRecord,
    response_wire: bytes,
    *,
    client_ip: object = None,
    cookies_enabled: bool = False,
    secret: Optional[bytes] = None,
    now: Optional[int] = None,
) -> bytes:
    """Brief: Rebind response COOKIE for hygiene or RFC 7873 server cookies.

    Inputs:
      - req: Parsed DNS request.
      - response_wire: Wire-format DNS response bytes.
      - client_ip: Transport client IP used when minting server cookies.
      - cookies_enabled: When True, attach client||server cookie.
      - secret: HMAC secret for server cookie generation.
      - now: Optional timestamp override for server cookies.

    Outputs:
      - bytes: Updated response wire bytes.

    Notes:
      - Always strips stale upstream COOKIE options first.
      - When cookies_enabled is False, echoes only the 8-byte client cookie
        (legacy hygiene behavior).
      - When enabled and a client cookie is present, attaches a fresh server
        cookie bound to client_ip. Does not invent client cookies.
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

        # Drop any COOKIE options copied from the client OPT before attaching.
        strip_cookie_options_from_response_record(msg)

        cookie_payload = bytes(client_cookie)
        if cookies_enabled and secret:
            try:
                server_cookie = generate_server_cookie(
                    client_cookie=client_cookie,
                    client_ip=client_ip,
                    secret=secret,
                    key_id=_DNS_COOKIE_KEY_ID_CURRENT,
                    now=now,
                )
                cookie_payload = bytes(client_cookie) + bytes(server_cookie)
            except Exception:
                cookie_payload = bytes(client_cookie)

        rdata_list = getattr(opt_rr, "rdata", None)
        if not isinstance(rdata_list, list):
            opt_rr.rdata = []
            rdata_list = opt_rr.rdata
        rdata_list.append(EDNSOption(_EDNS_COOKIE_OPTION_CODE, cookie_payload))
        changed = True

        if changed:
            return msg.pack()
        return bytes(response_wire)
    except Exception:
        return response_wire
