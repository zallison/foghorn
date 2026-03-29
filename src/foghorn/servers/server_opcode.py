"""Opcode handling helpers shared by server resolution paths.

Notes:
  - Non-QUERY opcode dispatch (e.g. NOTIFY/UPDATE) may carry TSIG (RFC 2845).
    When a TSIG is present, this module attempts best-effort MAC verification
    before dispatching to plugins. If no TSIG keys are configured, TSIG-signed
    messages are refused.
"""

import logging
import time
from typing import NamedTuple, Optional

from dnslib import RCODE, DNSHeader, DNSRecord
from foghorn.utils import dns_names, ip_networks

from foghorn.plugins.resolve.base import PluginContext, PluginDecision

from .server_response_utils import _set_response_id

logger = logging.getLogger("foghorn.server")

# Generous ceiling for non-QUERY messages (UPDATE/NOTIFY) to reduce CPU/memory
# exposure to oversized payloads while still supporting realistic operational
# use.
MAX_NON_QUERY_BYTES = 8192

# Default per-opcode, per-source-IP rate limit for non-QUERY opcodes.
# Intended as a lightweight safety net distinct from the adaptive RateLimit
# plugin (which typically targets QUERY traffic).
NON_QUERY_RATE_LIMIT_PER_SEC = 10

# Module-local caches for hot-path helpers.
_OP_PLUGINS_SORT_CACHE: dict[tuple[int, ...], list[object]] = {}
_OP_RATE_BUCKETS: dict[tuple[int, str], tuple[int, int]] = {}
_OP_RATE_BUCKET_MAX_ENTRIES = 4096
_OP_RATE_BUCKET_RETENTION_SECONDS = 3
_OP_RATE_LAST_PRUNE_BUCKET = -1


class _ResolveCoreResult(NamedTuple):
    """Internal result for the shared resolve pipeline.

    Inputs:
      - None (constructed by shared resolver helpers).
    Outputs:
      - wire: Final DNS response bytes with ID fixed.
      - dnssec_status: Optional DNSSEC status string.
      - upstream_id: Optional upstream identifier string.
      - rcode_name: Textual rcode name.
    """

    wire: bytes
    dnssec_status: Optional[str]
    upstream_id: Optional[str]
    rcode_name: str


def _prune_op_rate_buckets(now_bucket: int) -> None:
    """Brief: Prune stale non-query rate-limit buckets and enforce a hard cap.

    Inputs:
      - now_bucket: Current 1-second time bucket used by the rate limiter.

    Outputs:
      - None; mutates the module-local _OP_RATE_BUCKETS map in place.
    """
    try:
        retention_seconds = max(1, int(_OP_RATE_BUCKET_RETENTION_SECONDS))
    except Exception:
        retention_seconds = 3
    stale_before = int(now_bucket) - retention_seconds

    if _OP_RATE_BUCKETS:
        stale_keys = [
            key
            for key, (bucket, _count) in _OP_RATE_BUCKETS.items()
            if bucket < stale_before
        ]
        for key in stale_keys:
            _OP_RATE_BUCKETS.pop(key, None)

    try:
        max_entries = max(1, int(_OP_RATE_BUCKET_MAX_ENTRIES))
    except Exception:
        max_entries = 4096
    overflow = len(_OP_RATE_BUCKETS) - max_entries
    if overflow > 0:
        # dict preserves insertion order; dropping oldest entries keeps memory bounded.
        for key in list(_OP_RATE_BUCKETS.keys())[:overflow]:
            _OP_RATE_BUCKETS.pop(key, None)


def _handle_non_query_opcode(
    *,
    opcode: int,
    data: bytes,
    client_ip: str,
    listener: Optional[str],
    secure: Optional[bool],
    handler,
) -> Optional[_ResolveCoreResult]:
    """Brief: Handle non-QUERY opcodes via plugin.handle_opcode().

    Inputs:
      - opcode: DNS opcode parsed from the wire header.
      - data: Original wire-format DNS message bytes.
      - client_ip: Source client IP string for plugin context.
      - listener: Optional listener label ("udp", "tcp", "dot", "doh").
      - secure: Optional transport security flag for plugin context.
      - handler: Runtime handler-like object exposing plugins.

    Outputs:
      - _ResolveCoreResult when handled (drop/override/deny/notimp), else None.

    Notes:
      - UPDATE/NOTIFY messages may be TSIG-signed. When a TSIG is present and
        keys are configured, we attempt MAC verification before plugin dispatch.
        When a TSIG is present but no keys are configured, we refuse.
    """

    if opcode == 0:
        return None

    raw_data = data
    data_bytes = data if isinstance(data, (bytes, bytearray)) else b""

    # Size ceiling before any dnspython parsing.
    if len(data_bytes) > int(MAX_NON_QUERY_BYTES):
        # Oversized non-QUERY messages are refused to reduce parser load.
        try:
            mid = int.from_bytes(data_bytes[0:2], "big") if len(data_bytes) >= 2 else 0
        except Exception:
            mid = 0
        r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
        r.header.rcode = RCODE.REFUSED
        wire = r.pack()
        return _ResolveCoreResult(
            wire=wire,
            dnssec_status=None,
            upstream_id=None,
            rcode_name="REFUSED",
        )

    # Lightweight per-opcode, per-source-IP rate limiter (1-second buckets).
    try:
        limit = int(NON_QUERY_RATE_LIMIT_PER_SEC)
    except Exception:
        limit = 0
    if limit > 0 and client_ip:
        global _OP_RATE_LAST_PRUNE_BUCKET
        now_bucket = int(time.time())
        if now_bucket != _OP_RATE_LAST_PRUNE_BUCKET:
            _prune_op_rate_buckets(now_bucket)
            _OP_RATE_LAST_PRUNE_BUCKET = now_bucket
        elif len(_OP_RATE_BUCKETS) > int(_OP_RATE_BUCKET_MAX_ENTRIES):
            _prune_op_rate_buckets(now_bucket)
        key = (int(opcode), str(client_ip))
        prev_bucket, prev_count = _OP_RATE_BUCKETS.get(key, (now_bucket, 0))
        if prev_bucket != now_bucket:
            prev_bucket, prev_count = now_bucket, 0
        prev_count += 1
        _OP_RATE_BUCKETS[key] = (prev_bucket, prev_count)
        if prev_count > limit:
            try:
                mid = (
                    int.from_bytes(data_bytes[0:2], "big")
                    if len(data_bytes) >= 2
                    else 0
                )
            except Exception:
                mid = 0
            r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
            r.header.rcode = RCODE.REFUSED
            wire = r.pack()
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="REFUSED",
            )

    # For NOTIFY (opcode 4), enforce the AXFR/NOTIFY allowlist when configured.
    if int(opcode) == 4:
        try:
            from foghorn.runtime_config import get_runtime_snapshot

            snap = get_runtime_snapshot()
            allow_raw = list(getattr(snap, "axfr_allow_clients", []) or [])
            enabled = bool(getattr(snap, "axfr_enabled", False))
        except Exception:
            allow_raw = []
            enabled = False
        if enabled:
            allowed = ip_networks.ip_string_in_cidrs(str(client_ip).strip(), allow_raw)
            if not allowed:
                try:
                    mid = (
                        int.from_bytes(data_bytes[0:2], "big")
                        if len(data_bytes) >= 2
                        else 0
                    )
                except Exception:
                    mid = 0
                r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
                r.header.rcode = RCODE.REFUSED
                wire = r.pack()
                return _ResolveCoreResult(
                    wire=wire,
                    dnssec_status=None,
                    upstream_id=None,
                    rcode_name="REFUSED",
                )

    # dnspython is optional; if unavailable, return a minimal NOTIMP.
    try:
        import dns.message
        import dns.rcode
    except ImportError:
        try:
            mid = int.from_bytes(data_bytes[0:2], "big") if len(data_bytes) >= 2 else 0
        except Exception:
            mid = 0
        r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
        r.header.rcode = RCODE.NOTIMP
        wire = r.pack()
        return _ResolveCoreResult(
            wire=wire,
            dnssec_status=None,
            upstream_id=None,
            rcode_name="NOTIMP",
        )

    try:
        msg = dns.message.from_wire(data_bytes)
    except Exception:
        # For signed messages (e.g. TSIG UPDATE) dnspython can raise when no
        # keyring is supplied. Retry with continue_on_error so we can still
        # recover opcode/question metadata for plugin dispatch and response
        # shaping. TSIG verification (when possible) is performed before plugin
        # dispatch.
        try:
            msg = dns.message.from_wire(data_bytes, continue_on_error=True)
        except Exception:
            msg = None

    qname = ""
    qtype = 0
    if msg is not None and getattr(msg, "question", None):
        try:
            q0 = msg.question[0]
            qname = dns_names.normalize_name(getattr(q0, "name", ""))
            qtype = int(getattr(q0, "rdtype", 0))
        except Exception:
            qname = ""
            qtype = 0

    # If dnspython parsed with continue_on_error, extracted question metadata may
    # be partial. Perform a basic sanity check before surfacing it to plugins.
    def _looks_like_dns_name(text: str) -> bool:
        """Brief: Minimal qname validation for plugin context.

        Inputs:
          - text: Candidate domain name (no trailing dot).

        Outputs:
          - bool: True when the string resembles a plausible DNS name.
        """
        try:
            s = str(text or "")
        except Exception:
            return False
        if not s:
            return False
        if len(s) > 253:
            return False
        # Allow underscore for SRV-like names.
        allowed = set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
        )
        if any(ch not in allowed for ch in s):
            return False
        for label in s.split("."):
            if not label:
                return False
            if len(label) > 63:
                return False
            if label.startswith("-") or label.endswith("-"):
                return False
        return True

    if qname and not _looks_like_dns_name(qname):
        logger.debug("Non-query opcode parse yielded malformed qname=%r", qname)
        qname = ""
        qtype = 0

    # Best-effort TSIG verification before plugin dispatch.
    if msg is not None and getattr(msg, "had_tsig", False):
        from foghorn.plugins.resolve.zone_records import update_helpers
        from foghorn.plugins.resolve.zone_records import update_processor

        # Gather TSIG key configs across ZoneRecords instances.
        key_configs: list[dict] = []
        try:
            plugins = list(getattr(handler, "plugins", []) or [])
        except Exception:
            plugins = []
        for plug in plugins:
            dns_update_cfg = getattr(plug, "_dns_update_config", None)
            if not isinstance(dns_update_cfg, dict):
                continue
            zones = dns_update_cfg.get("zones", []) or []
            if not isinstance(zones, list):
                continue
            source_loaders = getattr(plug, "_dns_update_tsig_key_source_loaders", None)
            if not isinstance(source_loaders, dict):
                source_loaders = None
            for zone_cfg in zones:
                if not isinstance(zone_cfg, dict):
                    continue
                try:
                    key_configs.extend(
                        update_helpers.resolve_tsig_key_configs(
                            zone_cfg,
                            source_loaders=source_loaders,
                        )
                    )
                except Exception:
                    continue

        if not key_configs:
            logger.warning(
                "TSIG-signed opcode %s from %s rejected: no keyring configured",
                opcode,
                client_ip,
            )
            if msg is not None:
                resp = dns.message.make_response(msg)
                resp.set_rcode(dns.rcode.REFUSED)
                wire = resp.to_wire()
            else:
                try:
                    mid = (
                        int.from_bytes(data_bytes[0:2], "big")
                        if len(data_bytes) >= 2
                        else 0
                    )
                except Exception:
                    mid = 0
                r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
                r.header.rcode = RCODE.REFUSED
                wire = r.pack()
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="REFUSED",
            )

        ok, err, _cfg = update_processor.verify_tsig_auth(
            data_bytes, key_configs=key_configs
        )
        if not ok:
            logger.warning(
                "TSIG-signed opcode %s from %s rejected: %s",
                opcode,
                client_ip,
                err or "TSIG verification failed",
            )
            if msg is not None:
                resp = dns.message.make_response(msg)
                resp.set_rcode(dns.rcode.REFUSED)
                wire = resp.to_wire()
            else:
                try:
                    mid = (
                        int.from_bytes(data_bytes[0:2], "big")
                        if len(data_bytes) >= 2
                        else 0
                    )
                except Exception:
                    mid = 0
                r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
                r.header.rcode = RCODE.REFUSED
                wire = r.pack()
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="REFUSED",
            )

    ctx = PluginContext(client_ip=client_ip, listener=listener, secure=secure)
    try:
        ctx.qname = qname
    except Exception:  # pragma: no cover - defensive
        pass

    try:
        plugins_list = list(getattr(handler, "plugins", []) or [])
    except Exception:
        plugins_list = []
    cache_key = tuple([len(plugins_list)] + [int(id(p)) for p in plugins_list])
    ordered = _OP_PLUGINS_SORT_CACHE.get(cache_key)
    if ordered is None:
        ordered = sorted(plugins_list, key=lambda p: getattr(p, "pre_priority", 50))
        _OP_PLUGINS_SORT_CACHE[cache_key] = ordered
        # Best-effort cache bound.
        if len(_OP_PLUGINS_SORT_CACHE) > 256:
            _OP_PLUGINS_SORT_CACHE.clear()

    for p in ordered:
        try:
            if hasattr(p, "targets_opcode") and not p.targets_opcode(opcode):
                continue
        except Exception:  # pragma: no cover - defensive
            pass

        try:
            decision = p.handle_opcode(opcode, qname, qtype, raw_data, ctx)
        except Exception:  # pragma: no cover - defensive
            logger.warning("Plugin handle_opcode() raised", exc_info=True)
            continue

        if not isinstance(decision, PluginDecision):
            continue

        if decision.action == "drop":
            return _ResolveCoreResult(
                wire=b"",
                dnssec_status=None,
                upstream_id=None,
                rcode_name="DROP",
            )

        if decision.action == "override" and decision.response is not None:
            wire = decision.response
            # Ensure the response ID matches the request ID.
            try:
                wire = _set_response_id(wire, int.from_bytes(data_bytes[0:2], "big"))
            except Exception:
                pass
            # Ensure QR bit is set in case a plugin accidentally returns a query.
            try:
                if len(wire) >= 3 and not (wire[2] & 0x80):
                    wire = wire[:2] + bytes([wire[2] | 0x80]) + wire[3:]
            except Exception:
                pass
            try:
                # dnslib expects at least a full DNS header (12 bytes). For
                # shorter payloads, keep a synthetic label rather than deriving
                # an arbitrary rcode from partial flags.
                if len(wire) < 12:
                    raise ValueError("override wire too short")
                parsed = DNSRecord.parse(wire)
                rcode_name = RCODE.get(parsed.header.rcode, str(parsed.header.rcode))
            except Exception:
                rcode_name = "OVERRIDE"
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=None,
                rcode_name=str(rcode_name),
            )

        if decision.action == "deny":
            if msg is not None:
                resp = dns.message.make_response(msg)
                resp.set_rcode(dns.rcode.REFUSED)
                wire = resp.to_wire()
            else:
                # Worst-case: return a bare REFUSED header without parsing.
                try:
                    mid = int.from_bytes(data_bytes[0:2], "big")
                except Exception:
                    mid = 0
                r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
                r.header.rcode = RCODE.REFUSED
                wire = r.pack()
                try:
                    wire = _set_response_id(
                        wire, int.from_bytes(data_bytes[0:2], "big")
                    )
                except Exception:
                    pass
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="REFUSED",
            )

    # Default: no plugin handled this opcode.
    if msg is not None:
        resp = dns.message.make_response(msg)
        resp.set_rcode(dns.rcode.NOTIMP)
        wire = resp.to_wire()
    else:
        # Worst-case: return a bare NOTIMP header without parsing.
        try:
            mid = int.from_bytes(data_bytes[0:2], "big")
        except Exception:
            mid = 0
        r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
        r.header.rcode = RCODE.NOTIMP
        wire = r.pack()
        try:
            wire = _set_response_id(wire, int.from_bytes(data_bytes[0:2], "big"))
        except Exception:
            pass
    return _ResolveCoreResult(
        wire=wire,
        dnssec_status=None,
        upstream_id=None,
        rcode_name="NOTIMP",
    )
