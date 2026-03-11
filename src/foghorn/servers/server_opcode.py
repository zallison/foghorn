"""Opcode handling helpers shared by server resolution paths."""

import logging
from typing import NamedTuple, Optional

from dnslib import DNSHeader, DNSRecord, RCODE

from foghorn.plugins.resolve.base import PluginContext, PluginDecision

from .server_response_utils import _set_response_id

logger = logging.getLogger("foghorn.server")


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
    """

    if opcode == 0:
        return None

    import dns.message
    import dns.rcode

    try:
        msg = dns.message.from_wire(data)
    except Exception:
        # For signed messages (e.g. TSIG UPDATE) dnspython can raise when no
        # keyring is supplied. Retry with continue_on_error so we can still
        # recover opcode/question metadata for plugin dispatch and response
        # shaping.
        try:
            msg = dns.message.from_wire(data, continue_on_error=True)
        except Exception:
            msg = None

    qname = ""
    qtype = 0
    if msg is not None and getattr(msg, "question", None):
        try:
            q0 = msg.question[0]
            qname = str(getattr(q0, "name", "")).rstrip(".")
            qtype = int(getattr(q0, "rdtype", 0))
        except Exception:
            qname = ""
            qtype = 0

    ctx = PluginContext(client_ip=client_ip, listener=listener, secure=secure)
    try:
        ctx.qname = qname
    except Exception:  # pragma: no cover - defensive
        pass

    for p in sorted(handler.plugins, key=lambda p: getattr(p, "pre_priority", 50)):
        try:
            if hasattr(p, "targets_opcode") and not p.targets_opcode(opcode):
                continue
        except Exception:  # pragma: no cover - defensive
            pass

        try:
            decision = p.handle_opcode(opcode, qname, qtype, data, ctx)
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
                wire = _set_response_id(wire, int.from_bytes(data[0:2], "big"))
            except Exception:
                pass
            try:
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
                    mid = int.from_bytes(data[0:2], "big")
                except Exception:
                    mid = 0
                r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
                r.header.rcode = RCODE.REFUSED
                wire = r.pack()
            try:
                wire = _set_response_id(wire, int.from_bytes(data[0:2], "big"))
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
            mid = int.from_bytes(data[0:2], "big")
        except Exception:
            mid = 0
        r = DNSRecord(DNSHeader(id=mid, qr=1, ra=1, opcode=int(opcode)))
        r.header.rcode = RCODE.NOTIMP
        wire = r.pack()
    try:
        wire = _set_response_id(wire, int.from_bytes(data[0:2], "big"))
    except Exception:
        pass
    return _ResolveCoreResult(
        wire=wire,
        dnssec_status=None,
        upstream_id=None,
        rcode_name="NOTIMP",
    )
