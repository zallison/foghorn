from __future__ import annotations

import socket
import ssl
from typing import List, Optional, Tuple

from dnslib import QTYPE, RR, DNSRecord

from foghorn.security_limits import MAX_AXFR_FRAME_BYTES
from foghorn.utils import dns_names

from .dot import _build_ssl_context


class AXFRError(Exception):
    """Brief: DNS AXFR (full zone transfer) error.

    Inputs:
      - message: Short description of the failure.

    Outputs:
      - Exception instance indicating an AXFR-specific failure.
    """

    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Brief: Receive exactly *n* bytes from a blocking TCP socket.

    Inputs:
      - sock: Connected TCP socket.
      - n: Number of bytes to read.

    Outputs:
      - bytes: Exactly *n* bytes unless EOF occurs early.
    """

    remaining = n
    chunks: List[bytes] = []
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def axfr_transfer(
    host: str,
    port: int,
    zone: str,
    *,
    transport: str = "tcp",
    server_name: Optional[str] = None,
    verify: bool = True,
    ca_file: Optional[str] = None,
    connect_timeout_ms: int = 2000,
    read_timeout_ms: int = 5000,
    max_rrs: Optional[int] = None,
    max_total_bytes: Optional[int] = None,
) -> List[RR]:
    """Brief: Perform a blocking AXFR for *zone* over TCP or DoT and return all RRs.

    Inputs:
      - host: Master server host/IP.
      - port: Master server port (TCP or DoT; usually 53 or 853).
      - zone: Zone apex to transfer (with or without trailing dot).
      - transport: "tcp" (default) for plain TCP or "dot" for DNS-over-TLS.
      - server_name: Optional TLS SNI / verification name for DoT.
      - verify: Whether to verify TLS certificates for DoT.
      - ca_file: Optional path to CA bundle for DoT.
      - connect_timeout_ms: TCP connect timeout in milliseconds.
      - read_timeout_ms: Per-read timeout in milliseconds.
      - max_rrs: Optional maximum number of RRs allowed before aborting.
      - max_total_bytes: Optional maximum total response bytes allowed.

    Outputs:
      - list[RR]: All RRs returned by the AXFR, including the initial and
        terminal SOA records.
    """

    zone_qname = f"{dns_names.normalize_name(zone) or '.'}."

    try:
        q = DNSRecord.question(zone_qname, "AXFR")
    except Exception as exc:  # pragma: no cover - defensive
        raise AXFRError(
            f"failed to build AXFR query for {zone_qname!r}: {exc}"
        ) from exc

    payload = q.pack()
    length_prefix = len(payload).to_bytes(2, "big")
    frame = length_prefix + payload

    sock: Optional[socket.socket] = None
    tls_sock: Optional[socket.socket] = None
    io_sock: Optional[socket.socket] = None

    try:
        try:
            sock = socket.create_connection(
                (host, int(port)), timeout=connect_timeout_ms / 1000.0
            )
        except OSError as exc:  # pragma: no cover - network/environment dependent
            raise AXFRError(f"AXFR connect to {host}:{port} failed: {exc}") from exc

        transport_norm = (transport or "tcp").lower()
        if transport_norm == "dot":
            # Build TLS context consistent with other DoT helpers.
            ctx = _build_ssl_context(server_name, verify=bool(verify), ca_file=ca_file)
            try:
                tls_sock = ctx.wrap_socket(
                    sock, server_hostname=server_name if verify else None
                )
            except ssl.SSLError as exc:  # pragma: no cover - environment dependent
                raise AXFRError(
                    f"AXFR TLS handshake to {host}:{port} failed: {exc}"
                ) from exc
            io_sock = tls_sock
        else:
            io_sock = sock

        assert io_sock is not None  # for type checkers; logically always set above
        io_sock.settimeout(read_timeout_ms / 1000.0)

        rrs: List[RR] = []
        first_soa_key: Tuple[str, str] | None = None
        seen_any_message = False
        total_bytes = 0
        rr_count = 0

        # Send initial query frame.
        io_sock.sendall(frame)

        while True:
            hdr = _recv_exact(io_sock, 2)
            if len(hdr) != 2:
                break
            ln = int.from_bytes(hdr, "big")
            if ln <= 0:
                break
            if ln > int(MAX_AXFR_FRAME_BYTES):
                raise AXFRError(
                    f"AXFR response frame too large ({ln} bytes > {int(MAX_AXFR_FRAME_BYTES)})"
                )

            body = _recv_exact(io_sock, ln)
            if len(body) != ln:
                raise AXFRError("short read while receiving AXFR response frame")

            seen_any_message = True
            total_bytes += ln
            if max_total_bytes is not None and max_total_bytes > 0:
                if total_bytes > int(max_total_bytes):
                    raise AXFRError(
                        "AXFR response exceeded max_total_bytes "
                        f"({total_bytes} > {int(max_total_bytes)})"
                    )
            try:
                resp = DNSRecord.parse(body)
            except Exception as exc:  # pragma: no cover - defensive
                raise AXFRError(f"failed to parse AXFR response: {exc}") from exc

            for rr in resp.rr:
                rr_count += 1
                if max_rrs is not None and max_rrs > 0:
                    if rr_count > int(max_rrs):
                        raise AXFRError(
                            "AXFR response exceeded max_rrs "
                            f"({rr_count} > {int(max_rrs)})"
                        )
                owner = dns_names.normalize_name(rr.rname)
                rdata_text = str(rr.rdata)
                if rr.rtype == QTYPE.SOA:
                    key = (owner, rdata_text)
                    if first_soa_key is None:
                        first_soa_key = key
                    elif first_soa_key == key:
                        rrs.append(rr)
                        return rrs
                rrs.append(rr)

    except (
        OSError,
        TimeoutError,
        ssl.SSLError,
    ) as exc:  # pragma: no cover - environment dependent
        raise AXFRError(f"AXFR I/O error from {host}:{port}: {exc}") from exc
    finally:
        # Close TLS socket first (if any), then the underlying TCP socket.
        try:
            if tls_sock is not None:
                try:
                    tls_sock.close()
                except Exception:  # pragma: no cover - defensive
                    pass
            if sock is not None:
                try:
                    sock.close()
                except Exception:  # pragma: no cover - defensive
                    pass
        except Exception:  # pragma: no cover - defensive
            pass

    if not seen_any_message:
        raise AXFRError(f"AXFR from {host}:{port} for {zone_qname!r} returned no data")

    raise AXFRError(
        f"AXFR from {host}:{port} for {zone_qname!r} did not terminate with a matching SOA",
    )
