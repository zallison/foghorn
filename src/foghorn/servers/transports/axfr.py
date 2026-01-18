from __future__ import annotations

import socket
import ssl
from typing import List, Optional, Tuple

from dnslib import DNSRecord, QTYPE, RR
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

    Outputs:
      - list[RR]: All RRs returned by the AXFR, including the initial and
        terminal SOA records.
    """

    zone_qname = (zone.rstrip(".") or ".") + "."

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

        # Send initial query frame.
        io_sock.sendall(frame)

        while True:
            hdr = _recv_exact(io_sock, 2)
            if len(hdr) != 2:
                break
            ln = int.from_bytes(hdr, "big")
            if ln <= 0:
                break

            body = _recv_exact(io_sock, ln)
            if len(body) != ln:
                raise AXFRError("short read while receiving AXFR response frame")

            seen_any_message = True
            try:
                resp = DNSRecord.parse(body)
            except Exception as exc:  # pragma: no cover - defensive
                raise AXFRError(f"failed to parse AXFR response: {exc}") from exc

            for rr in resp.rr:
                owner = str(rr.rname).rstrip(".").lower()
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
