from __future__ import annotations

import socket
import ssl
from typing import List, Optional, Tuple
import dns.exception
import dns.message
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring

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


def _normalize_tsig_algorithm(algorithm: str) -> str:
    """Brief: Normalize TSIG algorithm names to canonical short forms.

    Inputs:
      - algorithm: TSIG algorithm name (e.g. hmac-sha256., HMAC-SHA512).

    Outputs:
      - str: Canonical algorithm string accepted by dnspython.
    """
    alg = str(algorithm or "").strip().rstrip(".").lower()
    if "hmac-sha512" in alg:
        return "hmac-sha512"
    if "hmac-sha384" in alg:
        return "hmac-sha384"
    if "hmac-sha256" in alg:
        return "hmac-sha256"
    if "hmac-sha1" in alg:
        return "hmac-sha1"
    if "hmac-md5" in alg:
        return "hmac-md5"
    return alg or "hmac-sha256"


def _build_tsig_query_wire(
    zone_qname: str, tsig: dict
) -> tuple[bytes, dns.message.Message]:
    """Brief: Build an AXFR query wire signed with TSIG.

    Inputs:
      - zone_qname: Fully-qualified zone name.
      - tsig: Mapping with TSIG fields name/secret/algorithm.

    Outputs:
      - (wire, query): Wire-format DNS query bytes and dnspython query object.
    """
    key_name = tsig.get("name")
    key_secret = tsig.get("secret")
    if not key_name or not key_secret:
        raise AXFRError("AXFR TSIG requires 'name' and 'secret'")
    algorithm = _normalize_tsig_algorithm(tsig.get("algorithm", "hmac-sha256"))
    keyring = dns.tsigkeyring.from_text({str(key_name): str(key_secret)})
    query = dns.message.make_query(zone_qname, dns.rdatatype.AXFR)
    query.use_tsig(
        keyring=keyring,
        keyname=str(key_name),
        algorithm=algorithm,
    )
    try:
        wire = query.to_wire()
    except Exception as exc:  # pragma: no cover - defensive
        raise AXFRError(
            f"failed to build TSIG AXFR query for {zone_qname!r}: {exc}"
        ) from exc
    return wire, query


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
    tsig: Optional[dict] = None,
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
      - tsig: Optional TSIG config mapping with name/secret/algorithm.

    Outputs:
      - list[RR]: All RRs returned by the AXFR, including the initial and
        terminal SOA records.
    """

    zone_qname = f"{dns_names.normalize_name(zone) or '.'}."

    dpy_query: Optional[dns.message.Message] = None
    if tsig and isinstance(tsig, dict):
        payload, dpy_query = _build_tsig_query_wire(zone_qname, tsig)
    else:
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
        tsig_ctx = None
        had_tsig_response = False
        last_frame_had_tsig = False

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
                if dpy_query is not None:
                    parsed = dns.message.from_wire(
                        body,
                        keyring=dpy_query.keyring,
                        request_mac=dpy_query.mac,
                        xfr=True,
                        tsig_ctx=tsig_ctx,
                        multi=True,
                    )
                    tsig_ctx = parsed.tsig_ctx
                    last_frame_had_tsig = bool(parsed.had_tsig)
                    had_tsig_response = had_tsig_response or last_frame_had_tsig
                resp = DNSRecord.parse(body)
            except (
                dns.tsig.BadSignature,
                dns.tsig.PeerBadTime,
                dns.tsig.PeerBadKey,
                dns.exception.DNSException,
            ) as exc:
                raise AXFRError(
                    f"failed TSIG validation for AXFR response: {exc}"
                ) from exc
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
                        if dpy_query is not None and not last_frame_had_tsig:
                            raise AXFRError("AXFR response missing TSIG")
                        rrs.append(rr)
                        return rrs
                rrs.append(rr)

        if dpy_query is not None and not had_tsig_response:
            raise AXFRError("AXFR response missing TSIG")

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
