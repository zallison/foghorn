import logging
import os
import socket
import ssl
import threading
import tempfile
import time
from typing import Optional

from foghorn.utils.register_caches import registered_lru_cache

logger = logging.getLogger("foghorn.servers.transports.dot")

_SSL_DETAILS_LOGGED_ATTR = "_foghorn_ssl_details_logged"


class DoTError(Exception):
    """
    A DNS-over-TLS transport error.

    Inputs:
      - message: A short error description.
    Outputs:
      - Exception instance.

    Brief: Raised for TLS connect/read/write or protocol framing errors.
    """

    pass


def _format_subject(subject: object) -> str | None:
    """
    Format decoded certificate subject tuples into `key=value` components.

    Inputs:
      - subject: Subject object from decoded certificate metadata.
    Outputs:
      - str | None: Comma-separated subject string when available.
    """

    if not isinstance(subject, (list, tuple)):
        return None
    components: list[str] = []
    for rdn in subject:
        if not isinstance(rdn, (list, tuple)):
            continue
        for attribute in rdn:
            if (
                isinstance(attribute, (list, tuple))
                and len(attribute) >= 2
                and attribute[0]
            ):
                components.append(f"{attribute[0]}={attribute[1]}")
    return ", ".join(components) if components else None


def _decode_cert_subject_from_file(cert_file: str) -> str | None:
    """
    Decode a certificate file and return a formatted `Subject:` value.

    Inputs:
      - cert_file: Path to the certificate file.
    Outputs:
      - str | None: Formatted subject string, or None when unavailable.
    """

    try:
        decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
        if not callable(decoder):
            return None
        decoded = decoder(cert_file)
        if not isinstance(decoded, dict):
            return None
        return _format_subject(decoded.get("subject"))
    except Exception:
        return None


def _decode_cert_subject_from_der(der_cert: bytes) -> str | None:
    """
    Decode DER certificate bytes and return a formatted subject string.

    Inputs:
      - der_cert: DER-encoded certificate bytes.
    Outputs:
      - str | None: Formatted subject string, or None if decode fails.
    """

    tmp_path: str | None = None
    try:
        pem_text = ssl.DER_cert_to_PEM_cert(der_cert)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".pem", delete=False
        ) as tmp:
            tmp.write(pem_text)
            tmp_path = tmp.name
        return _decode_cert_subject_from_file(tmp_path)
    except Exception:
        return None
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _probe_remote_cert_subject(
    host: str,
    port: int,
    *,
    server_hostname: Optional[str] = None,
    timeout_seconds: float = 1.2,
) -> str | None:
    """
    Best-effort probe to fetch remote certificate subject without verification.

    Inputs:
      - host: Remote host.
      - port: Remote TLS port.
      - server_hostname: Optional SNI hostname.
      - timeout_seconds: Probe timeout in seconds.
    Outputs:
      - str | None: Remote certificate subject string when obtainable.
    """

    raw_sock: Optional[socket.socket] = None
    tls_sock: Optional[socket.socket] = None
    try:
        raw_sock = socket.create_connection((host, int(port)), timeout=timeout_seconds)
        ctx = ssl._create_unverified_context()
        tls_sock = ctx.wrap_socket(
            raw_sock, server_hostname=server_hostname or host
        )  # type: ignore[arg-type]
        cert_dict = tls_sock.getpeercert()
        subject = _format_subject(
            cert_dict.get("subject") if isinstance(cert_dict, dict) else None
        )
        if subject:
            return subject
        der_cert = tls_sock.getpeercert(binary_form=True)
        if der_cert:
            return _decode_cert_subject_from_der(der_cert)
    except Exception:
        return None
    finally:
        try:
            if tls_sock is not None:
                tls_sock.close()
        except Exception:
            pass
        try:
            if raw_sock is not None:  # pragma: nocover - defensive finalizer branch
                raw_sock.close()
        except Exception:
            pass
    return None


def _describe_local_cert_file(cert_file: Optional[str]) -> str:
    """
    Describe local certificate file details including parsed subject if possible.

    Inputs:
      - cert_file: Optional certificate path.
    Outputs:
      - str: Human-readable description for warning logs.
    """

    if not cert_file:
        return "not configured"
    if not os.path.exists(cert_file):
        return f"path={cert_file!r} (missing)"
    if not os.path.isfile(cert_file):
        return f"path={cert_file!r} (not a regular file)"
    subject = _decode_cert_subject_from_file(cert_file)
    if subject:
        return f"path={cert_file!r}, Subject: {subject}"
    return f"path={cert_file!r}, Subject: unavailable"


def _describe_local_key_file(key_file: Optional[str]) -> str:
    """
    Describe local key file details for warning logs.

    Inputs:
      - key_file: Optional private-key path.
    Outputs:
      - str: Human-readable key-file description.
    """

    if not key_file:
        return "not configured"
    if not os.path.exists(key_file):
        return f"path={key_file!r} (missing)"
    if not os.path.isfile(key_file):
        return f"path={key_file!r} (not a regular file)"
    return f"path={key_file!r}"


def _describe_ca_source(*, verify: bool | None, ca_file: Optional[str]) -> str:
    """
    Describe which CA trust source was used for TLS verification.

    Inputs:
      - verify: Whether certificate verification is enabled.
      - ca_file: Optional CA bundle path.
    Outputs:
      - str: CA source description.
    """

    if verify is False:
        return "verification disabled (verify=False)"
    if ca_file:
        return f"file ({ca_file})"
    return "system trust store"


def _infer_ssl_error_hints(
    error: BaseException,
    *,
    server_hostname: Optional[str] = None,
    ca_file: Optional[str] = None,
) -> list[str]:
    """
    Infer likely causes for DoT SSL/TLS failures from exception content.

    Inputs:
      - error: Caught SSL/TLS-related exception.
      - server_hostname: Optional TLS SNI/verification hostname.
      - ca_file: Optional CA bundle path.
    Outputs:
      - list[str]: Human-readable probable causes for warning logs.
    """

    message = str(error)
    lowered = message.lower()
    hints: list[str] = []

    if (
        isinstance(error, FileNotFoundError)
        or "no such file" in lowered
        or "file not found" in lowered
    ):
        if ca_file:
            hints.append(f"CA file not found: {ca_file}")
        else:
            hints.append("certificate/key/CA file not found")

    if (
        "pem" in lowered
        or "asn1" in lowered
        or "bad base64 decode" in lowered
        or "no start line" in lowered
        or "unable to load certificate" in lowered
        or "unable to load private key" in lowered
    ):
        hints.append("certificate/key is not valid PEM/ASN.1 data")

    if isinstance(error, ssl.SSLCertVerificationError):
        if (
            "hostname" in lowered
            or "ip address mismatch" in lowered
            or "doesn't match" in lowered
            or "does not match" in lowered
        ):
            if server_hostname:
                hints.append(
                    f"certificate name mismatch for hostname {server_hostname!r}"
                )
            else:
                hints.append(
                    "certificate name mismatch (set server_name/server_hostname)"
                )
        if (
            "certificate verify failed" in lowered
            or "self signed" in lowered
            or "unknown ca" in lowered
            or "unable to get local issuer certificate" in lowered
        ):
            hints.append("certificate chain is not trusted by configured CA bundle")
        if "expired" in lowered or "not yet valid" in lowered:
            hints.append("certificate validity period is not currently valid")

    if (
        "wrong version number" in lowered
        or "unsupported protocol" in lowered
        or "protocol version" in lowered
        or "handshake failure" in lowered
    ):
        hints.append("TLS protocol/cipher mismatch during handshake")

    if not hints:
        hints.append(
            "verify CA bundle path, certificate format, and TLS server hostname/SNI"
        )

    return hints


def _warn_ssl_error_details(
    error: BaseException,
    *,
    phase: str,
    host: Optional[str] = None,
    port: Optional[int] = None,
    verify: bool | None = None,
    server_hostname: Optional[str] = None,
    cert_file: Optional[str] = None,
    key_file: Optional[str] = None,
    ca_file: Optional[str] = None,
) -> None:
    """
    Emit one warning log with SSL/TLS likely-cause hints for DoT operations.

    Inputs:
      - error: Caught SSL/TLS-related exception.
      - phase: Short operation stage label (e.g. "context setup", "handshake").
      - host: Optional upstream host.
      - port: Optional upstream port.
      - verify: Optional TLS verification flag.
      - server_hostname: Optional TLS SNI/verification hostname.
      - cert_file: Optional local certificate path.
      - key_file: Optional local private-key path.
      - ca_file: Optional CA bundle path.
    Outputs:
      - None. Emits at most one warning per exception instance.
    """

    if getattr(error, _SSL_DETAILS_LOGGED_ATTR, False):
        return

    hints = _infer_ssl_error_hints(
        error,
        server_hostname=server_hostname,
        ca_file=ca_file,
    )
    target = ""
    if host is not None and port is not None:
        target = f" for {host}:{int(port)}"

    remote_subject = None
    if host is not None and port is not None:
        remote_subject = _probe_remote_cert_subject(
            host,
            int(port),
            server_hostname=server_hostname,
        )

    logger.warning(
        "DoT TLS %s warning%s: %s. Remote cert Subject: %s. Local cert: %s. Local key: %s. CA source: %s. Likely causes: %s",
        phase,
        target,
        error,
        remote_subject or "unavailable",
        _describe_local_cert_file(cert_file),
        _describe_local_key_file(key_file),
        _describe_ca_source(verify=verify, ca_file=ca_file),
        "; ".join(hints),
    )
    try:
        setattr(error, _SSL_DETAILS_LOGGED_ATTR, True)
    except Exception:
        pass


@registered_lru_cache(maxsize=64)
def _build_ssl_context(
    server_hostname: Optional[str],
    verify: bool = True,
    ca_file: Optional[str] = None,
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
) -> ssl.SSLContext:
    """
    Build an SSLContext for DoT connections.

    Inputs:
      - server_hostname: Expected TLS server name (SNI/verify). May be None if verify is False.
      - verify: Whether to verify certificates.
      - ca_file: Optional path to a CA bundle.
      - min_version: Minimum TLS version; default TLS 1.2.
    Outputs:
      - ssl.SSLContext configured for client use.

    Example:
      >>> ctx = _build_ssl_context('cloudflare-dns.com', True, None)
    """
    try:
        ctx = (
            ssl.create_default_context(cafile=ca_file)
            if verify
            else ssl._create_unverified_context()
        )
    except (ssl.SSLError, OSError, ValueError) as exc:
        _warn_ssl_error_details(
            exc,
            phase="context setup",
            verify=verify,
            server_hostname=server_hostname,
            ca_file=ca_file,
        )
        raise
    ctx.minimum_version = min_version
    # RFC7858 recommends TLS 1.2 or later; HTTP/2 ciphers are fine but not required here.
    return ctx


class _DotConn:
    """
    A single DoT connection used for one in-flight query at a time.

    Inputs:
      - host, port: Upstream target.
      - ctx: SSLContext.
      - server_name: SNI value.
      - verify: Whether certificate verification is enabled.
      - ca_file: Optional CA bundle path used for diagnostics.
    Outputs:
      - Instance capable of send(query_bytes)->response_bytes.

    Brief: Manages one TLS socket; not safe for concurrent in-flight queries.
    """

    def __init__(
        self,
        host: str,
        port: int,
        ctx: ssl.SSLContext,
        server_name: Optional[str],
        verify: bool,
        ca_file: Optional[str],
    ):
        self._host = host
        self._port = int(port)
        self._ctx = ctx
        self._server_name = server_name
        self._verify = bool(verify)
        self._ca_file = ca_file
        self._sock = None  # type: Optional[socket.socket]
        self._tls = None  # type: Optional[socket.socket]
        self._last_used = time.time()

    def connect(self, connect_timeout_ms: int):
        self.close()
        s = socket.create_connection(
            (self._host, self._port), timeout=connect_timeout_ms / 1000.0
        )
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            t = self._ctx.wrap_socket(s, server_hostname=self._server_name)
        except ssl.SSLError as exc:
            _warn_ssl_error_details(
                exc,
                phase="handshake",
                host=self._host,
                port=self._port,
                verify=self._verify,
                server_hostname=self._server_name,
                ca_file=self._ca_file,
            )
            try:
                s.close()
            except Exception:
                pass
            raise
        self._sock = s
        self._tls = t
        self._last_used = time.time()

    def send(self, query: bytes, read_timeout_ms: int) -> bytes:
        if self._tls is None:
            raise DoTError(
                "connection not established"
            )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        self._tls.settimeout(read_timeout_ms / 1000.0)
        payload = len(query).to_bytes(2, "big") + query
        self._tls.sendall(payload)
        hdr = _recv_exact(self._tls, 2, read_timeout_ms)
        if len(hdr) != 2:
            raise DoTError(
                "short read on length header"
            )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        ln = int.from_bytes(hdr, "big")
        resp = _recv_exact(self._tls, ln, read_timeout_ms)
        if len(resp) != ln:
            raise DoTError(
                "short read on response body"
            )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        self._last_used = time.time()
        return resp

    def idle_for(self) -> float:
        return time.time() - self._last_used

    def close(self):
        try:
            if self._tls is not None:
                try:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    self._tls.close()
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            if self._sock is not None:
                try:
                    self._sock.close()
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        finally:
            self._tls = None
            self._sock = None


class DotConnectionPool:
    """
    Simple LIFO pool of DoT connections with one in-flight query per connection.

    Inputs:
      - host, port: Upstream target.
      - server_name: Optional SNI/verification hostname.
      - verify: Whether certificate verification is enabled.
      - ca_file: Optional CA bundle path.
      - max_connections: Pool cap.
      - idle_timeout_s: Close connections idle longer than this.
      - min_version: Minimum TLS version for new TLS contexts.
    Outputs:
      - Pool instance exposing send(query, connect_timeout_ms, read_timeout_ms).

    Example:
      >>> pool = get_dot_pool('1.1.1.1', 853, 'cloudflare-dns.com', True, None)
    """

    def __init__(
        self,
        host: str,
        port: int,
        server_name: Optional[str],
        verify: bool,
        ca_file: Optional[str],
        max_connections: int = 32,
        idle_timeout_s: int = 30,
        min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    ):
        self._host = host
        self._port = int(port)
        self._server_name = server_name
        self._verify = verify
        self._ca_file = ca_file
        self._ctx = _build_ssl_context(
            server_name, verify=verify, ca_file=ca_file, min_version=min_version
        )
        self._max = int(max_connections)
        self._idle = int(idle_timeout_s)
        self._lock = threading.Lock()
        self._stack = []  # type: list[_DotConn]

    def set_limits(
        self, *, max_connections: int | None = None, idle_timeout_s: int | None = None
    ) -> None:
        """
        Adjust pool sizing at runtime.

        Inputs:
          - max_connections: Optional new maximum size
          - idle_timeout_s: Optional new idle timeout seconds
        Outputs:
          - None

        Example:
          >>> pool.set_limits(max_connections=64, idle_timeout_s=60)
        """
        if max_connections is not None:
            try:
                self._max = max(1, int(max_connections))
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        if idle_timeout_s is not None:
            try:
                self._idle = max(1, int(idle_timeout_s))
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

    def send(
        self, query: bytes, connect_timeout_ms: int, read_timeout_ms: int
    ) -> bytes:
        conn = None
        with self._lock:
            # Cleanup idle
            now = time.time()
            keep = []
            while self._stack:
                c = self._stack.pop()
                if now - c._last_used <= self._idle:
                    keep.append(c)
                else:
                    c.close()
            self._stack.extend(keep)
            if self._stack:
                conn = self._stack.pop()
        try:
            if conn is None:
                conn = _DotConn(
                    self._host,
                    self._port,
                    self._ctx,
                    self._server_name,
                    self._verify,
                    self._ca_file,
                )
                conn.connect(connect_timeout_ms)
            resp = conn.send(query, read_timeout_ms)
            return resp
        except Exception:
            try:
                conn.close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            raise
        finally:
            if conn is not None and conn._tls is not None:
                with self._lock:
                    if len(self._stack) < self._max:
                        self._stack.append(conn)
                    else:
                        conn.close()


_POOLS = {}


def get_dot_pool(
    host: str,
    port: int,
    server_name: Optional[str],
    verify: bool,
    ca_file: Optional[str],
) -> DotConnectionPool:
    """
    Get or create a DoT connection pool for the given parameters.

    Inputs:
      - host, port, server_name, verify, ca_file
    Outputs:
      - DotConnectionPool instance

    Example:
      >>> pool = get_dot_pool('1.1.1.1', 853, 'cloudflare-dns.com', True, None)
    """
    key = (host, int(port), server_name or "", bool(verify), ca_file or "")
    pool = _POOLS.get(key)
    if pool is None:
        pool = DotConnectionPool(host, int(port), server_name, verify, ca_file)
        _POOLS[key] = pool
    return pool


def dot_query(
    host: str,
    port: int,
    query: bytes,
    *,
    server_name: Optional[str] = None,
    verify: bool = True,
    ca_file: Optional[str] = None,
    connect_timeout_ms: int = 1000,
    read_timeout_ms: int = 1500,
) -> bytes:
    """
    Perform a single DNS-over-TLS query (RFC 7858) to host:port.

    Inputs:
      - host: Upstream resolver hostname or IP.
      - port: Upstream DoT port (usually 853).
      - query: Wire-format DNS query bytes.
      - server_name: SNI/verification name; required if verify=True and host is not the cert CN/SAN.
      - verify: Enable TLS certificate verification.
      - ca_file: Optional CA bundle path.
      - connect_timeout_ms: TCP connect timeout in milliseconds.
      - read_timeout_ms: Read timeout in milliseconds.
    Outputs:
      - bytes: Wire-format DNS response.

    Example:
      >>> resp = dot_query('1.1.1.1', 853, b'\x12\x34...DNS...')
    """
    length_prefix = len(query).to_bytes(2, byteorder="big")
    payload = length_prefix + query

    try:
        # TCP connect
        sock = socket.create_connection(
            (host, port), timeout=connect_timeout_ms / 1000.0
        )
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ctx = _build_ssl_context(server_name, verify=verify, ca_file=ca_file)
            tls_sock = ctx.wrap_socket(
                sock, server_hostname=server_name if verify else None
            )
            try:
                tls_sock.settimeout(read_timeout_ms / 1000.0)
                # Send length-prefixed query
                tls_sock.sendall(payload)
                # Read two-byte length then message
                hdr = _recv_exact(tls_sock, 2, read_timeout_ms)
                if len(hdr) != 2:
                    raise DoTError(
                        "short read on length header"
                    )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                resp_len = int.from_bytes(hdr, byteorder="big")
                resp = _recv_exact(tls_sock, resp_len, read_timeout_ms)
                if len(resp) != resp_len:
                    raise DoTError(
                        "short read on response body"
                    )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                return resp
            finally:
                try:
                    tls_sock.close()
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        finally:
            try:
                sock.close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
    except ssl.SSLError as e:
        _warn_ssl_error_details(
            e,
            phase="handshake",
            host=host,
            port=int(port),
            verify=verify,
            server_hostname=server_name,
            ca_file=ca_file,
        )
        raise DoTError(
            f"TLS error: {e}"
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
    except (OSError, socket.timeout) as e:
        raise DoTError(
            f"Network error: {e}"
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably


def _recv_exact(sock: socket.socket, n: int, timeout_ms: int) -> bytes:
    """
    Receive exactly n bytes from a blocking socket.

    Inputs:
      - sock: A socket-like object with recv.
      - n: Number of bytes to read.
      - timeout_ms: Read timeout per recv() in milliseconds.
    Outputs:
      - bytes: Exactly n bytes unless EOF occurs early.

    Example:
      >>> _recv_exact(sock, 2, 1500)
    """
    remaining = n
    chunks = []
    sock.settimeout(timeout_ms / 1000.0)
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
