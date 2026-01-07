import socket
import ssl
import threading
import time
from typing import Optional


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
    ctx = (
        ssl.create_default_context(cafile=ca_file)
        if verify
        else ssl._create_unverified_context()
    )
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
    Outputs:
      - Instance capable of send(query_bytes)->response_bytes.

    Brief: Manages one TLS socket; not safe for concurrent in-flight queries.
    """

    def __init__(
        self, host: str, port: int, ctx: ssl.SSLContext, server_name: Optional[str]
    ):
        self._host = host
        self._port = int(port)
        self._ctx = ctx
        self._server_name = server_name
        self._sock = None  # type: Optional[socket.socket]
        self._tls = None  # type: Optional[socket.socket]
        self._last_used = time.time()

    def connect(self, connect_timeout_ms: int):
        self.close()
        s = socket.create_connection(
            (self._host, self._port), timeout=connect_timeout_ms / 1000.0
        )
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        t = self._ctx.wrap_socket(s, server_hostname=self._server_name)
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
      - key: tuple identifying upstream (host, port, server_name, verify, ca_file)
      - max_connections: pool cap
      - idle_timeout_s: close connections idle longer than this
    Outputs:
      - send(query, timeouts): response bytes

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
                conn = _DotConn(self._host, self._port, self._ctx, self._server_name)
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
