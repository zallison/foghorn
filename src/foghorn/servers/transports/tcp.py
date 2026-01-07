import socket
import threading
import time


class TCPError(Exception):
    """
    A DNS-over-TCP transport error.

    Inputs:
      - message: Error description.
    Outputs:
      - Exception instance.

    Brief: Raised for connect/read/write or framing errors.
    """

    pass


class _TCPConn:
    """
    A single DNS-over-TCP connection; one in-flight query at a time.

    Inputs:
      - host, port
    Outputs:
      - send(query_bytes)->response_bytes on a persistent connection.
    """

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = int(port)
        self._sock = None  # type: socket.socket | None
        self._last_used = time.time()

    def connect(self, connect_timeout_ms: int):
        self.close()
        s = socket.create_connection(
            (self._host, self._port), timeout=connect_timeout_ms / 1000.0
        )
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock = s
        self._last_used = time.time()

    def send(self, query: bytes, read_timeout_ms: int) -> bytes:
        if self._sock is None:
            raise TCPError("connection not established")
        self._sock.settimeout(read_timeout_ms / 1000.0)
        payload = len(query).to_bytes(2, "big") + query
        self._sock.sendall(payload)
        hdr = _recv_exact(self._sock, 2)
        if len(hdr) != 2:
            raise TCPError("short read on length header")
        ln = int.from_bytes(hdr, "big")
        resp = _recv_exact(self._sock, ln)
        if len(resp) != ln:
            raise TCPError("short read on body")
        self._last_used = time.time()
        return resp

    def idle_for(self) -> float:
        return time.time() - self._last_used

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
        self._sock = None


class TCPConnectionPool:
    """
    Simple LIFO pool of TCP connections.

    Inputs:
      - host, port
    Outputs:
      - send(query)->response using persistent connection.
    """

    def __init__(
        self, host: str, port: int, max_connections: int = 32, idle_timeout_s: int = 30
    ):
        self._host = host
        self._port = int(port)
        self._max = int(max_connections)
        self._idle = int(idle_timeout_s)
        self._lock = threading.Lock()
        self._stack = []  # type: list[_TCPConn]

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
                pass
        if idle_timeout_s is not None:
            try:
                self._idle = max(1, int(idle_timeout_s))
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

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
                conn = _TCPConn(self._host, self._port)
                conn.connect(connect_timeout_ms)
            resp = conn.send(query, read_timeout_ms)
            return resp
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            try:
                conn.close()
            except Exception:
                pass
            raise
        finally:
            if conn is not None and conn._sock is not None:
                with self._lock:
                    if len(self._stack) < self._max:
                        self._stack.append(conn)
                    else:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                        conn.close()


_POOLS = {}


def get_tcp_pool(host: str, port: int) -> TCPConnectionPool:
    """
    Get or create a TCP pool for host:port.

    Inputs:
      - host: str
      - port: int
    Outputs:
      - TCPConnectionPool instance

    Example:
      >>> pool = get_tcp_pool('8.8.8.8', 53)
    """
    key = (host, int(port))
    pool = _POOLS.get(key)
    if pool is None:
        pool = TCPConnectionPool(host, int(port))
        _POOLS[key] = pool
    return pool


def tcp_query(
    host: str,
    port: int,
    query: bytes,
    *,
    connect_timeout_ms: int = 1000,
    read_timeout_ms: int = 1500,
) -> bytes:
    """
    Perform a single DNS-over-TCP query to host:port using length-prefixed framing (RFC 7766).

    Inputs:
      - host: Upstream resolver host/IP.
      - port: Upstream TCP port (53 typically).
      - query: Wire-format DNS query bytes.
      - connect_timeout_ms: TCP connect timeout.
      - read_timeout_ms: Read timeout per operation.
    Outputs:
      - bytes: Wire-format DNS response.

    Example:
      >>> resp = tcp_query('8.8.8.8', 53, b'\x12\x34...')
    """
    length_prefix = len(query).to_bytes(2, byteorder="big")
    payload = length_prefix + query
    try:
        sock = socket.create_connection(
            (host, port), timeout=connect_timeout_ms / 1000.0
        )
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(read_timeout_ms / 1000.0)
            sock.sendall(payload)
            hdr = _recv_exact(sock, 2)
            if (
                len(hdr) != 2
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                raise TCPError("short read on length header")
            resp_len = int.from_bytes(hdr, byteorder="big")
            resp = _recv_exact(sock, resp_len)
            if (
                len(resp) != resp_len
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                raise TCPError("short read on body")
            return resp
        finally:
            try:
                sock.close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
    except (OSError, TimeoutError) as e:
        raise TCPError(f"Network error: {e}")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Receive exactly n bytes from a blocking socket.

    Inputs:
      - sock: Socket
      - n: Number of bytes
    Outputs:
      - bytes: Exactly n bytes unless EOF occurs.

    Example:
      >>> _recv_exact(sock, 2)
    """
    remaining = n
    chunks = []
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
