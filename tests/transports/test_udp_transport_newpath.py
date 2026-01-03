"""
Brief: Tests for the foghorn.transports.udp module to ensure full line coverage.

Inputs:
  - None

Outputs:
  - None
"""

import socket
import threading
import time

import pytest

from foghorn.transports.udp import UDPError, udp_query


class _UDPStubNewPath:
    """Brief: Minimal UDP echo stub for foghorn.transports.udp tests.

    Inputs:
      - None

    Outputs:
      - None
    """

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.addr = self.sock.getsockname()
        self._stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        """Brief: Start background echo loop.

        Inputs:
          - None

        Outputs:
          - None
        """

        self.thread.start()
        time.sleep(0.02)

    def _loop(self):
        """Brief: Echo back any received datagrams.

        Inputs:
          - None

        Outputs:
          - None
        """

        while not self._stop:
            try:
                self.sock.settimeout(0.2)
                data, peer = self.sock.recvfrom(4096)
            except Exception:  # pragma: nocover defensive: stub loop ignores spurious timeouts/errors
                continue
            try:
                self.sock.sendto(data, peer)
            except Exception:  # pragma: nocover defensive: send failures here are environment-specific
                pass

    def close(self):
        """Brief: Stop loop and close socket.

        Inputs:
          - None

        Outputs:
          - None
        """

        self._stop = True
        try:
            self.sock.close()
        except Exception:  # pragma: nocover defensive: close failure here is low-value to test
            pass


@pytest.fixture(scope="module")
def udp_stub_newpath():
    """Brief: Fixture providing a running UDP echo stub for newpath tests.

    Inputs:
      - None

    Outputs:
      - _UDPStubNewPath: running stub instance
    """

    s = _UDPStubNewPath()
    s.start()
    try:
        yield s
    finally:
        s.close()


def test_udp_query_roundtrip_newpath(udp_stub_newpath):
    """Brief: Ensure udp_query round-trips bytes via foghorn.transports.udp.

    Inputs:
      - udp_stub_newpath: UDP echo stub fixture

    Outputs:
      - None
    """

    q = b"\x12\x34hello"
    resp = udp_query(udp_stub_newpath.addr[0], udp_stub_newpath.addr[1], q, timeout_ms=500)
    assert resp == q


def test_udp_timeout_raises_newpath(monkeypatch):
    """Brief: Ensure UDPError is raised when socket operations fail.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture

    Outputs:
      - None
    """

    class _BoomSocket:
        """Brief: Socket stub that always raises OSError on send.

        Inputs:
          - *args, **kwargs: ignored

        Outputs:
          - None
        """

        def __init__(self, *_, **__):
            self.closed = False

        def settimeout(self, _):  # pragma: nocover trivial: no behaviour worth testing
            pass

        def sendto(self, *_):
            raise OSError("boom")

        def recvfrom(self, *_):  # pragma: nocover safety: never reached because sendto always fails
            raise AssertionError("should not be reached")

        def close(self):
            self.closed = True

    monkeypatch.setattr(socket, "socket", _BoomSocket)

    with pytest.raises(UDPError):
        udp_query("127.0.0.1", 53, b"\x12\x34", timeout_ms=10)


def test_udp_query_source_ip_bind_newpath():
    """Brief: Exercise source_ip binding path via foghorn.transports.udp.

    Inputs:
      - None

    Outputs:
      - None
    """

    # Echo server
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    host, port = srv.getsockname()

    stopped = {"v": False}

    def loop():
        srv.settimeout(0.5)
        while not stopped["v"]:
            try:
                data, peer = srv.recvfrom(2048)
                srv.sendto(data, peer)
            except Exception:  # pragma: nocover defensive: ignores spurious timeouts during teardown
                pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()

    try:
        q = b"\x12\x34hello"
        r = udp_query(host, port, q, timeout_ms=800, source_ip="127.0.0.1")
        assert r == q
    finally:
        stopped["v"] = True
        try:
            srv.close()
        except Exception:  # pragma: nocover defensive: close failure is non-essential to behaviour
            pass
