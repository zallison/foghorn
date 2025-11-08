"""
Brief: Test udp_query with source_ip binding.

Inputs:
  - None

Outputs:
  - None
"""

import socket

from foghorn.transports.udp import udp_query


def test_udp_query_source_ip_bind():
    # Find a local source port by binding and closing
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    src_port = s.getsockname()[1]
    s.close()

    # Echo server
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    host, port = srv.getsockname()

    import threading

    stopped = {"v": False}

    def loop():
        srv.settimeout(0.5)
        while not stopped["v"]:
            try:
                data, peer = srv.recvfrom(2048)
                srv.sendto(data, peer)
            except Exception:
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
        except Exception:
            pass
