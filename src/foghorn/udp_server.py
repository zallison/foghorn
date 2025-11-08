import socketserver
from typing import Callable


class _UDPHandler(socketserver.BaseRequestHandler):
    """
    Brief: Simple UDP handler that delegates to a resolver callable.

    Inputs:
    - request: (data, socket) tuple provided by socketserver
    - client_address: peer address

    Outputs:
    - None

    Example:
        See serve_udp.
    """

    resolver: Callable[[bytes, str], bytes] = lambda b, ip: b

    def handle(self) -> None:
        data, sock = self.request  # type: ignore
        try:
            peer_ip = (
                self.client_address[0]
                if isinstance(self.client_address, tuple)
                else "0.0.0.0"
            )
            resp = self.resolver(data, peer_ip)
            sock.sendto(resp, self.client_address)
        except Exception:
            pass  # pragma: no cover


def serve_udp(host: str, port: int, resolver: Callable[[bytes, str], bytes]) -> None:
    """
    Brief: Serve DNS-over-UDP using ThreadingUDPServer.

    Inputs:
    - host: listen address
    - port: listen port
    - resolver: callable mapping (query_bytes, client_ip) -> response_bytes

    Outputs:
    - None (runs forever)

    Example:
        >>> # In a thread:
        >>> # serve_udp('0.0.0.0', 5353, resolver)
    """
    handler_cls = _UDPHandler
    handler_cls.resolver = staticmethod(resolver)  # type: ignore
    server = socketserver.ThreadingUDPServer((host, port), handler_cls)
    server.daemon_threads = True
    try:
        server.serve_forever()
    finally:
        try:
            server.server_close()
        except Exception:
            pass  # pragma: no cover
