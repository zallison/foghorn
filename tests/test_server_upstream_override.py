from __future__ import annotations
from typing import Any, List, Tuple

import pytest
from dnslib import DNSRecord

from foghorn.server import DNSUDPHandler
from foghorn.plugins.upstream_router import UpstreamRouterPlugin
from foghorn.cache import TTLCache


class FakeSocket:
    def __init__(self) -> None:
        self.sent: List[Tuple[bytes, Tuple[str, int]]] = []

    def sendto(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.sent.append((data, addr))


def test_server_uses_upstream_override_from_plugin(monkeypatch):
    # Arrange handler shared state
    DNSUDPHandler.cache = TTLCache()  # clear cache
    override_addr = ("127.0.0.2", 10053)
    DNSUDPHandler.plugins = [
        UpstreamRouterPlugin(routes=[
            {"domain": "corp.example.com", "upstream": {"host": override_addr[0], "port": override_addr[1]}}
        ])
    ]
    DNSUDPHandler.upstream_addr = ("1.1.1.1", 53)
    DNSUDPHandler.timeout = 0.5

    # Prepare a DNS query packet
    query = DNSRecord.question("corp.example.com", "A")
    data = query.pack()

    # Capture the dest used by DNSRecord.send
    used_dest: List[Tuple[str, int]] = []

    def fake_send(self: DNSRecord, dest: Tuple[str, int], timeout: float = None, *args: Any, **kwargs: Any) -> bytes:
        used_dest.append(dest)
        return b"dummy-reply"

    monkeypatch.setattr(DNSRecord, "send", fake_send, raising=True)

    # Fake socket and server
    sock = FakeSocket()
    client_addr = ("9.9.9.9", 55555)

    # Act: constructing the handler will call handle()
    DNSUDPHandler((data, sock), client_addr, object())

    # Assert: upstream override was used and reply sent back to client
    assert used_dest and used_dest[0] == override_addr
    assert sock.sent and sock.sent[0][1] == client_addr
    assert sock.sent[0][0] == b"dummy-reply"
