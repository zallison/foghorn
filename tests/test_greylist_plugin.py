from __future__ import annotations
import time
import os
from typing import Any, List, Tuple

import pytest
from dnslib import DNSRecord, DNSHeader, RR, A

from foghorn.server import DNSUDPHandler
from foghorn.plugins.greylist import GreylistPlugin
from foghorn.cache import TTLCache


class FakeSocket:
    def __init__(self) -> None:
        self.sent: List[Tuple[bytes, Tuple[str, int]]] = []

    def sendto(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.sent.append((data, addr))


@pytest.fixture
def greylist_db_path(tmp_path):
    return os.path.join(tmp_path, "greylist.db")


def test_greylist_first_seen(greylist_db_path):
    """First time a domain is seen, it should be denied."""
    # Arrange handler shared state
    DNSUDPHandler.cache = TTLCache()  # clear cache
    DNSUDPHandler.plugins = [
        GreylistPlugin(db_path=greylist_db_path, duration_seconds=10)
    ]
    DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]
    DNSUDPHandler.timeout = 0.5
    DNSUDPHandler.timeout_ms = 500

    # Prepare a DNS query packet
    query = DNSRecord.question("new.domain.com", "A")
    data = query.pack()

    # Fake socket and server
    sock = FakeSocket()
    client_addr = ("9.9.9.9", 55555)

    # Act: constructing the handler will call handle()
    DNSUDPHandler((data, sock), client_addr, object())

    # Assert: response should be NXDOMAIN
    assert sock.sent
    response = DNSRecord.parse(sock.sent[0][0])
    assert response.header.rcode == 3  # NXDOMAIN


def test_greylist_allow_after_duration(greylist_db_path):
    """After the duration has passed, the domain should be allowed."""
    # Arrange handler shared state
    DNSUDPHandler.cache = TTLCache()  # clear cache
    plugin = GreylistPlugin(db_path=greylist_db_path, duration_seconds=1)
    DNSUDPHandler.plugins = [plugin]
    DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]
    DNSUDPHandler.timeout = 0.5
    DNSUDPHandler.timeout_ms = 500

    # First request to register the domain
    query = DNSRecord.question("new.domain.com", "A")
    data = query.pack()
    sock = FakeSocket()
    client_addr = ("9.9.9.9", 55555)
    DNSUDPHandler((data, sock), client_addr, object())

    # Wait for the greylist duration to pass
    time.sleep(1.1)

    # Second request
    sock = FakeSocket()
    DNSUDPHandler((data, sock), client_addr, object())

    # Assert: response should be a valid response, not NXDOMAIN
    assert sock.sent
    response = DNSRecord.parse(sock.sent[0][0])
    assert response.header.rcode != 3  # Not NXDOMAIN


def test_greylist_deny_within_duration(greylist_db_path):
    """Within the duration, the domain should be denied."""
    # Arrange handler shared state
    DNSUDPHandler.cache = TTLCache()  # clear cache
    plugin = GreylistPlugin(db_path=greylist_db_path, duration_seconds=10)
    DNSUDPHandler.plugins = [plugin]
    DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]
    DNSUDPHandler.timeout = 0.5
    DNSUDPHandler.timeout_ms = 500

    # First request to register the domain
    query = DNSRecord.question("new.domain.com", "A")
    data = query.pack()
    sock = FakeSocket()
    client_addr = ("9.9.9.9", 55555)
    DNSUDPHandler((data, sock), client_addr, object())

    # Second request immediately after
    sock = FakeSocket()
    DNSUDPHandler((data, sock), client_addr, object())

    # Assert: response should be NXDOMAIN
    assert sock.sent
    response = DNSRecord.parse(sock.sent[0][0])
    assert response.header.rcode == 3  # NXDOMAIN
