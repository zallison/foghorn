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


def test_greylist_permanently_allows_after_first_allow(greylist_db_path, monkeypatch):
    """
    Brief: Verify that once allowed after the greylist window, subsequent immediate queries remain allowed.

    Inputs:
        greylist_db_path: Temporary database path for testing
        monkeypatch: pytest fixture for patching time.time

    Outputs:
        Asserts on deny/allow decisions; first_seen remains unchanged after initial allow

    Example:
        After first deny, wait duration, second query allows, third immediate query also allows
    """
    from foghorn.plugins.base import PluginContext

    # Mock time to control timing deterministically
    now = [1_000_000]  # Use list for mutable reference
    monkeypatch.setattr("foghorn.plugins.greylist.time.time", lambda: now[0])

    # Create plugin instance directly
    plugin = GreylistPlugin(db_path=greylist_db_path, duration_seconds=2)
    ctx = PluginContext(client_ip="192.0.2.1")

    # First query at t=1_000_000 - should be denied (first seen)
    decision1 = plugin.pre_resolve("sub1.example.com", 1, b"", ctx)
    assert decision1 is not None
    assert decision1.action == "deny"

    # Advance time past the greylist window
    now[0] = 1_000_000 + 3  # 3 seconds later, past 2 second window

    # Second query - should be allowed after window
    decision2 = plugin.pre_resolve("sub2.example.com", 1, b"", ctx)
    assert decision2 is None  # None means allow

    # Third immediate query (same time) - should STILL be allowed (no greylist restart)
    decision3 = plugin.pre_resolve("www.example.com", 1, b"", ctx)
    assert decision3 is None  # None means permanent allow
