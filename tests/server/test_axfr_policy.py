from __future__ import annotations

from dnslib import QTYPE, RCODE, RR, DNSRecord

from foghorn.servers.server import iter_axfr_messages
from foghorn.servers.udp_server import DNSUDPHandler


class _ZoneExportPlugin:
    def __init__(self, zone: str) -> None:
        self._zone = zone

    def iter_zone_rrs_for_transfer(self, zone_apex: str, client_ip: str | None = None):
        if zone_apex.rstrip(".").lower() != self._zone.rstrip(".").lower():
            return None
        # Minimal zone: SOA start + end is handled by iter_axfr_messages.
        return RR.fromZone(
            f"{self._zone}. 300 IN SOA ns1.{self._zone}. hostmaster.{self._zone}. 1 3600 600 604800 300"
        )


def _make_axfr_query(zone: str) -> DNSRecord:
    return DNSRecord.question((zone.rstrip(".") + "."), qtype="AXFR")


def test_axfr_refused_when_not_enabled(monkeypatch):
    DNSUDPHandler.plugins = [_ZoneExportPlugin("example.com")]
    DNSUDPHandler.axfr_enabled = False
    DNSUDPHandler.axfr_allow_clients = ["127.0.0.1/32"]

    req = _make_axfr_query("example.com")
    messages = iter_axfr_messages(req, client_ip="127.0.0.1")
    assert messages
    resp = DNSRecord.parse(messages[0])
    assert resp.header.rcode == RCODE.REFUSED


def test_axfr_refused_when_client_not_allowlisted(monkeypatch):
    DNSUDPHandler.plugins = [_ZoneExportPlugin("example.com")]
    DNSUDPHandler.axfr_enabled = True
    DNSUDPHandler.axfr_allow_clients = ["192.0.2.0/24"]

    req = _make_axfr_query("example.com")
    messages = iter_axfr_messages(req, client_ip="127.0.0.1")
    assert messages
    resp = DNSRecord.parse(messages[0])
    assert resp.header.rcode == RCODE.REFUSED


def test_axfr_allows_allowlisted_client(monkeypatch):
    DNSUDPHandler.plugins = [_ZoneExportPlugin("example.com")]
    DNSUDPHandler.axfr_enabled = True
    DNSUDPHandler.axfr_allow_clients = ["127.0.0.0/8"]

    req = _make_axfr_query("example.com")
    messages = iter_axfr_messages(req, client_ip="127.0.0.1")
    assert messages
    # First message should be a normal response (not REFUSED)
    resp0 = DNSRecord.parse(messages[0])
    assert resp0.header.rcode != RCODE.REFUSED
    # Ensure we are actually returning transfer content
    assert any(rr.rtype == QTYPE.SOA for rr in resp0.rr)
