from __future__ import annotations

from dnslib import QTYPE, RCODE, RR, DNSRecord

from foghorn.servers.server import iter_axfr_messages


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


def test_axfr_refused_when_not_enabled(set_runtime_snapshot):
    set_runtime_snapshot(
        plugins=[_ZoneExportPlugin("example.com")],
        axfr_enabled=False,
        axfr_allow_clients=["127.0.0.1/32"],
    )

    req = _make_axfr_query("example.com")
    messages = iter(iter_axfr_messages(req, client_ip="127.0.0.1"))
    first_wire = next(messages, None)
    assert first_wire is not None
    resp = DNSRecord.parse(first_wire)
    assert resp.header.rcode == RCODE.REFUSED


def test_axfr_refused_when_client_not_allowlisted(set_runtime_snapshot):
    set_runtime_snapshot(
        plugins=[_ZoneExportPlugin("example.com")],
        axfr_enabled=True,
        axfr_allow_clients=["192.0.2.0/24"],
    )

    req = _make_axfr_query("example.com")
    messages = iter(iter_axfr_messages(req, client_ip="127.0.0.1"))
    first_wire = next(messages, None)
    assert first_wire is not None
    resp = DNSRecord.parse(first_wire)
    assert resp.header.rcode == RCODE.REFUSED


def test_axfr_allows_allowlisted_client(set_runtime_snapshot):
    set_runtime_snapshot(
        plugins=[_ZoneExportPlugin("example.com")],
        axfr_enabled=True,
        axfr_allow_clients=["127.0.0.0/8"],
    )

    req = _make_axfr_query("example.com")
    messages = iter(iter_axfr_messages(req, client_ip="127.0.0.1"))
    first_wire = next(messages, None)
    assert first_wire is not None
    # First message should be a normal response (not REFUSED)
    resp0 = DNSRecord.parse(first_wire)
    assert resp0.header.rcode != RCODE.REFUSED
    # Ensure we are actually returning transfer content
    assert any(rr.rtype == QTYPE.SOA for rr in resp0.rr)
