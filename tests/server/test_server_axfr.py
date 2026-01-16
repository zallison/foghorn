"""
Brief: Tests for AXFR handling in foghorn.servers.server.iter_axfr_messages.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from dnslib import QTYPE, RCODE, DNSRecord

import foghorn.servers.server as srv
from foghorn.servers.server import DNSUDPHandler


def _mk_axfr_query(name: str) -> DNSRecord:
    """Brief: Build an AXFR DNSRecord for the given zone name.

    Inputs:
      - name: Zone apex name (with or without trailing dot).

    Outputs:
      - DNSRecord representing an AXFR query for *name*.
    """
    qname = (name.rstrip(".") or ".") + "."
    return DNSRecord.question(qname, qtype="AXFR")


def test_iter_axfr_messages_non_authoritative_refused() -> None:
    """Brief: iter_axfr_messages returns REFUSED when no plugin is authoritative.

    Inputs:
      - None.

    Outputs:
      - Asserts that a single REFUSED response is returned when no plugin
        advertises iter_zone_rrs_for_transfer for the requested zone.
    """
    DNSUDPHandler.plugins = []

    q = _mk_axfr_query("example.com")
    messages = srv.iter_axfr_messages(q)
    assert isinstance(messages, list)
    assert len(messages) == 1

    resp = DNSRecord.parse(messages[0])
    assert resp.header.rcode == RCODE.REFUSED


def test_iter_axfr_messages_with_zone_plugin_exports_zone(tmp_path) -> None:
    """Brief: iter_axfr_messages streams an AXFR from a ZoneRecords-backed zone.

    Inputs:
      - tmp_path: pytest temporary directory for a synthetic zone file.

    Outputs:
      - Asserts that the AXFR reply sequence contains SOA-bounded zone data for
        the requested apex when a plugin exports RRs via iter_zone_rrs_for_transfer.
    """
    # Build a minimal authoritative zone file for example.com.
    zone_file = tmp_path / "zone.txt"
    zone_file.write_text(
        "\n".join(
            [
                (
                    "example.com.|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com.|NS|300|ns1.example.com.",
                "example.com.|A|300|192.0.2.10",
                "www.example.com.|A|300|192.0.2.20",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # Use the real ZoneRecords plugin to provide authoritative data.
    from foghorn.plugins.resolve.zone_records import ZoneRecords

    plugin = ZoneRecords(file_paths=[str(zone_file)])
    plugin.setup()

    # Wire the plugin into DNSUDPHandler so iter_axfr_messages can discover it.
    DNSUDPHandler.plugins = [plugin]

    q = _mk_axfr_query("example.com")
    messages = srv.iter_axfr_messages(q)
    assert messages, "Expected at least one AXFR response message"

    # Collect all RRs from the streamed messages.
    all_rrs = []
    for wire in messages:
        rec = DNSRecord.parse(wire)
        all_rrs.extend(rec.rr)

    # There should be at least two SOAs: leading and trailing at the apex.
    soa_rrs = [rr for rr in all_rrs if rr.rtype == QTYPE.SOA]
    assert len(soa_rrs) >= 2

    apex = "example.com."
    for rr in soa_rrs:
        assert str(rr.rname) == apex

    # Ensure the exported data includes the A record for the apex and www host.
    a_rrs = [rr for rr in all_rrs if rr.rtype == QTYPE.A]
    owners = {str(rr.rname).rstrip(".").lower() for rr in a_rrs}
    assert "example.com" in owners
    assert "www.example.com" in owners


def test_iter_axfr_messages_includes_dnssec_rrs(tmp_path) -> None:
    """Brief: AXFR responses include DNSKEY and RRSIG RRsets when present.

    Inputs:
      - tmp_path: pytest temporary directory used for a synthetic signed zone.

    Outputs:
      - Asserts that a signed zone served via ZoneRecords contributes DNSKEY and
        RRSIG records to the AXFR stream.
    """
    zone_file = tmp_path / "signed.zone"
    zone_file.write_text(
        "\n".join(
            [
                (
                    "example.com.|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                # DNSKEY at apex.
                (
                    "example.com.|DNSKEY|300|256 3 13 "
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "AAAAAAAAAAAAAAAAAAAAAAAAAA=="
                ),
                # RRSIG covering DNSKEY.
                (
                    "example.com.|RRSIG|300|DNSKEY 13 2 300 "
                    "20260201000000 20260101000000 12345 example.com. "
                    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                    "BBBBBBBBBBBBBBBBBBBBBBBBBB=="
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    from foghorn.plugins.resolve.zone_records import ZoneRecords

    plugin = ZoneRecords(file_paths=[str(zone_file)])
    plugin.setup()
    DNSUDPHandler.plugins = [plugin]

    q = _mk_axfr_query("example.com")
    messages = srv.iter_axfr_messages(q)
    all_rrs = []
    for wire in messages:
        rec = DNSRecord.parse(wire)
        all_rrs.extend(rec.rr)

    types = {rr.rtype for rr in all_rrs}
    assert QTYPE.DNSKEY in types
    assert QTYPE.RRSIG in types
