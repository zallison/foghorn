"""
Brief: Tests for FlakyServer plugin behavior and configuration parsing.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from dnslib import QTYPE, RCODE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.flaky_server import FlakyServer


def _mk_query(name="example.com", qtype="A"):
    q = DNSRecord.question(name, qtype)
    return q, q.pack()


def test_alias_discovery():
    # We loaded FlakyServer directly from source; ensure it is callable/class
    assert callable(FlakyServer)


def test_default_priority():
    p = FlakyServer()
    assert p.pre_priority == 15


def test_no_targets_is_noop():
    p = FlakyServer()  # no BasePlugin targets configured
    q, wire = _mk_query()
    ctx = PluginContext("192.0.2.55")
    assert p.pre_resolve("example.com", QTYPE.A, wire, ctx) is None


def test_client_ip_targets_only_that_ip():
    p = FlakyServer(
        targets=["192.0.2.55"], servfail_percent=100.0, nxdomain_percent=0.0, seed=1
    )
    q, wire = _mk_query()
    # Target IP should be affected (SERVFAIL forced by 100% probability)
    dec = p.pre_resolve("example.com", QTYPE.A, wire, PluginContext("192.0.2.55"))
    assert dec is not None
    resp = DNSRecord.parse(dec.response)
    assert resp.header.rcode == RCODE.SERVFAIL
    # Different IP should pass through
    dec2 = p.pre_resolve("example.com", QTYPE.A, wire, PluginContext("192.0.2.56"))
    assert dec2 is None


def test_allow_list_targets_cidr_and_single():
    p = FlakyServer(
        targets=["192.0.2.0/24", "198.51.100.10"], servfail_percent=100.0, seed=2
    )
    q, wire = _mk_query()
    assert p.pre_resolve("ex", QTYPE.A, wire, PluginContext("192.0.2.99")) is not None
    assert (
        p.pre_resolve("ex", QTYPE.A, wire, PluginContext("198.51.100.10")) is not None
    )
    # Non-matching address
    assert p.pre_resolve("ex", QTYPE.A, wire, PluginContext("203.0.113.1")) is None


def test_servfail_precedence_over_nxdomain():
    p = FlakyServer(
        targets=["192.0.2.55"], servfail_percent=100.0, nxdomain_percent=100.0, seed=3
    )
    q, wire = _mk_query()
    dec = p.pre_resolve("ex", QTYPE.A, wire, PluginContext("192.0.2.55"))
    assert dec is not None
    resp = DNSRecord.parse(dec.response)
    assert resp.header.rcode == RCODE.SERVFAIL


def test_qtype_filtering_only_A():
    p = FlakyServer(
        targets=["192.0.2.55"],
        servfail_one_in=1,
        apply_to_qtypes=["A"],
        seed=4,
    )
    q, wire_a = _mk_query("ex", "A")
    q6, wire_aaaa = _mk_query("ex", "AAAA")
    # A should be affected
    dec_a = p.pre_resolve("ex", QTYPE.A, wire_a, PluginContext("192.0.2.55"))
    assert dec_a is not None
    # AAAA should pass through
    dec_aaaa = p.pre_resolve("ex", QTYPE.AAAA, wire_aaaa, PluginContext("192.0.2.55"))
    assert dec_aaaa is None


def test_invalid_targets_entries_do_not_crash(caplog):
    caplog.set_level("WARNING")
    p = FlakyServer(
        targets=["not-an-ip", "300.300.300.300/33"], servfail_percent=100.0, seed=5
    )
    q, wire = _mk_query()
    # With no valid targets, BasePlugin will ignore them and FlakyServer is a no-op
    assert p.pre_resolve("ex", QTYPE.A, wire, PluginContext("192.0.2.55")) is None
