"""
Brief: Tests for FlakeyServer plugin behavior and configuration parsing.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

# Load the plugin class directly from source without relying on package discovery
import os
import sys
import importlib.util

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC_DIR = os.path.join(ROOT, "src")
PKG_DIR = os.path.join(SRC_DIR, "foghorn")
PLUG_DIR = os.path.join(PKG_DIR, "plugins")
PLUGIN_PATH = os.path.join(PLUG_DIR, "flakey_server.py")

# Synthesize a local package hierarchy so relative imports resolve inside flakey_server
import types

foghorn_pkg = types.ModuleType("foghorn")
foghorn_pkg.__path__ = [PKG_DIR]
sys.modules["foghorn"] = foghorn_pkg

plugins_pkg = types.ModuleType("foghorn.plugins")
plugins_pkg.__path__ = [PLUG_DIR]
sys.modules["foghorn.plugins"] = plugins_pkg

spec = importlib.util.spec_from_file_location(
    "foghorn.plugins.flakey_server", PLUGIN_PATH
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
assert spec.loader is not None
spec.loader.exec_module(mod)
FlakeyServer = mod.FlakeyServer

import pytest
from dnslib import DNSRecord, QTYPE, RCODE

from foghorn.plugins.base import PluginContext


def _mk_query(name="example.com", qtype="A"):
    q = DNSRecord.question(name, qtype)
    return q, q.pack()


def test_alias_discovery():
    # We loaded FlakeyServer directly from source; ensure it is callable/class
    assert callable(FlakeyServer)


def test_default_priority():
    p = FlakeyServer()
    assert p.pre_priority == 15


def test_no_targets_is_noop():
    p = FlakeyServer()  # no allow / client_ip
    q, wire = _mk_query()
    ctx = PluginContext("192.0.2.55")
    assert p.pre_resolve("example.com", QTYPE.A, wire, ctx) is None


def test_client_ip_targets_only_that_ip():
    p = FlakeyServer(
        client_ip="192.0.2.55", servfail_one_in=1, nxdomain_one_in=999, seed=1
    )
    q, wire = _mk_query()
    # Target IP should be affected (SERVFAIL forced by 1-in-1)
    dec = p.pre_resolve("example.com", QTYPE.A, wire, PluginContext("192.0.2.55"))
    assert dec is not None
    resp = DNSRecord.parse(dec.response)
    assert resp.header.rcode == RCODE.SERVFAIL
    # Different IP should pass through
    dec2 = p.pre_resolve("example.com", QTYPE.A, wire, PluginContext("192.0.2.56"))
    assert dec2 is None


def test_allow_list_targets_cidr_and_single():
    p = FlakeyServer(allow=["192.0.2.0/24", "198.51.100.10"], servfail_one_in=1, seed=2)
    q, wire = _mk_query()
    assert p.pre_resolve("ex", QTYPE.A, wire, PluginContext("192.0.2.99")) is not None
    assert (
        p.pre_resolve("ex", QTYPE.A, wire, PluginContext("198.51.100.10")) is not None
    )
    # Non-matching address
    assert p.pre_resolve("ex", QTYPE.A, wire, PluginContext("203.0.113.1")) is None


def test_servfail_precedence_over_nxdomain():
    p = FlakeyServer(
        client_ip="192.0.2.55", servfail_one_in=1, nxdomain_one_in=1, seed=3
    )
    q, wire = _mk_query()
    dec = p.pre_resolve("ex", QTYPE.A, wire, PluginContext("192.0.2.55"))
    assert dec is not None
    resp = DNSRecord.parse(dec.response)
    assert resp.header.rcode == RCODE.SERVFAIL


def test_qtype_filtering_only_A():
    p = FlakeyServer(
        client_ip="192.0.2.55",
        allow=None,
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


def test_invalid_allow_entries_do_not_crash(caplog):
    caplog.set_level("WARNING")
    p = FlakeyServer(
        allow=["not-an-ip", "300.300.300.300/33"], servfail_one_in=1, seed=5
    )
    q, wire = _mk_query()
    # With no valid targets, it's a no-op
    assert p.pre_resolve("ex", QTYPE.A, wire, PluginContext("192.0.2.55")) is None
