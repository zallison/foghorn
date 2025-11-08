"""
Brief: Additional unit tests for foghorn.plugins.flaky_server to cover edge cases.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

import types
import pytest
from dnslib import DNSRecord, QTYPE, RCODE

from foghorn.plugins.flaky_server import FlakyServer
from foghorn.plugins.base import PluginContext


def _mk_query(name="example.com", qtype="A"):
    """
    Brief: Build a DNS query and return (record, wire).

    Inputs:
      - name (str)
      - qtype (str)
    Outputs:
      - (DNSRecord, bytes)
    """
    q = DNSRecord.question(name, qtype)
    return q, q.pack()


def test__clamp_one_in_non_int_and_lt1(caplog):
    """
    Brief: _clamp_one_in coerces non-int and clamps values < 1 to 1.

    Inputs:
      - caplog: pytest logging capture
    Outputs:
      - None; asserts return 1 for bad inputs and logs warnings
    """
    caplog.set_level("WARNING")
    assert FlakyServer._clamp_one_in("notint", "k") == 1
    assert FlakyServer._clamp_one_in(0, "k") == 1
    # Should have at least one warning logged
    assert any(
        "clamping" in m.message or "non-integer" in m.message for m in caplog.records
    )


def test__is_target_client_invalid_ip_and_no_targets():
    """
    Brief: _is_target_client returns False for invalid ctx IP and when no targets configured.

    Inputs:
      - None
    Outputs:
      - None; asserts False in both conditions
    """
    p = FlakyServer()  # no allow/client_ip
    assert p._is_target_client("not-an-ip") is False
    assert p._is_target_client("192.0.2.55") is False


def test__is_target_qtype_with_int_and_unknown():
    """
    Brief: _is_target_qtype handles int qtype values and unknown names.

    Inputs:
      - None
    Outputs:
      - None; asserts matching and non-matching correctly
    """
    p = FlakyServer(allow=["192.0.2.0/24"], apply_to_qtypes=["A"])  # focuses A only
    assert p._is_target_qtype(QTYPE.A) is True
    assert p._is_target_qtype(QTYPE.AAAA) is False
    # Unknown literal name should not match
    assert p._is_target_qtype("UNKNOWN-TYPE") is False


def test__make_response_error_path_returns_none(monkeypatch):
    """
    Brief: _make_response returns None on parse errors and pre_resolve handles it gracefully.

    Inputs:
      - monkeypatch: pytest fixture
    Outputs:
      - None; asserts no exception and None decision
    """
    p = FlakyServer(client_ip="192.0.2.55", servfail_one_in=1, seed=1)
    # Feed invalid wire to _make_response directly
    assert p._make_response(b"\x00", RCODE.SERVFAIL) is None
    # In pre_resolve path with invalid wire, errors should be swallowed and return None
    assert p.pre_resolve("ex", QTYPE.A, b"\x00", PluginContext("192.0.2.55")) is None


def test_seed_bad_value_falls_back_to_systemrandom(caplog):
    """
    Brief: Bad seed logs a warning and falls back to SystemRandom.

    Inputs:
      - caplog: pytest logging capture
    Outputs:
      - None; asserts a warning was logged
    """
    caplog.set_level("WARNING")
    _ = FlakyServer(seed="not-int")
    assert any("bad seed" in r.message for r in caplog.records)
