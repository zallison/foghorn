"""
Brief: Additional unit tests for foghorn.plugins.flaky_server to cover edge cases.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from dnslib import QTYPE, RCODE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.flaky_server import FlakyServer


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


def test__is_target_qtype_with_int_and_unknown():
    """
    Brief: _is_target_qtype handles int qtype values and unknown names.

    Inputs:
      - None
    Outputs:
      - None; asserts matching and non-matching correctly
    """
    p = FlakyServer(apply_to_qtypes=["A"])  # focuses A only
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
    p = FlakyServer(targets=["192.0.2.55"], servfail_percent=100.0, seed=1)
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


def test_percent_fields_control_probabilities():
    """Brief: servfail_percent/nxdomain_percent control behaviour deterministically.

    Inputs:
      - None; constructs FlakyServer with 100% probabilities.
    Outputs:
      - None; asserts SERVFAIL and NXDOMAIN are produced for targeted client.
    """
    q, wire = _mk_query()

    # 100% SERVFAIL with zero NXDOMAIN probability.
    p_serv = FlakyServer(
        targets=["192.0.2.55"],
        servfail_percent=100.0,
        nxdomain_percent=0.0,
        seed=1,
    )
    dec1 = p_serv.pre_resolve("example.com", QTYPE.A, wire, PluginContext("192.0.2.55"))
    assert dec1 is not None
    resp1 = DNSRecord.parse(dec1.response)
    assert resp1.header.rcode == RCODE.SERVFAIL

    # 100% NXDOMAIN with zero SERVFAIL probability.
    p_nx = FlakyServer(
        targets=["192.0.2.55"],
        servfail_percent=0.0,
        nxdomain_percent=100.0,
        seed=1,
    )
    dec2 = p_nx.pre_resolve("example.com", QTYPE.A, wire, PluginContext("192.0.2.55"))
    assert dec2 is not None
    resp2 = DNSRecord.parse(dec2.response)
    assert resp2.header.rcode == RCODE.NXDOMAIN


def test_timeout_formerr_and_noerror_empty_decisions():
    """Brief: timeout/formerr/noerror_empty paths return expected actions/rcodes.

    Inputs:
      - FlakyServer configured with 100% probabilities for each behavior.
    Outputs:
      - None; asserts drop/formerr/noerror-empty behaviours.
    """
    q, wire = _mk_query()

    # Timeout -> drop decision, no response bytes.
    p_timeout = FlakyServer(
        targets=["192.0.2.55"],
        timeout_percent=100.0,
        servfail_percent=0.0,
        nxdomain_percent=0.0,
        formerr_percent=0.0,
        noerror_empty_percent=0.0,
        seed=1,
    )
    dec_t = p_timeout.pre_resolve(
        "example.com", QTYPE.A, wire, PluginContext("192.0.2.55")
    )
    assert dec_t is not None
    assert dec_t.action == "drop"

    # FORMERR.
    p_formerr = FlakyServer(
        targets=["192.0.2.55"],
        timeout_percent=0.0,
        servfail_percent=0.0,
        nxdomain_percent=0.0,
        formerr_percent=100.0,
        noerror_empty_percent=0.0,
        seed=1,
    )
    dec_f = p_formerr.pre_resolve(
        "example.com", QTYPE.A, wire, PluginContext("192.0.2.55")
    )
    assert dec_f is not None
    resp_f = DNSRecord.parse(dec_f.response)
    assert resp_f.header.rcode == RCODE.FORMERR

    # NOERROR empty.
    p_no = FlakyServer(
        targets=["192.0.2.55"],
        timeout_percent=0.0,
        servfail_percent=0.0,
        nxdomain_percent=0.0,
        formerr_percent=0.0,
        noerror_empty_percent=100.0,
        seed=1,
    )
    dec_n = p_no.pre_resolve("example.com", QTYPE.A, wire, PluginContext("192.0.2.55"))
    assert dec_n is not None
    resp_n = DNSRecord.parse(dec_n.response)
    assert resp_n.header.rcode == RCODE.NOERROR
    assert not resp_n.rr  # empty answer section


def test_clamp_percent_numeric_ranges_and_non_numeric(caplog):
    """Brief: _clamp_percent handles non-numeric, <0, and >100 percent values.

    Inputs:
      - caplog: pytest logging capture.
    Outputs:
      - None; asserts clamping behaviour and that non-numeric defaults to 0.0.
    """

    caplog.set_level("WARNING")
    # Non-numeric -> 0.0
    assert FlakyServer._clamp_percent("notnum", "k") == 0.0
    # Negative -> clamped to 0.0
    assert FlakyServer._clamp_percent(-5, "k") == 0.0
    # Above 100 -> clamped to 100.0
    assert FlakyServer._clamp_percent(200, "k") == 100.0


def test_clamp_one_in_positive_returns_value():
    """Brief: _clamp_one_in returns N for positive integers >= 1.

    Inputs:
      - None.
    Outputs:
      - None; asserts positive value passes through unchanged.
    """

    assert FlakyServer._clamp_one_in(5, "k") == 5


def test_init_qtype_and_fuzz_config_edge_cases():
    """Brief: __init__ handles empty qtypes, bad fuzz sizes, and bad actions.

    Inputs:
      - None.
    Outputs:
      - None; asserts defaults and clamping for edge-case config values.
    """

    # Empty/falsey apply_to_qtypes should default to ["*"].
    p_q = FlakyServer(apply_to_qtypes="", targets=["192.0.2.55"])
    assert p_q.apply_to_qtypes == ["*"]

    # Bad min_fuzz_bytes falls back to 1, and values < 1 are clamped to 1.
    p_fuzz_min = FlakyServer(min_fuzz_bytes="x")
    assert p_fuzz_min.min_fuzz_bytes == 1
    p_fuzz_min2 = FlakyServer(min_fuzz_bytes=0)
    assert p_fuzz_min2.min_fuzz_bytes == 1

    # Bad max_fuzz_bytes falls back to default, and when < min it is raised.
    p_fuzz_max = FlakyServer(min_fuzz_bytes=3, max_fuzz_bytes="x")
    assert p_fuzz_max.max_fuzz_bytes == 4
    p_fuzz_max2 = FlakyServer(min_fuzz_bytes=5, max_fuzz_bytes=1)
    assert p_fuzz_max2.max_fuzz_bytes == 5

    # Non-list or empty fuzz_actions fall back to the default action set.
    p_actions_bad = FlakyServer(fuzz_actions="not-a-list")
    assert p_actions_bad._fuzz_actions == ["bit_flip", "swap_bytes"]
    p_actions_empty = FlakyServer(fuzz_actions=[])
    assert p_actions_empty._fuzz_actions == ["bit_flip", "swap_bytes"]


def test_fuzz_wire_empty_and_bit_flip_only():
    """Brief: _fuzz_wire returns None on empty bytes and supports bit_flip action.

    Inputs:
      - None.
    Outputs:
      - None; asserts empty input returns None and bit_flip path mutates bytes.
    """

    p = FlakyServer(
        min_fuzz_bytes=1, max_fuzz_bytes=4, seed=1, fuzz_actions=["bit_flip"]
    )
    assert p._fuzz_wire(b"") is None

    q, wire = _mk_query()
    base = q.reply().pack()
    fuzzed = p._fuzz_wire(base)
    assert fuzzed is not None
    assert fuzzed != base
    assert len(fuzzed) == len(base)


def test_is_target_qtype_empty_apply_list_defaults_true():
    """Brief: _is_target_qtype returns True when apply_to_qtypes is empty.

    Inputs:
      - None.
    Outputs:
      - None; asserts empty list behaves as wildcard.
    """

    p = FlakyServer(apply_to_qtypes=[])
    assert p._is_target_qtype(QTYPE.A) is True


def test_post_resolve_early_exits_and_truncate_and_no_mutation():
    """Brief: post_resolve covers early exits, truncation, and non-mutating cases.

    Inputs:
      - None.
    Outputs:
      - None; asserts None when no targets/qtype mismatch and TC=1 on truncate.
    """

    q, wire = _mk_query()
    base_resp = q.reply().pack()

    # No targets configured -> no-op.
    p_no_targets = FlakyServer()
    assert (
        p_no_targets.post_resolve(
            "example.com", QTYPE.A, base_resp, PluginContext("192.0.2.55")
        )
        is None
    )

    # Targets configured but ctx not targeted -> no-op.
    p_targets = FlakyServer(targets=["192.0.2.55"])
    assert (
        p_targets.post_resolve(
            "example.com", QTYPE.A, base_resp, PluginContext("192.0.2.56")
        )
        is None
    )

    # Qtype filter blocks post_resolve when qtype excluded.
    p_qfilter = FlakyServer(targets=["192.0.2.55"], apply_to_qtypes=["AAAA"])
    assert (
        p_qfilter.post_resolve(
            "example.com", QTYPE.A, base_resp, PluginContext("192.0.2.55")
        )
        is None
    )

    # Truncation path: TC=1 when truncate_prob is 100%%.
    p_trunc = FlakyServer(
        targets=["192.0.2.55"],
        truncate_percent=100.0,
        servfail_percent=0.0,
        nxdomain_percent=0.0,
        fuzz_percent=0.0,
        wrong_qtype_percent=0.0,
        seed=1,
    )
    dec_t = p_trunc.post_resolve(
        "example.com", QTYPE.A, base_resp, PluginContext("192.0.2.55")
    )
    assert dec_t is not None
    trunc_rec = DNSRecord.parse(dec_t.response)
    assert trunc_rec.header.tc == 1

    # When all probabilities are zero but plugin is targeted, no mutation occurs.
    p_none = FlakyServer(targets=["192.0.2.55"], seed=1)
    dec_none = p_none.post_resolve(
        "example.com", QTYPE.A, base_resp, PluginContext("192.0.2.55")
    )
    assert dec_none is None


def test_post_resolve_fuzz_and_wrong_qtype():
    """Brief: post_resolve can fuzz bytes and rewrite question qtype.

    Inputs:
      - None; uses 100%% fuzz and wrong_qtype probabilities.
    Outputs:
      - None; asserts response is mutated and qtype can change.
    """
    q, wire = _mk_query()
    base_resp = q.reply().pack()

    # Pure fuzzing: bytes change but length stays the same.
    p_fuzz = FlakyServer(
        targets=["192.0.2.55"],
        servfail_percent=0.0,
        nxdomain_percent=0.0,
        fuzz_percent=100.0,
        min_fuzz_bytes=1,
        max_fuzz_bytes=4,
        seed=1,
    )
    dec_fuzz = p_fuzz.post_resolve(
        "example.com", QTYPE.A, base_resp, PluginContext("192.0.2.55")
    )
    assert dec_fuzz is not None
    assert dec_fuzz.action == "override"
    assert dec_fuzz.response != base_resp
    assert len(dec_fuzz.response) == len(base_resp)

    # Wrong-qtype mutation: question qtype changes from original.
    p_qtype = FlakyServer(
        targets=["192.0.2.55"],
        servfail_percent=0.0,
        nxdomain_percent=0.0,
        wrong_qtype_percent=100.0,
        seed=2,
    )
    dec_q = p_qtype.post_resolve(
        "example.com", QTYPE.A, base_resp, PluginContext("192.0.2.55")
    )
    assert dec_q is not None
    mutated = DNSRecord.parse(dec_q.response)
    assert mutated.questions
    assert mutated.questions[0].qtype != QTYPE.A
