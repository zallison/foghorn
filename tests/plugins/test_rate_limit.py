"""
Brief: Tests for foghorn.plugins.rate_limit.RateLimitPlugin learning and enforcement.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from contextlib import closing

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.base import PluginContext
from foghorn.plugins.rate_limit import RateLimitPlugin
import foghorn.plugins.rate_limit as rate_limit_module


def _set_time(monkeypatch, value: float) -> None:
    """Brief: Patch time.time used inside rate_limit module.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - value: float epoch seconds to return.

    Outputs:
      - None.
    """

    monkeypatch.setattr(rate_limit_module.time, "time", lambda: float(value))


def test_warmup_phase_does_not_enforce(tmp_path, monkeypatch):
    """Brief: During warmup windows the plugin only learns and never denies.

    Inputs:
      - tmp_path: temporary directory for sqlite DB.

    Outputs:
      - None: Asserts decisions are None during the configured warmup period.
    """

    db = tmp_path / "rl.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=2,
        min_enforce_rps=0.0,
        burst_factor=2.0,
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(plugin._conn):
        # Window 0: high volume, but no prior samples
        _set_time(monkeypatch, 0.0)
        for _ in range(100):
            dec = plugin.pre_resolve("sub.example.com.", QTYPE.A, b"", ctx)
            assert dec is None

        # Window 1: first completed window provides a single sample; still warmup
        _set_time(monkeypatch, 10.0)
        for _ in range(100):
            dec = plugin.pre_resolve("sub.example.com.", QTYPE.A, b"", ctx)
            assert dec is None


def test_enforces_after_learning_when_rate_spikes(tmp_path, monkeypatch):
    """Brief: After warmup, a large spike above baseline is denied.

    Inputs:
      - tmp_path: temporary directory for sqlite DB.
      - monkeypatch: to control time progression.

    Outputs:
      - None: Asserts that some queries are denied once rate exceeds learned threshold.
    """

    db = tmp_path / "rl2.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=1,
        alpha=0.5,
        burst_factor=1.5,
        min_enforce_rps=0.0,
        global_max_rps=1000.0,
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(plugin._conn):
        # Training window: steady 10 rps baseline
        _set_time(monkeypatch, 0.0)
        for _ in range(10):
            dec = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
            assert dec is None

        # Next window: large burst; warmup complete so enforcement is active.
        _set_time(monkeypatch, 10.0)
        denied = 0
        total = 0
        for _ in range(60):
            total += 1
            dec = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
            if dec is not None:
                assert dec.action == "deny"
                denied += 1
        # Some of the tail queries should be denied, but not necessarily the first few.
        assert denied > 0
        assert denied < total


def test_per_domain_mode_uses_base_domain_key(tmp_path, monkeypatch):
    """Brief: mode='per_domain' keys profiles by base domain only.

    Inputs:
      - tmp_path: temporary directory for sqlite DB (unused beyond plugin init).

    Outputs:
      - None: Asserts that two clients hitting the same domain share the same key.
    """

    db = tmp_path / "rl-domain.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        mode="per_domain",
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
    )
    plugin.setup()

    ctx1 = PluginContext(client_ip="1.2.3.4")
    ctx2 = PluginContext(client_ip="5.6.7.8")

    _set_time(monkeypatch, 0.0)
    # Same qname, different clients -> underlying key should be the same base domain.
    key1 = plugin._make_key("sub.example.com.", ctx1)
    key2 = plugin._make_key("sub.example.com.", ctx2)
    assert key1 == key2


def test_profiles_persist_and_can_be_read_from_db(tmp_path, monkeypatch):
    """Brief: profiles are persisted and contain sensible values.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture (unused here).

    Outputs:
      - None: uses assertions on stored profile fields.
    """
    """Brief: Completed window statistics are persisted to sqlite in rate_profiles.

    Inputs:
      - tmp_path: temporary directory for sqlite DB.

    Outputs:
      - None: Asserts that avg_rps, max_rps, and samples are stored for the client key.
    """

    db = tmp_path / "rl3.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
        burst_factor=2.0,
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(plugin._conn):
        # Single window with a fixed number of queries
        _set_time(monkeypatch, 0.0)
        for _ in range(20):
            assert plugin.pre_resolve("example.com", QTYPE.A, b"", ctx) is None

        # Advance into the next window so the previous one is committed to DB.
        _set_time(monkeypatch, 10.0)
        assert plugin.pre_resolve("example.com", QTYPE.A, b"", ctx) is None

        cur = plugin._conn.cursor()
        # For per_client mode the key is simply the client_ip string.
        cur.execute(
            "SELECT avg_rps, max_rps, samples FROM rate_profiles WHERE key=?",
            ("1.2.3.4",),
        )
        row = cur.fetchone()
        assert row is not None
        avg_rps, max_rps, samples = row
    assert avg_rps > 0.0
    assert max_rps >= avg_rps
    assert samples >= 1


def test_to_base_domain_single_label():
    """Brief: Single-label qname returns as-is (base label path).\n\n    Inputs:\n      - None.\n\n    Outputs:\n      - None: asserts helper returns the original label.\n"""

    assert rate_limit_module._to_base_domain("localhost.") == "localhost"


def test_get_config_model_returns_config_class():
    """Brief: get_config_model exposes the RateLimitConfig model.\n\n    Inputs:\n      - None.\n\n    Outputs:\n      - None: asserts the returned model is RateLimitConfig.\n"""

    model = RateLimitPlugin.get_config_model()
    assert model is rate_limit_module.RateLimitConfig


def test_invalid_mode_defaults_to_per_client(tmp_path):
    """Brief: Unknown mode falls back to 'per_client'.\n\n    Inputs:\n      - tmp_path: pytest tmp path for sqlite db.\n\n    Outputs:\n      - None: asserts plugin.mode is 'per_client'.\n"""

    db = tmp_path / "rl-mode.db"
    plugin = RateLimitPlugin(db_path=str(db), mode="invalid-mode")
    plugin.setup()
    assert plugin.mode == "per_client"


def test_invalid_deny_response_defaults_to_nxdomain(tmp_path):
    """Brief: Unknown deny_response falls back to 'nxdomain'.\n\n    Inputs:\n      - tmp_path: pytest tmp path for sqlite db.\n\n    Outputs:\n      - None: asserts deny_response attribute is normalized.\n"""

    db = tmp_path / "rl-deny.db"
    plugin = RateLimitPlugin(db_path=str(db), deny_response="bogus")
    plugin.setup()
    assert plugin.deny_response == "nxdomain"


def test_int_config_parsing_and_clamping(tmp_path):
    """Brief: _parse_int_config handles non-integers and clamps to minimum.\n\n    Inputs:\n      - tmp_path: pytest tmp path for sqlite db.\n\n    Outputs:\n      - None: asserts defaults and minimum clamping are applied.\n"""

    db = tmp_path / "rl-int.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        window_seconds="not-an-int",
        warmup_windows=-5,
    )
    plugin.setup()
    # Non-integer window_seconds falls back to default (10).
    assert plugin.window_seconds == 10
    # Negative warmup_windows is clamped to minimum of 0.
    assert plugin.warmup_windows == 0


def test_float_config_parsing_and_clamping(tmp_path):
    """Brief: _parse_float_config handles bad types and range limits.\n\n    Inputs:\n      - tmp_path: pytest tmp path for sqlite db.\n\n    Outputs:\n      - None: asserts defaults, min, and max clamping are applied.\n"""

    db = tmp_path / "rl-float.db"
    # alpha is a non-float -> use default 0.2; alpha_down below min; burst_factor below 1.0.
    plugin = RateLimitPlugin(
        db_path=str(db),
        alpha="not-a-float",
        alpha_down=-0.1,
        burst_factor=0.5,
    )
    plugin.setup()
    assert plugin.alpha == 0.2
    # alpha_down minimum is 0.0.
    assert plugin.alpha_down == 0.0
    # burst_factor minimum is 1.0.
    assert plugin.burst_factor == 1.0

    # Second instance to exercise max clamping branch.
    db2 = tmp_path / "rl-float-max.db"
    plugin2 = RateLimitPlugin(
        db_path=str(db2),
        alpha=2.0,
        alpha_down=5.0,
    )
    plugin2.setup()
    # Both alpha and alpha_down are clamped to maximum 1.0.
    assert plugin2.alpha == 1.0
    assert plugin2.alpha_down == 1.0


def test_per_client_domain_mode_uses_client_and_base_domain(tmp_path, monkeypatch):
    """Brief: mode='per_client_domain' uses client_ip and base domain in key.\n\n    Inputs:\n      - tmp_path: pytest tmp path.\n      - monkeypatch: unused here but matches other tests.\n\n    Outputs:\n      - None: asserts key combines client and base domain.\n"""

    db = tmp_path / "rl-client-domain.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        mode="per_client_domain",
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
    )
    plugin.setup()

    ctx = PluginContext(client_ip="1.2.3.4")
    key = plugin._make_key("sub.example.com.", ctx)
    assert key.startswith("1.2.3.4|")
    assert key.endswith("example.com")


def test_increment_window_default_now_uses_time(monkeypatch, tmp_path):
    """Brief: _increment_window uses time.time() when now is omitted.\n\n    Inputs:\n      - monkeypatch: pytest monkeypatch fixture.\n      - tmp_path: pytest tmp path.\n\n    Outputs:\n      - None: asserts window_id and count are computed.\n"""

    db = tmp_path / "rl-window.db"
    plugin = RateLimitPlugin(db_path=str(db), window_seconds=10, warmup_windows=0)
    plugin.setup()

    monkeypatch.setattr(rate_limit_module.time, "time", lambda: 30.0)
    window_id, count = plugin._increment_window("client-1")
    assert window_id == int(30.0 // 10)
    assert count == 1


def test_build_deny_decision_status_codes(tmp_path):
    """Brief: deny_response modes map to expected DNS status codes.\n\n    Inputs:\n      - tmp_path: pytest tmp path.\n\n    Outputs:\n      - None: asserts override responses have appropriate rcodes.\n"""

    db = tmp_path / "rl-deny-modes.db"
    plugin = RateLimitPlugin(db_path=str(db), deny_response="refused")
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    req = DNSRecord.question("example.com", "A")
    wire = req.pack()

    decision = plugin._build_deny_decision("example.com", QTYPE.A, wire, ctx)
    assert decision.action == "override"
    refused = DNSRecord.parse(decision.response)
    assert refused.header.rcode == 5  # REFUSED

    # Switch deny mode to servfail and noerror_empty to exercise branches.
    plugin.deny_response = "servfail"
    decision2 = plugin._build_deny_decision("example.com", QTYPE.A, wire, ctx)
    servfail = DNSRecord.parse(decision2.response)
    assert servfail.header.rcode == 2  # SERVFAIL

    plugin.deny_response = "noerror_empty"
    decision3 = plugin._build_deny_decision("example.com", QTYPE.A, wire, ctx)
    noerror = DNSRecord.parse(decision3.response)
    assert noerror.header.rcode == 0  # NOERROR
    assert noerror.rr == []


def test_build_deny_decision_ip_mode_and_fallback(tmp_path):
    """Brief: deny_response 'ip' uses override when IP is configured, else deny.\n\n    Inputs:\n      - tmp_path: pytest tmp path.\n\n    Outputs:\n      - None: asserts both override and simple deny behavior.\n"""

    db = tmp_path / "rl-deny-ip.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        deny_response="ip",
        deny_response_ip4="192.0.2.1",
        deny_response_ip6="2001:db8::1",
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    req_a = DNSRecord.question("example.com", "A")
    wire_a = req_a.pack()
    decision_a = plugin._build_deny_decision("example.com", QTYPE.A, wire_a, ctx)
    assert decision_a.action == "override"
    assert decision_a.response is not None

    req_aaaa = DNSRecord.question("example.com", "AAAA")
    wire_aaaa = req_aaaa.pack()
    decision_aaaa = plugin._build_deny_decision(
        "example.com", QTYPE.AAAA, wire_aaaa, ctx
    )
    assert decision_aaaa.action == "override"

    # When no IPs are configured, IP mode falls back to a simple deny.
    plugin2 = RateLimitPlugin(db_path=str(db), deny_response="ip")
    plugin2.setup()
    decision_fallback = plugin2._build_deny_decision(
        "example.com", QTYPE.A, wire_a, ctx
    )
    assert decision_fallback.action == "deny"


def test_pre_resolve_respects_targets_and_missing_client_ip(tmp_path, monkeypatch):
    """Brief: pre_resolve short-circuits on non-targets and missing client IP.\n\n    Inputs:\n      - tmp_path: pytest tmp path.\n      - monkeypatch: pytest monkeypatch fixture.\n\n    Outputs:\n      - None: asserts early-return branches are exercised.\n"""

    db = tmp_path / "rl-targets.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
        targets=["10.0.0.0/8"],
    )
    plugin.setup()

    # Client outside targets is ignored by plugin.
    ctx_not_targeted = PluginContext(client_ip="192.0.2.1")
    _set_time(monkeypatch, 0.0)
    assert plugin.pre_resolve("example.com", QTYPE.A, b"", ctx_not_targeted) is None

    # With no targets configured, but an empty client_ip, pre_resolve also returns None.
    plugin2 = RateLimitPlugin(db_path=str(db), window_seconds=10, warmup_windows=0)
    plugin2.setup()
    ctx_empty_ip = PluginContext(client_ip="")
    _set_time(monkeypatch, 0.0)
    assert plugin2.pre_resolve("example.com", QTYPE.A, b"", ctx_empty_ip) is None


def test_asymmetric_alpha_allows_slower_ramp_down(tmp_path, monkeypatch):
    """Brief: alpha_down is used when new RPS is below the learned average.

    Inputs:
      - tmp_path: temporary directory for sqlite DB.
      - monkeypatch: pytest monkeypatch fixture (unused here).

    Outputs:
      - None: asserts that the average drops using alpha_down when rps decreases.
    """

    db = tmp_path / "rl-alpha.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        alpha=0.5,
        alpha_down=0.1,
        min_enforce_rps=0.0,
    )
    plugin.setup()

    key = "client-1"
    now_ts = 1000

    # First update establishes a baseline at 10 RPS.
    plugin._db_update_profile(key, 10.0, now_ts)
    avg_rps, max_rps, samples = plugin._db_get_profile(key)
    assert avg_rps == 10.0
    assert samples == 1

    # Next update with higher RPS should use alpha=0.5 and move halfway toward 20.
    plugin._db_update_profile(key, 20.0, now_ts + 10)
    avg_rps, max_rps, samples = plugin._db_get_profile(key)
    assert samples == 2
    assert avg_rps == 15.0

    # Update with lower RPS (0) should use alpha_down=0.1 and decay slowly.
    plugin._db_update_profile(key, 0.0, now_ts + 20)
    avg_rps, max_rps, samples = plugin._db_get_profile(key)
    assert samples == 3
    #  new_avg = (1 - 0.1) * 15 + 0.1 * 0 = 13.5
    assert avg_rps == 13.5


def test_malformed_rate_profiles_rows_are_ignored(tmp_path, monkeypatch):
    """Brief: Malformed rate_profiles rows (bad values) are ignored safely.

    Inputs:
      - tmp_path: temporary directory for sqlite DB.
      - monkeypatch: pytest monkeypatch fixture (unused here).

    Outputs:
      - None: asserts that bad avg_rps/max_rps/samples do not crash pre_resolve
        and that profiles are reset on next update.
    """

    db = tmp_path / "rl-bad-row.db"
    plugin = RateLimitPlugin(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
    )
    plugin.setup()
    ctx = PluginContext(client_ip="192.0.2.1")

    # Seed a malformed row with bad "numeric" values that will fail conversion.
    cur = plugin._conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO rate_profiles(key, avg_rps, max_rps, samples, last_update) "
        "VALUES(?, ?, ?, ?, ?)",
        ("192.0.2.1", "not-a-float", "not-a-float", "not-an-int", int(1000)),
    )
    plugin._conn.commit()

    # pre_resolve should not crash and should treat the profile as missing.
    _set_time(monkeypatch, 1000.0)
    decision = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
    assert decision is None

    # A completed window should overwrite the malformed row via _db_update_profile.
    _set_time(monkeypatch, 1010.0)
    for _ in range(5):
        # We only care that this does not crash; enforcement may begin once
        # a valid profile exists again, so the decision can be None or deny.
        plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)

    profile = plugin._db_get_profile("192.0.2.1")
    assert profile is not None
    avg_rps, max_rps, samples = profile
    assert avg_rps >= 0.0
    assert max_rps >= avg_rps
    assert samples >= 1
