"""
Brief: Tests for foghorn.plugins.rate_limit.RateLimit learning and enforcement.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

import threading
from contextlib import closing

import pytest
from dnslib import QTYPE, DNSRecord
from pydantic import ValidationError

import foghorn.plugins.resolve.rate_limit as rate_limit_module
from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.rate_limit import RateLimit


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
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=2,
        min_enforce_rps=0.0,
        burst_factor=2.0,
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4", listener="tcp")

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
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=1,
        alpha=0.5,
        burst_factor=1.5,
        min_enforce_rps=0.0,
        global_max_rps=1000.0,
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4", listener="tcp")

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


def test_hard_cap_enforces_when_avg_below_min_enforce_rps(tmp_path, monkeypatch):
    """Brief: max_enforce_rps still enforces below default min_enforce_rps.

    Inputs:
      - tmp_path: temporary directory for sqlite DB.
      - monkeypatch: pytest monkeypatch fixture to keep requests in one window.

    Outputs:
      - None: Asserts hard-cap denials occur when current RPS exceeds cap.
    """

    db = tmp_path / "rl-hard-cap.db"
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        burst_factor=4.0,
        max_enforce_rps=10.0,
        bootstrap_rps=10.0,
        deny_response="nxdomain",
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4", listener="tcp")

    with closing(plugin._conn):
        _set_time(monkeypatch, 0.0)
        total = 120
        denied = 0
        for _ in range(total):
            decision = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
            if decision is not None:
                assert decision.action == "deny"
                denied += 1

        # avg_rps/bootstrap is 10 while min_enforce_rps defaults to 50; the
        # configured hard cap should still deny once current_rps exceeds 10.
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
    plugin = RateLimit(
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
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
        burst_factor=2.0,
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4", listener="tcp")

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
    """Brief: Single-label qname returns as-is.

    Inputs:
      - None.

    Outputs:
      - None: asserts helper returns the original label.
    """

    assert rate_limit_module._to_base_domain("localhost.") == "localhost"


def test_to_base_domain_is_psl_aware_for_common_suffixes():
    """Brief: Base domain extraction uses the Public Suffix List (PSL).

    Inputs:
      - None.

    Outputs:
      - None: asserts multi-label public suffixes (e.g. co.uk) are handled.
    """

    assert rate_limit_module._to_base_domain("a.b.example.co.uk.") == "example.co.uk"
    assert rate_limit_module._to_base_domain("a.b.example.com.au.") == "example.com.au"


def test_to_base_domain_is_psl_aware_for_private_suffixes_like_github_io():
    """Brief: PSL extraction respects common private suffix entries.

    Inputs:
      - None.

    Outputs:
      - None: asserts github.io-style suffixes keep the user label.
    """

    assert rate_limit_module._to_base_domain("a.b.user.github.io.") == "user.github.io"


def test_missing_psl_switches_domain_mode_to_per_client(tmp_path, monkeypatch):
    """Brief: Missing PSL support forces domain-based modes to fall back.

    Inputs:
      - tmp_path: pytest temp path for sqlite DB.
      - monkeypatch: pytest monkeypatch fixture to simulate missing PSL.

    Outputs:
      - None: asserts mode changes and PSL availability is False.
    """

    monkeypatch.setattr(rate_limit_module, "_psl_is_available", lambda: False)
    db = tmp_path / "rl-psl-missing.db"
    plugin = RateLimit(db_path=str(db), mode="per_domain")
    plugin.setup()
    assert plugin.mode == "per_client"
    assert plugin._psl_available is False


def test_get_config_model_returns_config_class():
    """Brief: get_config_model exposes the RateLimitConfig model.\n\n    Inputs:\n      - None.\n\n    Outputs:\n      - None: asserts the returned model is RateLimitConfig.\n"""

    model = RateLimit.get_config_model()
    assert model is rate_limit_module.RateLimitConfig


def test_rate_limit_config_applies_defaults_for_new_fields():
    """Brief: New RateLimitConfig fields default correctly when omitted.

    Inputs:
      - None

    Outputs:
      - None: asserts new fields are populated with documented defaults.
    """

    cfg = rate_limit_module.RateLimitConfig()

    assert cfg.max_profiles == 10000
    assert cfg.profile_ttl_seconds == 7 * 24 * 60 * 60
    assert cfg.prune_interval_seconds == 60

    assert cfg.assume_udp_when_listener_missing is True
    assert cfg.bucket_network_prefix_v4 == 24
    assert cfg.bucket_network_prefix_v6 == 56
    assert cfg.limit_recalc_windows == 10
    assert cfg.warmup_max_rps == 0.0
    assert cfg.burst_reset_windows == 20
    assert cfg.bootstrap_rps == 50.0
    assert cfg.stats_window_seconds == 0
    assert cfg.psl_strict is False


def test_rate_limit_config_validates_max_profiles_ge_1():
    """Brief: max_profiles must be >= 1.

    Inputs:
      - None

    Outputs:
      - None: asserts ValidationError for invalid values.
    """

    rate_limit_module.RateLimitConfig(max_profiles=1)

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(max_profiles=0)


def test_rate_limit_config_validates_ttls_and_prune_interval_ge_0():
    """Brief: ttl/prune/window knobs must be >= 0.

    Inputs:
      - None

    Outputs:
      - None: asserts ValidationError for invalid values.
    """

    rate_limit_module.RateLimitConfig(
        profile_ttl_seconds=0,
        prune_interval_seconds=0,
        stats_window_seconds=0,
    )

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(profile_ttl_seconds=-1)

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(prune_interval_seconds=-1)

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(stats_window_seconds=-1)


def test_rate_limit_config_validates_bucket_network_prefix_ranges():
    """Brief: bucket_network_prefix_v4/v6 must be within CIDR prefix bounds.

    Inputs:
      - None

    Outputs:
      - None: asserts v4 in [0,32] and v6 in [0,128].
    """

    rate_limit_module.RateLimitConfig(
        bucket_network_prefix_v4=0, bucket_network_prefix_v6=0
    )
    rate_limit_module.RateLimitConfig(
        bucket_network_prefix_v4=32, bucket_network_prefix_v6=128
    )

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(bucket_network_prefix_v4=-1)

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(bucket_network_prefix_v4=33)

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(bucket_network_prefix_v6=-1)

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(bucket_network_prefix_v6=129)


def test_rate_limit_config_rejects_removed_udp_keying():
    """Brief: Removed udp_keying config is rejected.

    Inputs:
      - None

    Outputs:
      - None: asserts ValidationError when udp_keying is provided.
    """

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(udp_keying="cidr")


def test_setup_rejects_removed_udp_keying(tmp_path):
    """Brief: setup() rejects removed udp_keying config key.

    Inputs:
      - tmp_path: pytest tmp path for sqlite db.

    Outputs:
      - None: asserts ValueError when udp_keying is supplied.
    """

    db = tmp_path / "rl-udp-key-removed.db"
    plugin = RateLimit(db_path=str(db), udp_keying="cidr")

    with pytest.raises(ValueError):
        plugin.setup()


def test_rate_limit_config_validates_limit_recalc_windows_ge_1():
    """Brief: limit_recalc_windows must be >= 1.

    Inputs:
      - None

    Outputs:
      - None: asserts ValidationError for invalid values.
    """

    rate_limit_module.RateLimitConfig(limit_recalc_windows=1)

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(limit_recalc_windows=0)


def test_recalculated_allowed_rps_refreshes_seen_buckets_each_window(tmp_path):
    """Brief: Seen buckets recalculate once per request window interval.

    Inputs:
      - tmp_path: pytest tmp path for sqlite db.

    Outputs:
      - None: asserts same-window values stay cached and next-window values refresh.
    """

    db = tmp_path / "rl-limit-recalc-seen.db"
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        burst_factor=2.0,
        max_enforce_rps=0.0,
        limit_recalc_windows=3,
    )
    plugin.setup()

    burst_1, base_1 = plugin._get_recalculated_allowed_rps(
        key="client-1",
        avg_rps=10.0,
        samples=5,
        now=0.0,
    )
    assert burst_1 == pytest.approx(20.0)
    assert base_1 == pytest.approx(10.0)

    # Same window: thresholds remain cached even if avg_rps input changes.
    burst_2, base_2 = plugin._get_recalculated_allowed_rps(
        key="client-1",
        avg_rps=20.0,
        samples=6,
        now=9.9,
    )
    assert burst_2 == pytest.approx(burst_1)
    assert base_2 == pytest.approx(base_1)

    # Next window: seen bucket thresholds are recalculated.
    burst_3, base_3 = plugin._get_recalculated_allowed_rps(
        key="client-1",
        avg_rps=20.0,
        samples=7,
        now=10.0,
    )
    assert burst_3 == pytest.approx(40.0)
    assert base_3 == pytest.approx(20.0)


def test_limit_recalc_windows_globally_refreshes_unseen_bucket_limits(tmp_path):
    """Brief: limit_recalc_windows globally refreshes unseen bucket thresholds.

    Inputs:
      - tmp_path: pytest tmp path for sqlite db.

    Outputs:
      - None: asserts unseen buckets are refreshed from DB on global cadence.
    """

    db = tmp_path / "rl-limit-recalc-global.db"
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        burst_factor=2.0,
        max_enforce_rps=0.0,
        limit_recalc_windows=3,
    )
    plugin.setup()

    seen_key = "client-seen"
    unseen_key = "client-unseen"
    plugin._seed_profile(seen_key, rps=5.0, now_ts=0, samples=5)
    plugin._seed_profile(unseen_key, rps=10.0, now_ts=0, samples=5)

    unseen_burst_1, unseen_base_1 = plugin._get_recalculated_allowed_rps(
        key=unseen_key,
        avg_rps=10.0,
        samples=5,
        now=0.0,
    )
    assert unseen_burst_1 == pytest.approx(20.0)
    assert unseen_base_1 == pytest.approx(10.0)

    # Raise unseen key baseline in DB but do not touch that key again.
    plugin._seed_profile(unseen_key, rps=30.0, now_ts=1, samples=6)

    # Drive traffic for a different key; global recalc should run at window 3.
    plugin._get_recalculated_allowed_rps(
        key=seen_key,
        avg_rps=5.0,
        samples=5,
        now=10.0,
    )
    plugin._get_recalculated_allowed_rps(
        key=seen_key,
        avg_rps=5.0,
        samples=6,
        now=20.0,
    )
    plugin._get_recalculated_allowed_rps(
        key=seen_key,
        avg_rps=5.0,
        samples=7,
        now=30.0,
    )

    unseen_burst_2, unseen_base_2 = plugin._get_recalculated_allowed_rps(
        key=unseen_key,
        avg_rps=10.0,
        samples=6,
        now=30.0,
    )
    assert unseen_burst_2 == pytest.approx(60.0)
    assert unseen_base_2 == pytest.approx(30.0)


def test_invalid_mode_defaults_to_per_client(tmp_path):
    """Brief: Unknown mode falls back to 'per_client'.\n\n    Inputs:\n      - tmp_path: pytest tmp path for sqlite db.\n\n    Outputs:\n      - None: asserts plugin.mode is 'per_client'.\n"""

    db = tmp_path / "rl-mode.db"
    plugin = RateLimit(db_path=str(db), mode="invalid-mode")
    plugin.setup()
    assert plugin.mode == "per_client"


def test_invalid_deny_response_defaults_to_refused(tmp_path):
    """Brief: Unknown deny_response falls back to 'refused'.\n\n    Inputs:\n      - tmp_path: pytest tmp path for sqlite db.\n\n    Outputs:\n      - None: asserts deny_response attribute is normalized.\n"""

    db = tmp_path / "rl-deny.db"
    plugin = RateLimit(db_path=str(db), deny_response="bogus")
    plugin.setup()
    assert plugin.deny_response == "refused"


def test_int_config_parsing_and_clamping(tmp_path):
    """Brief: _parse_int_config handles non-integers and clamps to minimum.\n\n    Inputs:\n      - tmp_path: pytest tmp path for sqlite db.\n\n    Outputs:\n      - None: asserts defaults and minimum clamping are applied.\n"""

    db = tmp_path / "rl-int.db"
    plugin = RateLimit(
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
    plugin = RateLimit(
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
    plugin2 = RateLimit(
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
    plugin = RateLimit(
        db_path=str(db),
        mode="per_client_domain",
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
    )
    plugin.setup()

    ctx = PluginContext(client_ip="1.2.3.4", listener="tcp")
    key = plugin._make_key("sub.example.com.", ctx)
    assert key.startswith("1.2.3.4|")
    assert key.endswith("example.com")


def test_increment_window_default_now_uses_time(monkeypatch, tmp_path):
    """Brief: _increment_window uses time.time() when now is omitted.\n\n    Inputs:\n      - monkeypatch: pytest monkeypatch fixture.\n      - tmp_path: pytest tmp path.\n\n    Outputs:\n      - None: asserts window_id and count are computed.\n"""

    db = tmp_path / "rl-window.db"
    plugin = RateLimit(db_path=str(db), window_seconds=10, warmup_windows=0)
    plugin.setup()

    monkeypatch.setattr(rate_limit_module.time, "time", lambda: 30.0)
    window_id, count = plugin._increment_window("client-1")
    assert window_id == int(30.0 // 10)
    assert count == 1


def test_get_http_snapshot_includes_current_rps(tmp_path, monkeypatch):
    """Brief: get_http_snapshot includes active current_rps in settings.

    Inputs:
      - tmp_path: pytest temporary path for sqlite DB.
      - monkeypatch: fixture used to pin time to one active request window.

    Outputs:
      - None: asserts settings.current_rps reflects the in-progress global window.
    """

    db = tmp_path / "rl-snapshot-current-rps.db"
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
    )
    plugin.setup()

    ctx = PluginContext(client_ip="1.2.3.4", listener="tcp")

    with closing(plugin._conn):
        _set_time(monkeypatch, 0.0)
        for _ in range(25):
            assert plugin.pre_resolve("example.com", QTYPE.A, b"", ctx) is None

        snapshot = plugin.get_http_snapshot()

    settings = snapshot.get("settings")
    assert isinstance(settings, dict)
    assert float(settings.get("current_rps", -1.0)) == pytest.approx(2.5)


def test_increment_window_is_atomic_under_concurrency(tmp_path):
    """Brief: Concurrent window increments for a key are not lost.

    Inputs:
      - tmp_path: pytest temp path for sqlite DB.

    Outputs:
      - None: asserts final count equals total increments.
    """

    db = tmp_path / "rl-concurrent.db"
    plugin = RateLimit(db_path=str(db), window_seconds=10, warmup_windows=0)
    plugin.setup()

    key = "client-1"
    threads: list[threading.Thread] = []
    errors: list[Exception] = []
    per_thread = 50
    num_threads = 20
    barrier = threading.Barrier(num_threads)

    def worker() -> None:
        try:
            barrier.wait()
            for _ in range(per_thread):
                plugin._increment_window(key, now=0.0)
        except Exception as exc:  # pragma: no cover - exercised via stress
            errors.append(exc)

    for _ in range(num_threads):
        threads.append(threading.Thread(target=worker))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    raw = plugin._window_cache.get((key, 0))
    assert raw is not None
    window_id_str, count_str = raw.decode().split(":", 1)
    assert int(window_id_str) == 0
    assert int(count_str) == per_thread * num_threads


def test_build_deny_decision_status_codes(tmp_path):
    """Brief: deny_response modes map to expected DNS status codes.\n\n    Inputs:\n      - tmp_path: pytest tmp path.\n\n    Outputs:\n      - None: asserts override responses have appropriate rcodes.\n"""

    db = tmp_path / "rl-deny-modes.db"
    plugin = RateLimit(db_path=str(db), deny_response="refused")
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


def test_build_deny_decision_drop_mode(tmp_path):
    """Brief: deny_response='drop' returns a drop decision.

    Inputs:
      - tmp_path: pytest tmp path.

    Outputs:
      - None: asserts drop mode remains configured and emits action='drop'.
    """

    db = tmp_path / "rl-deny-drop.db"
    plugin = RateLimit(db_path=str(db), deny_response="drop")
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    req = DNSRecord.question("example.com", "A")
    wire = req.pack()
    decision = plugin._build_deny_decision("example.com", QTYPE.A, wire, ctx)

    assert plugin.deny_response == "drop"
    assert decision.action == "drop"
    assert decision.response is None


def test_build_deny_decision_ip_mode_and_fallback(tmp_path):
    """Brief: deny_response 'ip' uses override when IP is configured, else deny.\n\n    Inputs:\n      - tmp_path: pytest tmp path.\n\n    Outputs:\n      - None: asserts both override and simple deny behavior.\n"""

    db = tmp_path / "rl-deny-ip.db"
    plugin = RateLimit(
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

    req_mx = DNSRecord.question("example.com", "MX")
    wire_mx = req_mx.pack()
    decision_mx = plugin._build_deny_decision("example.com", QTYPE.MX, wire_mx, ctx)
    assert decision_mx.action == "deny"

    # When no IPs are configured, IP mode falls back to a simple deny.
    plugin2 = RateLimit(db_path=str(db), deny_response="ip")
    plugin2.setup()
    decision_fallback = plugin2._build_deny_decision(
        "example.com", QTYPE.A, wire_a, ctx
    )
    assert decision_fallback.action == "deny"


def test_pre_resolve_respects_targets_and_missing_client_ip(tmp_path, monkeypatch):
    """Brief: pre_resolve short-circuits on non-targets and missing client IP.\n\n    Inputs:\n      - tmp_path: pytest tmp path.\n      - monkeypatch: pytest monkeypatch fixture.\n\n    Outputs:\n      - None: asserts early-return branches are exercised.\n"""

    db = tmp_path / "rl-targets.db"
    plugin = RateLimit(
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
    plugin2 = RateLimit(db_path=str(db), window_seconds=10, warmup_windows=0)
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
    plugin = RateLimit(
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


def test_burst_reset_requires_configured_below_threshold_windows(tmp_path):
    """Brief: burst_reset_windows controls burst-state reset cadence.

    Inputs:
      - tmp_path: pytest temporary path for sqlite DB.

    Outputs:
      - None: asserts burst state only resets after burst_reset_windows
        consecutive below-threshold completed windows.
    """

    db = tmp_path / "rl-burst-reset.db"
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
        burst_factor=2.0,
        burst_windows=3,
        burst_reset_windows=2,
        max_enforce_rps=0.0,
    )
    plugin.setup()

    key = "client-1"
    plugin._seed_profile(key, rps=10.0, now_ts=1000, samples=20)

    # Two burst windows raise burst count to 2.
    plugin._update_burst_counter(key, rps=30.0)
    plugin._update_burst_counter(key, rps=30.0)
    assert plugin._get_burst_count(key) == 2

    # First low window should not reset yet.
    plugin._update_burst_counter(key, rps=10.0)
    assert plugin._get_burst_count(key) == 2

    # Second consecutive low window reaches burst_reset_windows and resets.
    plugin._update_burst_counter(key, rps=10.0)
    assert plugin._get_burst_count(key) == 0


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
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
    )
    plugin.setup()
    ctx = PluginContext(client_ip="192.0.2.1", listener="tcp")

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


def test_db_get_profile_is_thread_safe_with_lock(tmp_path):
    """Brief: _db_get_profile can be called safely from multiple threads.

    Inputs:
      - tmp_path: pytest tmp path for sqlite db.

    Outputs:
      - None: asserts concurrent readers/writers do not raise and see profiles.
    """

    db = tmp_path / "rl-thread.db"
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
    )
    plugin.setup()

    key = "client-1"
    now_ts = 1000
    # Establish an initial profile so readers have something to fetch.
    plugin._db_update_profile(key, 10.0, now_ts)

    errors: list[Exception] = []

    def reader() -> None:
        try:
            for _ in range(200):
                profile = plugin._db_get_profile(key)
                assert profile is not None
        except Exception as exc:  # pragma: no cover - exercised via threaded stress
            errors.append(exc)

    def writer() -> None:
        try:
            local_now = now_ts
            for i in range(50):
                plugin._db_update_profile(key, 10.0 + float(i), local_now + i)
        except Exception as exc:  # pragma: no cover - exercised via threaded stress
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    threads.append(threading.Thread(target=writer))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors

    # Final profile should still be readable.
    final_profile = plugin._db_get_profile(key)
    assert final_profile is not None
    avg_rps, max_rps, samples = final_profile
    assert avg_rps >= 0.0
    assert max_rps >= avg_rps
    assert samples >= 1


def test_stats_logging_uses_configured_window(tmp_path):
    """Brief: _maybe_log_stats applies a true sample-based lookback window.

    Inputs:
      - tmp_path: pytest temp path for sqlite db.

    Outputs:
      - None: asserts old spikes outside the window are excluded from max stats.
    """

    db = tmp_path / "rl-stats-window.db"
    plugin = RateLimit(
        db_path=str(db),
        stats_log_interval_seconds=1,
        stats_window_seconds=300,
    )
    plugin.setup()

    # Same key had a large historical burst, then a recent low window.
    # Windowed stats should only reflect the recent sample.
    plugin._db_update_profile("same-key", 100.0, now_ts=1000)
    plugin._db_update_profile("same-key", 5.0, now_ts=1990)

    records: list[tuple[object, ...]] = []
    original_logger_info = rate_limit_module.logger.info

    def _capture_info(message: object, *args: object, **kwargs: object) -> None:
        records.append((message, *args))

    rate_limit_module.logger.info = _capture_info  # type: ignore[assignment]
    try:
        plugin._last_stats_log_ts = 0.0
        plugin._maybe_log_stats(now=2000.0)
    finally:
        rate_limit_module.logger.info = original_logger_info  # type: ignore[assignment]

    assert len(records) == 1
    message, *args = records[0]
    assert "stats_window_seconds=%d" in str(message)

    # Only the recent sample for the same key should be included (cutoff=1700).
    assert args[0] == "rate_limit"
    assert args[1] == 5.0
    assert args[2] == 5.0
    assert args[3] == 1
    assert args[4] == 5.0
    assert args[5] == 300


def test_stats_logging_cadence_follows_stats_window_seconds(tmp_path):
    """Brief: stats_window_seconds overrides stats log cadence when configured.

    Inputs:
      - tmp_path: pytest temp path for sqlite db.

    Outputs:
      - None: asserts logs emit at stats_window_seconds intervals.
    """

    db = tmp_path / "rl-stats-cadence.db"
    plugin = RateLimit(
        db_path=str(db),
        stats_log_interval_seconds=900,
        stats_window_seconds=300,
    )
    plugin.setup()

    plugin._db_update_profile("recent", 5.0, now_ts=2005)

    records: list[tuple[object, ...]] = []
    original_logger_info = rate_limit_module.logger.info

    def _capture_info(message: object, *args: object, **kwargs: object) -> None:
        records.append((message, *args))

    rate_limit_module.logger.info = _capture_info  # type: ignore[assignment]
    try:
        plugin._last_stats_log_ts = 0.0
        plugin._maybe_log_stats(now=2000.0)
        # Too soon for a second log when cadence is 300 seconds.
        plugin._maybe_log_stats(now=2200.0)
        # Exactly at cadence threshold -> should log again.
        plugin._maybe_log_stats(now=2300.0)
    finally:
        rate_limit_module.logger.info = original_logger_info  # type: ignore[assignment]

    assert len(records) == 2
    for message, *args in records:
        assert "stats_window_seconds=%d" in str(message)
        assert args[5] == 300


def test_stats_logging_concurrent_calls_emit_once_per_interval(tmp_path):
    """Brief: Concurrent _maybe_log_stats calls emit at most one summary line.

    Inputs:
      - tmp_path: pytest temp path for sqlite db.

    Outputs:
      - None: asserts only one periodic RateLimit stats log is emitted for a
        shared interval under concurrent invocation.
    """

    db = tmp_path / "rl-stats-concurrent.db"
    plugin = RateLimit(
        db_path=str(db),
        stats_log_interval_seconds=1,
        stats_window_seconds=0,
    )
    plugin.setup()
    plugin._db_update_profile("recent", 5.0, now_ts=2005)

    records: list[tuple[object, ...]] = []
    errors: list[Exception] = []
    start = threading.Barrier(3)
    original_logger_info = rate_limit_module.logger.info

    def _capture_info(message: object, *args: object, **kwargs: object) -> None:
        records.append((message, *args))

    def _worker() -> None:
        try:
            start.wait(timeout=2.0)
            plugin._maybe_log_stats(now=2000.0)
        except Exception as exc:  # pragma: no cover - defensive thread collection
            errors.append(exc)

    rate_limit_module.logger.info = _capture_info  # type: ignore[assignment]
    plugin._last_stats_log_ts = 0.0
    plugin._db_lock.acquire()
    t1 = threading.Thread(target=_worker)
    t2 = threading.Thread(target=_worker)
    t1.start()
    t2.start()
    try:
        start.wait(timeout=2.0)
        # Hold the DB lock briefly so both threads contend in the same interval.
        threading.Event().wait(0.2)
    finally:
        if plugin._db_lock.locked():
            plugin._db_lock.release()
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)
        rate_limit_module.logger.info = original_logger_info  # type: ignore[assignment]

    assert not errors
    assert not t1.is_alive()
    assert not t2.is_alive()
    assert len(records) == 1


def test_db_prunes_by_max_profiles(tmp_path):
    """Brief: sqlite profile table is bounded by max_profiles via pruning.

    Inputs:
      - tmp_path: pytest temp path for sqlite DB.

    Outputs:
      - None: asserts total rows never exceed max_profiles after updates.
    """

    db = tmp_path / "rl-prune-max.db"
    plugin = RateLimit(
        db_path=str(db),
        max_profiles=3,
        prune_interval_seconds=0,
        profile_ttl_seconds=0,
    )
    plugin.setup()

    # Write more profiles than the cap.
    for i in range(10):
        plugin._db_update_profile(f"client-{i}", 1.0, now_ts=1000 + i)

    cur = plugin._conn.cursor()
    cur.execute("SELECT COUNT(*) FROM rate_profiles")
    count = int(cur.fetchone()[0])
    assert count <= 3


def test_db_prunes_by_profile_ttl_seconds(tmp_path):
    """Brief: sqlite profiles older than profile_ttl_seconds are pruned.

    Inputs:
      - tmp_path: pytest temp path for sqlite DB.

    Outputs:
      - None: asserts old rows are removed after a later update triggers pruning.
    """

    db = tmp_path / "rl-prune-ttl.db"
    plugin = RateLimit(
        db_path=str(db),
        max_profiles=100,
        prune_interval_seconds=0,
        profile_ttl_seconds=1,
    )
    plugin.setup()

    plugin._db_update_profile("old", 1.0, now_ts=0)
    plugin._db_update_profile("new", 1.0, now_ts=10)

    assert plugin._db_get_profile("new") is not None
    assert plugin._db_get_profile("old") is None


def test_episode_suppress_counts_first_n_then_suppresses(tmp_path):
    """Brief: _episode_suppress returns False for first N denies, True thereafter.

    Inputs:
      - tmp_path: pytest temp path for sqlite DB.

    Outputs:
      - None: asserts episode counter increments and suppresses after first_n.
    """

    db = tmp_path / "rl-ep-count.db"
    plugin = RateLimit(db_path=str(db), deny_log_first_n=3)
    plugin.setup()
    key = "test-ep-key"

    # First 3 calls: not suppressed (count <= 3)
    assert plugin._episode_suppress(key) is False  # count=1
    assert plugin._episode_suppress(key) is False  # count=2
    assert plugin._episode_suppress(key) is False  # count=3
    # After 3: suppressed
    assert plugin._episode_suppress(key) is True  # count=4
    assert plugin._episode_suppress(key) is True  # count=5


def test_episode_reset_clears_count(tmp_path):
    """Brief: _episode_reset removes the key so the next episode starts fresh.

    Inputs:
      - tmp_path: pytest temp path for sqlite DB.

    Outputs:
      - None: asserts counter resets and next episode begins with count=1.
    """

    db = tmp_path / "rl-ep-reset.db"
    plugin = RateLimit(db_path=str(db), deny_log_first_n=2)
    plugin.setup()
    key = "test-reset-key"

    # Exhaust the first-N budget.
    plugin._episode_suppress(key)  # count=1 -> False
    plugin._episode_suppress(key)  # count=2 -> False
    assert plugin._episode_suppress(key) is True  # count=3 -> suppressed

    # Reset simulates key dropping below threshold.
    plugin._episode_reset(key)

    # New episode: back to visible for first N.
    assert plugin._episode_suppress(key) is False  # count=1 again
    assert plugin._episode_suppress(key) is False  # count=2
    assert plugin._episode_suppress(key) is True  # count=3 -> suppressed again


def test_deny_log_first_n_zero_suppresses_all(tmp_path):
    """Brief: deny_log_first_n=0 suppresses all query-log rows immediately.

    Inputs:
      - tmp_path: pytest temp path for sqlite DB.

    Outputs:
      - None: asserts suppress is always True when first_n is zero.
    """

    db = tmp_path / "rl-ep-zero.db"
    plugin = RateLimit(db_path=str(db), deny_log_first_n=0)
    plugin.setup()
    key = "any-key"

    for _ in range(5):
        assert plugin._episode_suppress(key) is True


def test_deny_log_first_n_decisions_carry_correct_suppress(tmp_path, monkeypatch):
    """Brief: pre_resolve deny decisions carry suppress_query_log=False for first N.

    Checks that the deny_log_first_n mechanism propagates through
    _build_deny_decision so the resolver can write visible query-log rows
    for the first N denied queries in an episode.

    Inputs:
      - tmp_path: pytest temp path for sqlite DB.
      - monkeypatch: pytest monkeypatch fixture to control time.

    Outputs:
      - None: asserts first 3 denies unsuppressed, subsequent suppressed.
    """

    db = tmp_path / "rl-ep-decisions.db"
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
        # global_max_rps=1.0: current_rps = count/10, so the 11th query in the
        # window gives rps=1.1 > 1.0 and is denied.  Sending 20 gives 9 denies.
        global_max_rps=1.0,
        deny_log_first_n=3,
        deny_response="nxdomain",
    )
    plugin.setup()
    ctx = PluginContext(client_ip="10.0.0.1", listener="tcp")

    _set_time(monkeypatch, 0.0)

    suppress_values: list[bool] = []
    with __import__("contextlib").closing(plugin._conn):
        # Send 20 queries; the first ~10 are allowed, remaining are denied.
        for _ in range(20):
            dec = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
            if dec is not None:
                suppress_values.append(bool(dec.suppress_query_log))

    assert len(suppress_values) >= 4, "Expected at least 4 denied decisions"
    # First 3 denies in the episode must not be suppressed.
    assert suppress_values[0] is False
    assert suppress_values[1] is False
    assert suppress_values[2] is False
    # After the first 3, remaining denies should be suppressed.
    for sv in suppress_values[3:]:
        assert sv is True


def test_deny_episode_resets_on_unblock(tmp_path, monkeypatch):
    """Brief: Episode counter resets when key rate drops below threshold.

    Simulates a host that briefly exceeds the limit, then settles, then
    bursts again.  The second burst should produce another 3 visible
    query-log rows before suppression kicks in again.

    Inputs:
      - tmp_path: pytest temp path for sqlite DB.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts suppress sequence False*3, True+, reset, False*3, True+.
    """

    db = tmp_path / "rl-ep-unblock.db"
    plugin = RateLimit(
        db_path=str(db),
        window_seconds=10,
        warmup_windows=0,
        min_enforce_rps=0.0,
        global_max_rps=1.0,  # 11+ queries/10s window triggers denial
        deny_log_first_n=2,
        deny_response="nxdomain",
    )
    plugin.setup()
    ctx = PluginContext(client_ip="10.0.0.2", listener="tcp")

    with __import__("contextlib").closing(plugin._conn):
        # --- First episode: burst in window 0 ---
        _set_time(monkeypatch, 0.0)
        first_ep: list[bool] = []
        for _ in range(20):
            dec = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
            if dec is not None:
                first_ep.append(bool(dec.suppress_query_log))

        assert len(first_ep) >= 3
        # First 2 unsuppressed, rest suppressed.
        assert first_ep[0] is False
        assert first_ep[1] is False
        for sv in first_ep[2:]:
            assert sv is True

        # --- Rate drops: move to a new window with low traffic ---
        _set_time(monkeypatch, 10.0)
        # A single query that stays under global_max_rps -> returns None
        # and triggers episode reset.
        dec = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
        assert dec is None  # Not limited; episode reset.

        # --- Second episode: burst again in window 2 ---
        _set_time(monkeypatch, 20.0)
        second_ep: list[bool] = []
        for _ in range(20):
            dec = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
            if dec is not None:
                second_ep.append(bool(dec.suppress_query_log))

        assert len(second_ep) >= 3
        # Fresh episode: first 2 unsuppressed again.
        assert second_ep[0] is False
        assert second_ep[1] is False
        for sv in second_ep[2:]:
            assert sv is True
