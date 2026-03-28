"""
Brief: Tests for foghorn.plugins.rate_limit.RateLimit learning and enforcement.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

import builtins
import logging
import threading
from contextlib import closing

import pytest
from dnslib import QTYPE, DNSRecord
from pydantic import ValidationError
from foghorn.plugins.cache.none import NullCache

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


def _clear_rate_limit_caches() -> None:
    """Brief: Clear LRU-cached helper functions used across tests.

    Inputs:
      - None.

    Outputs:
      - None.
    """

    for fn in (
        rate_limit_module._psl_registrable_domain,
        rate_limit_module._to_base_domain,
    ):
        cache_clear = getattr(fn, "cache_clear", None)
        if callable(cache_clear):
            cache_clear()


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


def test_cache_none_falls_back_to_stateful_window_counters(tmp_path, monkeypatch):
    """Brief: RateLimit still enforces when cache backend is NullCache.

    Inputs:
      - tmp_path: temporary directory for sqlite DB.
      - monkeypatch: pytest monkeypatch fixture to pin requests to one window.

    Outputs:
      - None: Asserts NullCache does not disable window/global counter enforcement.
    """

    db = tmp_path / "rl-cache-none-fallback.db"
    plugin = RateLimit(
        db_path=str(db),
        cache=NullCache(),
        bucket_network_prefix_v4=32,
        alpha=0.05,
        alpha_down=0.10,
        burst_factor=10.0,
        max_enforce_rps=20.0,
        bootstrap_rps=40.0,
        global_max_rps=50.0,
        min_enforce_rps=5.0,
        window_seconds=5,
        warmup_windows=4,
        burst_windows=6,
        mode="per_client",
        deny_response="nxdomain",
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4", listener="tcp")

    with closing(plugin._conn):
        backend = getattr(plugin._window_cache, "_backend", None)
        assert not isinstance(backend, NullCache)

        _set_time(monkeypatch, 0.0)
        denied = 0
        total = 1000
        for _ in range(total):
            decision = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
            if decision is not None:
                denied += 1

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
    assert cfg.active_window_max_keys == 2048
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


def test_rate_limit_config_validates_active_window_max_keys_ge_1():
    """Brief: active_window_max_keys must be >= 1.

    Inputs:
      - None

    Outputs:
      - None: asserts ValidationError for invalid values.
    """

    rate_limit_module.RateLimitConfig(active_window_max_keys=1)

    with pytest.raises(ValidationError):
        rate_limit_module.RateLimitConfig(active_window_max_keys=0)


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


def test_psl_helpers_cover_empty_and_import_error_paths(monkeypatch):
    """Brief: PSL helper functions safely handle empty names and import failures.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts safe None/False fallbacks on edge cases.
    """

    _clear_rate_limit_caches()
    monkeypatch.setattr(
        rate_limit_module.dns_names,
        "normalize_name",
        lambda _name: "",
    )
    assert rate_limit_module._psl_registrable_domain("ignored.example") is None

    _clear_rate_limit_caches()
    original_import = builtins.__import__

    def _import_with_publicsuffix_failure(name, *args, **kwargs):
        if name == "publicsuffix2":
            raise ImportError("simulated missing dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(
        builtins,
        "__import__",
        _import_with_publicsuffix_failure,
    )
    assert rate_limit_module._psl_registrable_domain("example.com") is None
    assert rate_limit_module._psl_is_available() is False


def test_prefix_normalization_and_validator_passthrough_branches():
    """Brief: Prefix normalization and config validators cover passthrough paths.

    Inputs:
      - None.

    Outputs:
      - None: asserts slash stripping and non-mapping passthrough behavior.
    """

    assert rate_limit_module._normalize_prefix_length_value("/32") == "32"
    assert rate_limit_module._normalize_prefix_length_value(" 24 ") == "24"
    assert rate_limit_module._normalize_prefix_length_value(24) == 24

    payload = {"other": 1}
    assert rate_limit_module.RateLimitConfig._reject_client_prefix_keys("raw") == "raw"
    assert (
        rate_limit_module.RateLimitConfig._normalize_bucket_network_prefix_v4(payload)
        is payload
    )


def test_rate_limit_config_defaults_bootstrap_to_explicit_global_max():
    """Brief: Explicit global_max_rps drives bootstrap_rps when bootstrap is omitted.

    Inputs:
      - None.

    Outputs:
      - None: asserts bootstrap_rps matches explicit global_max_rps.
    """

    cfg = rate_limit_module.RateLimitConfig(global_max_rps=123.5)
    assert cfg.bootstrap_rps == pytest.approx(123.5)


def test_to_base_domain_falls_back_when_psl_lookup_returns_none(monkeypatch):
    """Brief: Base-domain extraction falls back to last labels without PSL output.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts fallback behavior for multi-label and single-label names.
    """

    _clear_rate_limit_caches()
    monkeypatch.setattr(
        rate_limit_module,
        "_psl_registrable_domain",
        lambda _qname: None,
    )
    assert rate_limit_module._to_base_domain("a.b.example.com.") == "example.com"
    assert rate_limit_module._to_base_domain("localhost.") == "localhost"


def test_setup_raises_when_psl_is_required_but_missing(tmp_path, monkeypatch):
    """Brief: Domain mode with psl_strict=True fails when PSL support is absent.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts setup raises RuntimeError in strict PSL mode.
    """

    monkeypatch.setattr(rate_limit_module, "_psl_is_available", lambda: False)
    plugin = RateLimit(
        db_path=str(tmp_path / "rl-psl-strict.db"),
        mode="per_domain",
        psl_strict=True,
    )
    with pytest.raises(RuntimeError):
        plugin.setup()


def test_bool_parsing_and_last_update_malformed_db_row_branches(tmp_path):
    """Brief: Boolean parsing and malformed last_update conversion branches are safe.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts bool parsing behavior and malformed timestamp fallback.
    """

    plugin = RateLimit(db_path=str(tmp_path / "rl-bool-last-update.db"))
    plugin.setup()

    plugin.config["flag"] = None
    assert plugin._parse_bool_config("flag", True) is True
    plugin.config["flag"] = "yes"
    assert plugin._parse_bool_config("flag", False) is True
    plugin.config["flag"] = "off"
    assert plugin._parse_bool_config("flag", True) is False
    plugin.config["flag"] = "not-bool"
    assert plugin._parse_bool_config("flag", False) is False

    plugin._conn.execute(
        "INSERT OR REPLACE INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) "
        "VALUES (?, ?, ?, ?, ?)",
        ("bad-ts", 1.0, 1.0, 1, "nan-epoch"),
    )
    plugin._conn.commit()
    assert plugin._db_get_profile_last_update("bad-ts") is None


def test_client_bucket_udp_and_window_lock_fallback_branches(tmp_path, monkeypatch):
    """Brief: Client bucketing and UDP-keying helper branches cover fallback paths.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts parse-failure fallbacks and listener-based policy decisions.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-client-bucket.db"),
        bucket_network_prefix_v4=32,
    )
    plugin.setup()

    assert plugin._client_ip_bucket("192.0.2.9") == "192.0.2.9"
    monkeypatch.setattr(rate_limit_module.ip_networks, "parse_ip", lambda _ip: None)
    assert plugin._client_ip_bucket("not-an-ip") == "not-an-ip"

    def _raise_parse(_ip: str):
        raise RuntimeError("parse failure")

    monkeypatch.setattr(rate_limit_module.ip_networks, "parse_ip", _raise_parse)
    assert plugin._client_ip_bucket("198.51.100.4") == "198.51.100.4"

    assert plugin._should_apply_udp_bucketing("tcp", secure=False) is False
    assert plugin._should_apply_udp_bucketing("udp", secure=True) is False
    assert plugin._should_apply_udp_bucketing("weird", secure=True) is False
    assert plugin._should_apply_udp_bucketing("", secure=False) is True
    plugin.assume_udp_when_listener_missing = False
    assert plugin._should_apply_udp_bucketing("", secure=False) is False

    plugin._window_locks = []
    lock = plugin._window_lock_for_key("any-key")
    assert hasattr(lock, "acquire")


def test_current_window_rps_helpers_cover_malformed_stale_and_limit_paths(
    tmp_path,
    monkeypatch,
):
    """Brief: Current-window helpers handle malformed payloads, stale data, and limits.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts stale/malformed counters resolve to safe zero values.
    """

    plugin = RateLimit(db_path=str(tmp_path / "rl-current-rps.db"), window_seconds=10)
    plugin.setup()

    plugin.window_seconds = -1
    assert plugin._get_current_window_rps("key") == 0.0
    assert plugin._get_current_window_rps_snapshot(limit=10) == {}

    plugin.window_seconds = 10
    plugin._window_cache.set(("key", 0), 20, b"bad-payload")
    assert plugin._get_current_window_rps("key") == 0.0

    plugin._window_cache.set(("key", 0), 20, b"0:0")
    assert plugin._get_current_window_rps("key") == 0.0

    monkeypatch.setattr(rate_limit_module.time, "time", lambda: 20.0)
    plugin._window_cache.set(("key", 0), 20, b"0:3")
    assert plugin._get_current_window_rps("key") == 0.0

    plugin._active_window_id = 1
    plugin._active_window_counts = {
        "stale": (1, 2),
        "hot": (2, 5),
        "cool": (2, 3),
    }
    snapshot = plugin._get_current_window_rps_snapshot(limit=1)
    assert snapshot == {"hot": pytest.approx(0.5)}
    assert "stale" not in plugin._active_window_counts

    plugin._active_window_id = 2
    plugin._active_window_counts = {"steady": (2, 2)}
    steady_snapshot = plugin._get_current_window_rps_snapshot(limit=10)
    assert steady_snapshot == {"steady": pytest.approx(0.2)}


def test_active_window_tracking_is_capped_by_active_window_max_keys(tmp_path):
    """Brief: Active-window counters are bounded by active_window_max_keys.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts active-window tracking admits only up to
        active_window_max_keys keys per window while still updating tracked keys.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-active-window-cap.db"),
        window_seconds=10,
        max_profiles=50,
        active_window_max_keys=2,
    )
    plugin.setup()

    assert plugin._active_window_max_keys == 2

    plugin._record_active_window_count("k1", window_id=1, count=1)
    plugin._record_active_window_count("k2", window_id=1, count=1)
    plugin._record_active_window_count("k3", window_id=1, count=1)

    assert set(plugin._active_window_counts.keys()) == {"k1", "k2"}
    assert "k3" not in plugin._active_window_counts
    assert len(plugin._active_window_counts) == 2

    plugin._record_active_window_count("k1", window_id=1, count=5)
    assert plugin._active_window_counts["k1"] == (1, 5)

    plugin.shutdown()


def test_active_window_max_keys_default_and_clamp_paths(tmp_path):
    """Brief: active_window_max_keys defaults safely and clamps to max_profiles.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts the default cap is bounded for large max_profiles and
        explicit over-cap values are clamped to max_profiles.
    """

    default_cap_plugin = RateLimit(
        db_path=str(tmp_path / "rl-active-window-default-cap.db"),
        max_profiles=50000,
    )
    default_cap_plugin.setup()
    assert default_cap_plugin._active_window_max_keys == 2048
    default_cap_plugin.shutdown()

    clamped_plugin = RateLimit(
        db_path=str(tmp_path / "rl-active-window-clamped-cap.db"),
        max_profiles=3,
        active_window_max_keys=999,
    )
    clamped_plugin.setup()
    assert clamped_plugin._active_window_max_keys == 3
    clamped_plugin.shutdown()


def test_burst_counter_helpers_cover_parse_and_reset_paths(tmp_path):
    """Brief: Burst helper branches handle malformed values and reset edge cases.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts no-op, malformed, and reset-window branches.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-burst-branches.db"),
        burst_windows=0,
    )
    plugin.setup()

    plugin._set_burst_count("k", 5)
    plugin._set_burst_reset_count("k", 7)
    assert plugin._window_cache.get(("k", 1)) is None
    assert plugin._window_cache.get(("k", 2)) is None

    plugin.burst_windows = 2
    plugin._window_cache.set(("k", 1), 20, b"bad")
    plugin._window_cache.set(("k", 2), 20, b"bad")
    assert plugin._get_burst_count("k") == 0
    assert plugin._get_burst_reset_count("k") == 0

    plugin._set_burst_count("k", 1)
    plugin.burst_reset_windows = 1
    plugin._advance_burst_reset_counter("k", "not-int")
    assert plugin._get_burst_count("k") == 1
    plugin._advance_burst_reset_counter("k", 1)
    assert plugin._get_burst_count("k") == 0


def test_throttled_deny_log_zero_interval_and_suppression_flush(tmp_path, monkeypatch):
    """Brief: Deny-log throttling covers immediate and suppressed-flush logging paths.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts both direct logging and delayed suppressed-count logging.
    """

    plugin = RateLimit(db_path=str(tmp_path / "rl-throttle-log.db"))
    plugin.setup()

    records: list[tuple[object, tuple[object, ...]]] = []
    monkeypatch.setattr(
        rate_limit_module.logger,
        "info",
        lambda msg, *args: records.append((msg, args)),
    )

    plugin.deny_log_interval_seconds = -1
    plugin._throttled_deny_log("k", "direct %s", "log")
    assert records

    plugin.deny_log_interval_seconds = 5
    times = iter([100.0, 101.0, 107.0])
    monkeypatch.setattr(rate_limit_module.time, "time", lambda: next(times))
    plugin._throttled_deny_log("k2", "burst %s", "event")
    plugin._throttled_deny_log("k2", "burst %s", "event")
    plugin._throttled_deny_log("k2", "burst %s", "event")

    assert any("suppressed %d similar" in str(msg) for msg, _args in records)


def test_throttled_deny_log_prunes_high_cardinality_maps(tmp_path, monkeypatch):
    """Brief: Deny-log throttle maps are pruned under high-cardinality traffic.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts deny-log throttle maps stay bounded by configured limits.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-throttle-prune.db"),
        max_profiles=2,
        deny_log_interval_seconds=60,
    )
    plugin.setup()

    monkeypatch.setattr(
        rate_limit_module.logger,
        "info",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(rate_limit_module.time, "time", lambda: 100.0)

    for i in range(50):
        key = f"key-{i}"
        plugin._throttled_deny_log(key, "deny key=%s", key)
        plugin._throttled_deny_log(key, "deny key=%s", key)

    max_keys = max(int(plugin.max_profiles), 1) * 2
    assert len(plugin._deny_log_ts) <= max_keys
    assert len(plugin._deny_log_suppressed) <= max_keys
    assert set(plugin._deny_log_suppressed).issubset(set(plugin._deny_log_ts))


def test_throttled_deny_log_prunes_stale_suppressed_entries(tmp_path, monkeypatch):
    """Brief: Stale suppressed deny-log entries are pruned without breaking flush.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts stale suppressed keys are evicted while current-key
        suppressed-count flush still appears on next emitted log.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-throttle-stale-prune.db"),
        deny_log_interval_seconds=5,
        max_profiles=100,
    )
    plugin.setup()

    records: list[tuple[object, tuple[object, ...]]] = []
    monkeypatch.setattr(
        rate_limit_module.logger,
        "info",
        lambda msg, *args: records.append((msg, args)),
    )

    times = iter([100.0, 101.0, 102.0, 103.0, 107.0])
    monkeypatch.setattr(rate_limit_module.time, "time", lambda: next(times))

    plugin._throttled_deny_log("keep", "deny key=%s", "keep")
    plugin._throttled_deny_log("keep", "deny key=%s", "keep")
    plugin._throttled_deny_log("stale", "deny key=%s", "stale")
    plugin._throttled_deny_log("stale", "deny key=%s", "stale")
    plugin._throttled_deny_log("keep", "deny key=%s", "keep")

    assert any(
        "suppressed %d similar" in str(msg) and args and args[0] == "keep"
        for msg, args in records
    )
    assert "stale" not in plugin._deny_log_ts
    assert "stale" not in plugin._deny_log_suppressed


def test_build_deny_decision_ede_and_ip_fallback_paths(tmp_path, monkeypatch):
    """Brief: Deny decision building covers EDE attach and IP-mode fallback deny.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts EDE hooks fire and IP mode falls back when no wire exists.
    """

    plugin = RateLimit(db_path=str(tmp_path / "rl-ede.db"), deny_response="refused")
    plugin.setup()

    import foghorn.servers.server as server_mod
    from foghorn.servers.dns_runtime_state import DNSRuntimeState

    calls: dict[str, object] = {}
    monkeypatch.setattr(DNSRuntimeState, "enable_ede", True, raising=False)
    monkeypatch.setattr(
        server_mod,
        "_echo_client_edns",
        lambda _req, _reply: calls.setdefault("echo", True),
        raising=True,
    )
    monkeypatch.setattr(
        server_mod,
        "_attach_ede_option",
        lambda _req, _reply, code, text: calls.setdefault("ede", (code, text)),
        raising=True,
    )

    ctx = PluginContext(client_ip="1.2.3.4", listener="tcp")
    wire = DNSRecord.question("example.com", "A").pack()
    decision = plugin._build_deny_decision("example.com", QTYPE.A, wire, ctx)
    assert decision.action == "override"
    assert calls.get("echo") is True
    assert calls.get("ede") == (17, "Rate-Limited")

    plugin.deny_response = "ip"
    plugin.deny_response_ip4 = "192.0.2.55"
    monkeypatch.setattr(plugin, "_make_a_response", lambda *_args, **_kwargs: None)
    fallback = plugin._build_deny_decision("example.com", QTYPE.A, wire, ctx)
    assert fallback.action == "deny"


def test_pre_resolve_warmup_cap_paths_without_bootstrap_and_during_warmup(
    tmp_path,
    monkeypatch,
):
    """Brief: Warmup-cap enforcement is applied with and without an existing profile.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts both warmup-cap branches emit denies when limits are exceeded.
    """

    ctx = PluginContext(client_ip="9.9.9.9", listener="tcp")
    _set_time(monkeypatch, 0.0)

    plugin_no_profile = RateLimit(
        db_path=str(tmp_path / "rl-warmup-no-profile.db"),
        window_seconds=10,
        warmup_windows=6,
        warmup_max_rps=1.0,
        bootstrap_rps=0.0,
        deny_response="nxdomain",
    )
    plugin_no_profile.setup()

    denied_no_profile = 0
    for _ in range(25):
        decision = plugin_no_profile.pre_resolve("example.com", QTYPE.A, b"", ctx)
        if decision is not None:
            denied_no_profile += 1
    assert denied_no_profile > 0

    plugin_warmup = RateLimit(
        db_path=str(tmp_path / "rl-warmup-profile.db"),
        window_seconds=10,
        warmup_windows=5,
        warmup_max_rps=10.0,
        max_enforce_rps=1.0,
        bootstrap_rps=0.0,
        deny_response="nxdomain",
    )
    plugin_warmup.setup()
    plugin_warmup._seed_profile("9.9.9.9", rps=0.5, now_ts=0, samples=0)

    denied_during_warmup = 0
    for _ in range(25):
        decision = plugin_warmup.pre_resolve("example.com", QTYPE.A, b"", ctx)
        if decision is not None:
            denied_during_warmup += 1
    assert denied_during_warmup > 0


def test_admin_descriptor_snapshot_and_shutdown_branches(tmp_path):
    """Brief: Admin metadata, snapshot stats, and shutdown branches execute cleanly.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts admin outputs and connection cleanup behavior.
    """

    plugin = RateLimit(db_path=str(tmp_path / "rl-admin-shutdown.db"))
    plugin.setup()

    pages = plugin.get_admin_pages()
    descriptor = plugin.get_admin_ui_descriptor()
    snapshot_stats = plugin._get_snapshot_rps_stats()
    assert pages
    assert descriptor.get("name")
    assert set(snapshot_stats.keys()) == {
        "total_avg_rps",
        "total_max_rps",
        "window_avg_rps",
        "window_max_rps",
    }

    plugin.shutdown()
    assert getattr(plugin, "_conn", None) is None


def test_db_apply_zero_windows_covers_validation_and_decay_branches(tmp_path):
    """Brief: Zero-window decay handles invalid inputs and all alpha_down decay regimes.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts no-op/return branches and each decay branch outcome.
    """

    plugin = RateLimit(db_path=str(tmp_path / "rl-zero-windows.db"))
    plugin.setup()

    plugin._seed_profile("keep", rps=10.0, now_ts=0, samples=2)
    plugin.alpha_down = 0.0
    plugin._db_apply_zero_windows("keep", windows="3", now_ts=100)
    avg_keep, _max_keep, samples_keep = plugin._db_get_profile("keep")
    assert avg_keep == pytest.approx(10.0)
    assert samples_keep == 5

    plugin._seed_profile("zero", rps=10.0, now_ts=0, samples=2)
    plugin.alpha_down = 1.0
    plugin._db_apply_zero_windows("zero", windows=2, now_ts=100)
    avg_zero, _max_zero, samples_zero = plugin._db_get_profile("zero")
    assert avg_zero == pytest.approx(0.0)
    assert samples_zero == 4

    plugin._seed_profile("decay", rps=8.0, now_ts=0, samples=2)
    plugin.alpha_down = 0.5
    plugin._db_apply_zero_windows("decay", windows=2, now_ts=100)
    avg_decay, _max_decay, samples_decay = plugin._db_get_profile("decay")
    assert avg_decay == pytest.approx(2.0)
    assert samples_decay == 4

    plugin._db_apply_zero_windows("decay", windows="bad", now_ts=120)
    avg_after_bad, _max_after_bad, samples_after_bad = plugin._db_get_profile("decay")
    assert avg_after_bad == pytest.approx(2.0)
    assert samples_after_bad == 4

    plugin._db_apply_zero_windows("decay", windows=0, now_ts=130)
    avg_after_zero, _max_after_zero, samples_after_zero = plugin._db_get_profile(
        "decay"
    )
    assert avg_after_zero == pytest.approx(2.0)
    assert samples_after_zero == 4


def test_increment_window_handles_missed_window_profile_branches(tmp_path, monkeypatch):
    """Brief: Missed-window handling resets or advances burst state based on profile state.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts missed-window branch decisions across profile variants.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-increment-missed.db"),
        window_seconds=10,
        warmup_windows=2,
        min_enforce_rps=5.0,
    )
    plugin.setup()

    monkeypatch.setattr(plugin, "_record_active_window_count", lambda *args: None)
    monkeypatch.setattr(plugin, "_db_get_profile_last_update", lambda _key: 0)

    def _run_case(key: str, profile):
        calls: list[object] = []
        monkeypatch.setattr(
            plugin,
            "_db_apply_zero_windows",
            lambda *_args, **_kwargs: calls.append("apply"),
        )
        monkeypatch.setattr(plugin, "_db_get_profile", lambda _k: profile)
        monkeypatch.setattr(
            plugin,
            "_reset_burst_state",
            lambda _k: calls.append("reset"),
        )
        monkeypatch.setattr(
            plugin,
            "_advance_burst_reset_counter",
            lambda _k, windows: calls.append(("advance", windows)),
        )
        plugin._increment_window(key, now=50.0)
        return calls

    calls_none = _run_case("case-none", None)
    assert "apply" in calls_none
    assert "reset" in calls_none

    calls_warmup = _run_case("case-warmup", (10.0, 10.0, 1))
    assert "apply" in calls_warmup
    assert "reset" in calls_warmup

    calls_below_min = _run_case("case-below-min", (4.0, 10.0, 10))
    assert "apply" in calls_below_min
    assert "reset" in calls_below_min

    calls_advance = _run_case("case-advance", (10.0, 10.0, 10))
    assert "apply" in calls_advance
    assert ("advance", 4) in calls_advance


def test_flush_completed_active_window_keys_filters_and_updates(tmp_path, monkeypatch):
    """Brief: Active-window flush skips invalid entries and updates valid stale keys.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts only actionable stale entries are persisted.
    """

    plugin = RateLimit(db_path=str(tmp_path / "rl-flush-active.db"), window_seconds=10)
    plugin.setup()

    calls: list[tuple[str, object, object]] = []
    monkeypatch.setattr(
        plugin,
        "_db_update_profile",
        lambda key, rps, _now_ts: calls.append(("update", key, rps)),
    )
    monkeypatch.setattr(
        plugin,
        "_update_burst_counter",
        lambda key, rps: calls.append(("burst", key, rps)),
    )

    plugin._flush_completed_active_window_keys(
        stale_entries=[("", 2), ("skip", 2), ("zero", 0), ("ok", 5)],
        exclude_keys={"skip"},
    )

    assert ("update", "ok", pytest.approx(0.5)) in calls
    assert ("burst", "ok", pytest.approx(0.5)) in calls
    assert not any(call for call in calls if call[1] in {"", "skip", "zero"})


def test_update_burst_counter_covers_reset_advance_and_cap_paths(tmp_path, monkeypatch):
    """Brief: Burst-counter updates reset, advance, and cap count across profile states.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts reset on warmup/below-min and cap behavior on bursts.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-update-burst.db"),
        burst_windows=2,
        warmup_windows=2,
        min_enforce_rps=5.0,
        burst_factor=2.0,
        max_enforce_rps=0.0,
    )
    plugin.setup()

    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(
        plugin,
        "_reset_burst_state",
        lambda _key: calls.append(("reset", None)),
    )
    monkeypatch.setattr(
        plugin,
        "_advance_burst_reset_counter",
        lambda _key, windows: calls.append(("advance", windows)),
    )
    monkeypatch.setattr(
        plugin,
        "_set_burst_count",
        lambda _key, count: calls.append(("set_count", count)),
    )
    monkeypatch.setattr(
        plugin,
        "_set_burst_reset_count",
        lambda _key, count: calls.append(("set_reset", count)),
    )

    monkeypatch.setattr(plugin, "_db_get_profile", lambda _key: (10.0, 10.0, 1))
    plugin._update_burst_counter("k", rps=30.0)
    assert ("reset", None) in calls

    calls.clear()
    monkeypatch.setattr(plugin, "_db_get_profile", lambda _key: (4.0, 10.0, 10))
    plugin._update_burst_counter("k", rps=30.0)
    assert ("reset", None) in calls

    calls.clear()
    monkeypatch.setattr(plugin, "_db_get_profile", lambda _key: (10.0, 10.0, 10))
    plugin._update_burst_counter("k", rps=10.0)
    assert ("advance", 1) in calls

    calls.clear()
    monkeypatch.setattr(plugin, "_get_burst_count", lambda _key: 5)
    plugin._update_burst_counter("k", rps=30.0)
    assert ("set_count", 2) in calls
    assert ("set_reset", 0) in calls


def test_maybe_log_stats_handles_disabled_interval_and_empty_probe_retry(tmp_path):
    """Brief: Stats logging returns early when disabled and applies retry offset on empty probes.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts disabled-cadence and empty-stats retry behavior.
    """

    plugin_disabled = RateLimit(
        db_path=str(tmp_path / "rl-stats-disabled.db"),
        stats_log_interval_seconds=0,
        stats_window_seconds=0,
    )
    plugin_disabled.setup()
    plugin_disabled._last_stats_log_ts = 123.0
    plugin_disabled._maybe_log_stats(now=200.0)
    assert plugin_disabled._last_stats_log_ts == pytest.approx(123.0)

    plugin_retry = RateLimit(
        db_path=str(tmp_path / "rl-stats-retry.db"),
        stats_log_interval_seconds=60,
        stats_window_seconds=0,
        window_seconds=10,
    )
    plugin_retry.setup()
    del plugin_retry._stats_log_lock
    plugin_retry._last_stats_log_ts = 0.0
    plugin_retry._maybe_log_stats(now=100.0)
    assert plugin_retry._last_stats_log_ts == pytest.approx(50.0)


def test_snapshot_stats_window_query_and_shutdown_no_conn_path(tmp_path, monkeypatch):
    """Brief: Snapshot stats cover window-query success/fallback and repeated shutdown.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts snapshot behavior with/without window table and closed DB.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-snapshot-window.db"),
        stats_window_seconds=60,
    )
    plugin.setup()
    plugin._db_update_profile("k1", 5.0, now_ts=100)
    plugin._db_update_profile("k1", 7.0, now_ts=150)

    monkeypatch.setattr(rate_limit_module.time, "time", lambda: 200.0)
    stats = plugin._get_snapshot_rps_stats()
    assert stats["total_avg_rps"] > 0.0
    assert stats["window_avg_rps"] > 0.0

    plugin._conn.execute("DROP TABLE rate_profile_windows")
    plugin._conn.commit()
    stats_after_drop = plugin._get_snapshot_rps_stats()
    assert stats_after_drop["window_avg_rps"] == 0.0
    assert stats_after_drop["window_max_rps"] == 0.0

    plugin.shutdown()
    plugin.shutdown()
    assert plugin._get_snapshot_rps_stats() == {
        "total_avg_rps": 0.0,
        "total_max_rps": 0.0,
        "window_avg_rps": 0.0,
        "window_max_rps": 0.0,
    }


def test_psl_registrable_domain_handles_empty_get_sld_result(monkeypatch):
    """Brief: PSL helper returns None when get_sld yields an empty result.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts empty get_sld output is treated as unavailable.
    """

    _clear_rate_limit_caches()
    original_import = builtins.__import__

    class _PublicSuffixModule:
        """Brief: Minimal module shim exposing get_sld for import interception.

        Inputs:
          - name: normalized fqdn.

        Outputs:
          - str: empty string to trigger the falsy get_sld branch.
        """

        @staticmethod
        def get_sld(_name: str) -> str:
            return ""

    def _import_with_empty_sld(name, *args, **kwargs):
        if name == "publicsuffix2":
            return _PublicSuffixModule
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _import_with_empty_sld)
    assert rate_limit_module._psl_registrable_domain("a.example.com") is None


def test_rate_limit_config_validator_non_mapping_and_explicit_bootstrap_branches():
    """Brief: Config validators cover non-mapping passthrough and explicit bootstrap preservation.

    Inputs:
      - None.

    Outputs:
      - None: asserts non-mapping passthrough and explicit bootstrap precedence.
    """

    payload = ["not-a-mapping"]
    assert (
        rate_limit_module.RateLimitConfig._normalize_bucket_network_prefix_v4(payload)
        is payload
    )

    cfg = rate_limit_module.RateLimitConfig(global_max_rps=123.0, bootstrap_rps=7.0)
    assert cfg.bootstrap_rps == pytest.approx(7.0)


def test_setup_without_db_directory_and_udp_listener_keying_branch(monkeypatch):
    """Brief: setup() and _make_key cover no-dir db_path, IPv6 bucketing, and listener-present UDP path.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts setup works with db_path lacking a directory and UDP keying branch is used.
    """

    plugin = RateLimit(
        db_path=":memory:",
        bucket_network_prefix_v6=64,
    )
    plugin.setup()

    assert plugin._client_ip_bucket("2001:db8::1234").endswith("/64")

    monkeypatch.setattr(plugin, "_client_ip_bucket", lambda _ip: "2001:db8::/64")
    key = plugin._make_key(
        "example.com",
        PluginContext(client_ip="2001:db8::1234", listener="udp"),
    )
    assert key == "2001:db8::/64"
    plugin.shutdown()


def test_increment_and_active_window_rollover_uncovered_branches(tmp_path, monkeypatch):
    """Brief: Window increment/rollover logic covers zero-count rollover and stale mismatch filtering.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts zero-count rollover skips profile writes and stale mismatches do not flush.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-increment-extra-branches.db"),
        window_seconds=10,
    )
    plugin.setup()

    plugin._window_cache.set(("k", 0), 20, b"0:0")
    window_id, count = plugin._increment_window("k", now=10.0)
    assert (window_id, count) == (1, 1)
    assert plugin._db_get_profile("k") is None

    captured_stale_entries: list[list[tuple[str, int]]] = []
    monkeypatch.setattr(
        plugin,
        "_flush_completed_active_window_keys",
        lambda *, stale_entries, exclude_keys: captured_stale_entries.append(
            list(stale_entries)
        ),
    )
    plugin._active_window_id = 3
    plugin._active_window_counts = {"mismatch": (5, 2)}
    plugin._record_active_window_count("new", window_id=4, count=1)
    assert captured_stale_entries == [[]]

    # Call the real method directly to exercise the empty stale_entries early-return branch.
    RateLimit._flush_completed_active_window_keys(
        plugin,
        stale_entries=[],
        exclude_keys=set(),
    )
    plugin.shutdown()


def test_burst_and_recalc_helper_uncovered_branches(tmp_path, monkeypatch):
    """Brief: Burst/recalc helpers cover remaining no-op and cache-clear paths.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts helper early-returns and cache-bounding branch behavior.
    """

    plugin = RateLimit(
        db_path=str(tmp_path / "rl-burst-recalc-extra.db"),
        burst_windows=0,
        window_seconds=10,
    )
    plugin.setup()

    assert plugin._get_burst_count("missing-key") == 0
    assert plugin._get_burst_reset_count("missing-key") == 0
    plugin._advance_burst_reset_counter("k", 1)

    plugin.burst_windows = 2
    plugin._advance_burst_reset_counter("k", 0)

    plugin.burst_windows = 0
    plugin._update_burst_counter("k", rps=1.0)

    plugin.burst_windows = 2
    monkeypatch.setattr(plugin, "_db_get_profile", lambda _k: None)
    plugin._update_burst_counter("k", rps=1.0)

    plugin.window_seconds = -1
    assert plugin._maybe_recalculate_all_bucket_limits(now=1.0) == 0

    plugin.window_seconds = 10
    monkeypatch.setattr(rate_limit_module.time, "time", lambda: 123.0)
    monkeypatch.setattr(plugin, "_maybe_recalculate_all_bucket_limits", lambda _now: 0)
    plugin.max_profiles = 1
    plugin._cached_bucket_limits = {
        "a": (0, 1.0, 1.0),
        "b": (0, 1.0, 1.0),
        "c": (0, 1.0, 1.0),
    }
    plugin._get_recalculated_allowed_rps(
        key="new",
        avg_rps=2.0,
        samples=1,
    )
    assert plugin._cached_bucket_limits == {}
    plugin.shutdown()


def test_pre_resolve_uncovered_warmup_and_burst_selection_paths(tmp_path, monkeypatch):
    """Brief: pre_resolve covers warmup fallback and burst-selection branches not previously exercised.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts no-profile warmup/no-cap and burst-selection branches return safely.
    """

    _set_time(monkeypatch, 0.0)
    ctx = PluginContext(client_ip="10.10.10.10", listener="tcp")

    plugin_no_warmup_cap = RateLimit(
        db_path=str(tmp_path / "rl-no-warmup-cap.db"),
        warmup_windows=5,
        warmup_max_rps=0.0,
        bootstrap_rps=0.0,
        max_enforce_rps=0.0,
    )
    plugin_no_warmup_cap.setup()
    assert plugin_no_warmup_cap.pre_resolve("example.com", QTYPE.A, b"", ctx) is None

    plugin_warmup_cap_no_max = RateLimit(
        db_path=str(tmp_path / "rl-warmup-cap-no-max.db"),
        warmup_windows=5,
        warmup_max_rps=10.0,
        bootstrap_rps=0.0,
        max_enforce_rps=0.0,
    )
    plugin_warmup_cap_no_max.setup()
    assert (
        plugin_warmup_cap_no_max.pre_resolve("example.com", QTYPE.A, b"", ctx) is None
    )

    plugin_profile_warmup = RateLimit(
        db_path=str(tmp_path / "rl-profile-warmup.db"),
        warmup_windows=5,
        warmup_max_rps=10.0,
        bootstrap_rps=0.0,
        max_enforce_rps=0.0,
    )
    plugin_profile_warmup.setup()
    plugin_profile_warmup._seed_profile("10.10.10.10", rps=1.0, now_ts=0, samples=0)
    assert plugin_profile_warmup.pre_resolve("example.com", QTYPE.A, b"", ctx) is None

    plugin_no_burst = RateLimit(
        db_path=str(tmp_path / "rl-no-burst.db"),
        warmup_windows=0,
        min_enforce_rps=0.0,
        burst_windows=0,
        bootstrap_rps=5.0,
    )
    plugin_no_burst.setup()
    assert plugin_no_burst.pre_resolve("example.com", QTYPE.A, b"", ctx) is None

    plugin_burst_exhausted = RateLimit(
        db_path=str(tmp_path / "rl-burst-exhausted.db"),
        warmup_windows=0,
        min_enforce_rps=0.0,
        burst_windows=2,
        bootstrap_rps=5.0,
    )
    plugin_burst_exhausted.setup()
    monkeypatch.setattr(plugin_burst_exhausted, "_get_burst_count", lambda _k: 2)
    assert plugin_burst_exhausted.pre_resolve("example.com", QTYPE.A, b"", ctx) is None

    for plugin in (
        plugin_no_warmup_cap,
        plugin_warmup_cap_no_max,
        plugin_profile_warmup,
        plugin_no_burst,
        plugin_burst_exhausted,
    ):
        plugin.shutdown()


def test_build_deny_decision_unknown_mode_falls_back_to_simple_deny(tmp_path):
    """Brief: Unexpected deny_response values fall back to a simple deny decision.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts unsupported mode reaches the fallback deny branch.
    """

    plugin = RateLimit(db_path=str(tmp_path / "rl-deny-fallback.db"))
    plugin.setup()
    plugin.deny_response = "unexpected-mode"

    decision = plugin._build_deny_decision(
        "example.com",
        QTYPE.A,
        b"",
        PluginContext(client_ip="1.2.3.4", listener="tcp"),
    )
    assert decision.action == "deny"
    plugin.shutdown()


def test_setup_warns_when_limit_precedence_is_conflicting(
    tmp_path,
    caplog,
):
    """Brief: setup() logs warnings when stricter limits will trigger earlier.

    Inputs:
      - tmp_path: pytest temp path for sqlite db.
      - caplog: pytest logging capture fixture.

    Outputs:
      - None: asserts startup warnings are emitted for conflicting thresholds.
    """

    db = tmp_path / "rl-precedence-warn.db"
    plugin = RateLimit(
        db_path=str(db),
        warmup_max_rps=100.0,
        max_enforce_rps=10.0,
        bootstrap_rps=20.0,
        burst_factor=3.0,
        min_enforce_rps=50.0,
        global_max_rps=5.0,
    )
    with caplog.at_level(logging.WARNING):
        plugin.setup()

    text = caplog.text
    assert "warmup_max_rps=100.00 exceeds max_enforce_rps=10.00" in text
    assert "bootstrap threshold 60.00" in text
    assert "max_enforce_rps=10.00 is below min_enforce_rps=50.00" in text
    assert "global_max_rps=5.00 is below warmup_max_rps=100.00" in text
    assert "global_max_rps=5.00 is below max_enforce_rps=10.00" in text
    plugin.shutdown()


def test_setup_no_precedence_warnings_for_non_conflicting_limits(
    tmp_path,
    caplog,
):
    """Brief: setup() does not emit precedence warnings for aligned thresholds.

    Inputs:
      - tmp_path: pytest temp path for sqlite db.
      - caplog: pytest logging capture fixture.

    Outputs:
      - None: asserts precedence warning text is absent.
    """

    db = tmp_path / "rl-precedence-clean.db"
    plugin = RateLimit(
        db_path=str(db),
        warmup_max_rps=10.0,
        max_enforce_rps=100.0,
        bootstrap_rps=10.0,
        burst_factor=2.0,
        min_enforce_rps=5.0,
        global_max_rps=1000.0,
    )
    with caplog.at_level(logging.WARNING):
        plugin.setup()

    text = caplog.text
    assert "warmup_max_rps=" not in text
    assert "bootstrap threshold" not in text
    assert "global_max_rps=" not in text
    assert "hard-cap enforcement may trigger" not in text
    plugin.shutdown()
