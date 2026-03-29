"""Brief: Branch-focused tests for foghorn.servers.webserver.rate_limit_helpers.

Inputs:
  - Temporary sqlite files and monkeypatched plugin/runtime helpers.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

import os
import sqlite3
import time

import pytest

import foghorn.servers.webserver as web_mod
from foghorn.servers.webserver import rate_limit_helpers as helpers


def _reset_rate_limit_cache() -> None:
    """Brief: Reset webserver rate-limit snapshot cache for deterministic tests.

    Inputs:
      - None.

    Outputs:
      - None.
    """

    with web_mod._RATE_LIMIT_CACHE_LOCK:
        web_mod._last_rate_limit_snapshot = None
        web_mod._last_rate_limit_snapshot_ts = 0.0


def test_rate_limit_effective_config_and_coercion_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Profile resolution and scalar coercion helpers cover fallback and bounds.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts profile resolve success/fallback and non-negative coercion behavior.
    """

    entry = {
        "config": {"profile": "high", "abort_on_failure": 1, "db_path": "/tmp/x.db"}
    }

    captured: dict[str, object] = {}

    def _fake_resolve(**kwargs):  # noqa: ANN003
        captured.update(kwargs)
        return {"db_path": "/tmp/resolved.db"}

    monkeypatch.setattr(helpers, "resolve_plugin_profile", _fake_resolve)
    resolved = helpers._resolve_rate_limit_effective_config(entry)
    assert resolved == {"db_path": "/tmp/resolved.db"}
    assert captured["plugin_type"] == "rate_limit"
    assert captured["profile_name"] == "high"
    assert captured["abort_on_failure"] is True

    monkeypatch.setattr(
        helpers,
        "resolve_plugin_profile",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),  # noqa: ARG005
    )
    fallback = helpers._resolve_rate_limit_effective_config(entry)
    assert fallback["profile"] == "high"
    assert fallback["db_path"] == "/tmp/x.db"

    assert helpers._resolve_rate_limit_effective_config({"config": "not-a-dict"}) == {}
    assert helpers._coerce_nonnegative_int("5") == 5
    assert helpers._coerce_nonnegative_int("-2") == 0
    assert helpers._coerce_nonnegative_int("bad", default=7) == 7
    assert helpers._coerce_nonnegative_float("5.5") == 5.5
    assert helpers._coerce_nonnegative_float("-1.0") == 0.0
    assert helpers._coerce_nonnegative_float("bad", default=2.5) == 2.5


def test_rate_limit_config_extractors_for_lookback_and_limit_settings() -> None:
    """Brief: Config extractors handle mixed plugin entries and normalization rules.

    Inputs:
      - None.

    Outputs:
      - Asserts lookback and limit settings extraction for rate_limit entries only.
    """

    cfg = {
        "plugins": [
            {
                "module": "rate_limit",
                "config": {
                    "db_path": "/tmp/a.db",
                    "stats_window_seconds": 30,
                    "stats_log_interval_seconds": 10,
                    "warmup_windows": 4,
                    "warmup_max_rps": 15.0,
                    "burst_factor": 0.2,
                    "burst_windows": 3,
                    "min_enforce_rps": 5.0,
                    "max_enforce_rps": 100.0,
                    "global_max_rps": 9.0,
                    "limit_recalc_windows": 8,
                },
            },
            {
                "module": "rate_limit",
                "db_path": "/tmp/b.db",
                "config": {
                    "stats_window_seconds": -5,
                    "stats_log_interval_seconds": 40,
                },
            },
            {"module": "other", "config": {"db_path": "/tmp/ignored.db"}},
            "not-a-dict",
        ]
    }

    lookbacks = helpers._find_rate_limit_db_lookback_seconds_from_config(cfg)
    assert lookbacks["/tmp/a.db"] == 30
    assert lookbacks["/tmp/b.db"] == 40
    assert "/tmp/ignored.db" not in lookbacks

    settings = helpers._find_rate_limit_db_limit_settings_from_config(cfg)
    assert settings["/tmp/a.db"]["warmup_windows"] == 4
    assert settings["/tmp/a.db"]["burst_factor"] == 1.0
    assert settings["/tmp/a.db"]["global_max_rps"] == 9.0
    assert settings["/tmp/b.db"]["warmup_windows"] == 6
    assert settings["/tmp/b.db"]["max_enforce_rps"] == 5000.0


def test_compute_current_limit_rps_branch_matrix() -> None:
    """Brief: _compute_current_limit_rps covers global, warmup, below-min, and burst paths.

    Inputs:
      - None.

    Outputs:
      - Asserts representative source labels and enforcement decisions.
    """

    assert helpers._compute_current_limit_rps(
        avg_rps=0.0,
        samples=0,
        current_rps=1.0,
        limit_settings={"global_max_rps": 0.0},
        profile_key="global",
    ) == (None, "global_disabled", None, False)

    global_enabled = helpers._compute_current_limit_rps(
        avg_rps=0.0,
        samples=0,
        current_rps=7.0,
        limit_settings={"global_max_rps": 5.0},
        profile_key="global",
    )
    assert global_enabled == (5.0, "global_max_rps", None, True)

    warmup_learning = helpers._compute_current_limit_rps(
        avg_rps=2.0,
        samples=1,
        current_rps=1.0,
        limit_settings={"warmup_windows": 5, "warmup_max_rps": 0.0},
    )
    assert warmup_learning[1] == "warmup_learning"
    assert warmup_learning[0] is None

    warmup_enforced = helpers._compute_current_limit_rps(
        avg_rps=2.0,
        samples=1,
        current_rps=21.0,
        limit_settings={
            "warmup_windows": 5,
            "warmup_max_rps": 30.0,
            "max_enforce_rps": 20.0,
        },
    )
    assert warmup_enforced[0] == 20.0
    assert warmup_enforced[1] == "warmup_max_rps"
    assert warmup_enforced[3] is True

    below_min_no_cap = helpers._compute_current_limit_rps(
        avg_rps=4.0,
        samples=10,
        current_rps=10.0,
        limit_settings={"min_enforce_rps": 5.0, "max_enforce_rps": 0.0},
    )
    assert below_min_no_cap == (None, "below_min_enforce_rps", 12.0, False)

    below_min_with_cap = helpers._compute_current_limit_rps(
        avg_rps=4.0,
        samples=10,
        current_rps=60.0,
        limit_settings={"min_enforce_rps": 5.0, "max_enforce_rps": 50.0},
    )
    assert below_min_with_cap[1] == "below_min_enforce_rps"
    assert below_min_with_cap[3] is True

    burst_mode = helpers._compute_current_limit_rps(
        avg_rps=100.0,
        samples=12,
        current_rps=150.0,
        limit_settings={
            "min_enforce_rps": 10.0,
            "burst_factor": 2.0,
            "burst_windows": 3,
            "max_enforce_rps": 1000.0,
        },
        burst_count=1,
        recalculated_thresholds=(140.0, 90.0),
    )
    assert burst_mode[0] == 140.0
    assert burst_mode[1] == "burst_threshold"
    assert burst_mode[3] is True

    baseline_mode = helpers._compute_current_limit_rps(
        avg_rps=100.0,
        samples=12,
        current_rps=95.0,
        limit_settings={
            "min_enforce_rps": 10.0,
            "burst_factor": 2.0,
            "burst_windows": 3,
            "max_enforce_rps": 1000.0,
        },
        burst_count=3,
        recalculated_thresholds=("bad", "bad"),
    )
    assert baseline_mode[1] == "baseline_after_burst_windows"
    assert baseline_mode[0] == 100.0


@pytest.mark.parametrize(
    ("finder_name", "reader_name"),
    [
        ("_find_rate_limit_current_rps_readers", "_get_current_window_rps"),
        (
            "_find_rate_limit_recalculated_allowed_rps_readers",
            "_get_recalculated_allowed_rps",
        ),
        (
            "_find_rate_limit_current_rps_snapshot_readers",
            "_get_current_window_rps_snapshot",
        ),
        ("_find_rate_limit_burst_count_readers", "_get_burst_count"),
    ],
)
def test_rate_limit_reader_discovery_helpers(
    finder_name: str,
    reader_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Reader discovery helpers include raw/absolute db_path and tolerate failures.

    Inputs:
      - finder_name: Helper function name under test.
      - reader_name: Reader method name expected on plugin object.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts mapping behavior for valid, invalid, and abspath-failure inputs.
    """

    class _Plugin:
        def __init__(self, db_path: str) -> None:
            self.db_path = db_path

    plugin = _Plugin("relative/rate_limit.db")
    plugin_empty = _Plugin("")
    setattr(plugin, reader_name, lambda *args, **kwargs: 0.0)
    setattr(plugin_empty, reader_name, lambda *args, **kwargs: 0.0)

    finder = getattr(helpers, finder_name)
    found = finder([None, plugin_empty, plugin, object()])
    assert "relative/rate_limit.db" in found
    assert os.path.abspath("relative/rate_limit.db") in found

    monkeypatch.setattr(
        helpers.os.path,
        "abspath",
        lambda _p: (_ for _ in ()).throw(RuntimeError("abspath-fail")),
    )
    found_with_error = finder([plugin])
    assert found_with_error == {
        "relative/rate_limit.db": found["relative/rate_limit.db"]
    }
    assert finder(None) == {}


def test_collect_rate_limit_stats_handles_live_readers_and_snapshot_only_profiles(
    tmp_path,
) -> None:
    """Brief: _collect_rate_limit_stats merges sqlite profiles with live plugin readers.

    Inputs:
      - tmp_path: pytest temp directory for sqlite DB.

    Outputs:
      - Asserts global de-duplication, lookback usage, and snapshot-only key inclusion.
    """

    db_path = tmp_path / "rate_limit.db"
    now = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        conn.execute(
            "CREATE TABLE rate_profile_windows (key TEXT, rps REAL, last_update INTEGER)"
        )
        conn.executemany(
            "INSERT INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) VALUES (?, ?, ?, ?, ?)",
            [
                ("global", 10.0, 120.0, 200, now),
                ("__global__", 90.0, 110.0, 5, now),
                ("client1", 40.0, 60.0, 12, now),
                ("client2", "bad", "bad", "bad", "bad"),
            ],
        )
        conn.executemany(
            "INSERT INTO rate_profile_windows (key, rps, last_update) VALUES (?, ?, ?)",
            [
                ("client1", 50.0, now),
                ("client1", 30.0, now),
            ],
        )
        conn.commit()

    class _RatePlugin:
        def __init__(self, db_path_value: str) -> None:
            self.db_path = db_path_value

        def _get_current_window_rps(self, key: str) -> float:
            if key == "client2":
                raise RuntimeError("reader-fail")
            return {"global": 130.0, "client1": 45.0}.get(key, 0.0)

        def _get_current_window_rps_snapshot(self) -> dict[str, object]:
            return {"global": 3.0, "new-key": "7.5", "": 999}

        def _get_burst_count(self, key: str) -> int:
            if key == "client2":
                raise RuntimeError("burst-fail")
            return 1

        def _get_recalculated_allowed_rps(
            self,
            key: str,
            avg_rps: float,
            samples: int,
        ) -> object:
            if key == "client1":
                return (avg_rps * 2.0, avg_rps)
            if key == "new-key":
                return "invalid"
            raise RuntimeError("recalc-fail")

    relative_db_path = os.path.relpath(str(db_path), start="/home/zack/work/foghorn")
    plugin = _RatePlugin(relative_db_path)

    _reset_rate_limit_cache()
    cfg = {
        "plugins": [
            {
                "module": "rate_limit",
                "config": {
                    "db_path": str(db_path),
                    "stats_window_seconds": 60,
                    "min_enforce_rps": 10.0,
                    "max_enforce_rps": 200.0,
                    "burst_factor": 2.0,
                    "burst_windows": 3,
                },
            }
        ]
    }
    data = helpers._collect_rate_limit_stats(cfg, plugins=[plugin])
    assert len(data["databases"]) == 1
    summary = data["databases"][0]
    assert summary["db_path"] == str(db_path)
    assert summary["lookback_seconds"] == 60

    profiles_by_key = {row["key"]: row for row in summary["profiles"]}
    assert "global" in profiles_by_key
    assert "new-key" in profiles_by_key
    assert profiles_by_key["global"]["samples"] == 200
    assert profiles_by_key["new-key"]["samples"] == 0
    assert profiles_by_key["new-key"]["current_rps"] == 7.5
    assert summary["total_profiles"] >= 3


def test_collect_rate_limit_stats_with_empty_db_and_live_snapshot_key(tmp_path) -> None:
    """Brief: _collect_rate_limit_stats emits snapshot-only profile rows when sqlite has none.

    Inputs:
      - tmp_path: pytest temp directory for sqlite DB.

    Outputs:
      - Asserts profiles are created from live snapshot payload.
    """

    db_path = tmp_path / "rate_limit_empty.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        conn.commit()

    class _RatePlugin:
        def __init__(self, db_path_value: str) -> None:
            self.db_path = db_path_value

        def _get_current_window_rps_snapshot(self) -> dict[str, float]:
            return {"fresh-key": 5.0}

    relative_db_path = os.path.relpath(str(db_path), start="/home/zack/work/foghorn")
    plugin = _RatePlugin(relative_db_path)

    _reset_rate_limit_cache()
    cfg = {
        "plugins": [
            {
                "module": "rate_limit",
                "config": {"db_path": str(db_path)},
            }
        ]
    }
    data = helpers._collect_rate_limit_stats(cfg, plugins=[plugin])
    assert len(data["databases"]) == 1
    summary = data["databases"][0]
    assert summary["total_profiles"] == 1
    assert summary["profiles"][0]["key"] == "fresh-key"
    assert summary["profiles"][0]["samples"] == 0


def test_rate_limit_config_extractors_handle_invalid_inputs_and_missing_db_path() -> (
    None
):
    """Brief: Config extractors return empty output for invalid shapes and skip empty db_path.

    Inputs:
      - None.

    Outputs:
      - Asserts robust empty/skip behavior.
    """

    assert helpers._find_rate_limit_db_lookback_seconds_from_config(None) == {}
    assert (
        helpers._find_rate_limit_db_lookback_seconds_from_config(
            {"plugins": "not-a-list"}
        )
        == {}
    )
    assert helpers._find_rate_limit_db_limit_settings_from_config(None) == {}
    assert (
        helpers._find_rate_limit_db_limit_settings_from_config(
            {"plugins": "not-a-list"}
        )
        == {}
    )

    cfg = {
        "plugins": [
            {"module": "rate_limit", "config": {"db_path": ""}},
            {"module": "rate_limit", "config": {"db_path": None}},
            {"module": "rate_limit", "config": {}},
        ]
    }
    assert helpers._find_rate_limit_db_lookback_seconds_from_config(cfg) == {}
    assert helpers._find_rate_limit_db_limit_settings_from_config(cfg) == {}


def test_compute_current_limit_rps_additional_fallback_paths() -> None:
    """Brief: _compute_current_limit_rps covers recalculated-fallback and no-burst-counter paths.

    Inputs:
      - None.

    Outputs:
      - Asserts source/limit behavior for additional branch combinations.
    """

    warmup_without_clamp = helpers._compute_current_limit_rps(
        avg_rps=2.0,
        samples=1,
        current_rps=5.0,
        limit_settings={
            "warmup_windows": 5,
            "warmup_max_rps": 7.0,
            "max_enforce_rps": 0.0,
        },
    )
    assert warmup_without_clamp[0] == 7.0
    assert warmup_without_clamp[1] == "warmup_max_rps"

    burst_no_recalc = helpers._compute_current_limit_rps(
        avg_rps=50.0,
        samples=20,
        current_rps=60.0,
        limit_settings={
            "min_enforce_rps": 10.0,
            "burst_factor": 2.0,
            "burst_windows": 5,
            "max_enforce_rps": 0.0,
        },
        burst_count=None,
        recalculated_thresholds=None,
    )
    assert burst_no_recalc[0] == 100.0
    assert burst_no_recalc[1] == "burst_threshold"


def test_collect_rate_limit_stats_handles_reader_fallback_exceptions(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _collect_rate_limit_stats tolerates abspath fallback failures for missing readers.

    Inputs:
      - tmp_path: pytest temp directory for sqlite DB.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts stats collection still succeeds with empty reader maps.
    """

    db_path = tmp_path / "reader_fallback.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        conn.execute(
            "INSERT INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) VALUES (?, ?, ?, ?, ?)",
            ("client", 5.0, 10.0, 2, int(time.time())),
        )
        conn.commit()

    _reset_rate_limit_cache()
    cfg = {
        "plugins": [
            {
                "module": "rate_limit",
                "config": {"db_path": str(db_path)},
            }
        ]
    }
    monkeypatch.setattr(
        helpers.os.path,
        "abspath",
        lambda _p: (_ for _ in ()).throw(RuntimeError("abspath-fail")),
    )
    data = helpers._collect_rate_limit_stats(cfg, plugins=None)
    assert len(data["databases"]) == 1
    assert data["databases"][0]["total_profiles"] == 1


def test_collect_rate_limit_stats_snapshot_only_reader_exceptions_and_limit_tracking(
    tmp_path,
) -> None:
    """Brief: Snapshot-only profile path handles reader exceptions and tracks current-limit maxima.

    Inputs:
      - tmp_path: pytest temp directory for sqlite DB.

    Outputs:
      - Asserts snapshot-only profile creation with warmup-derived current limit.
    """

    db_path = tmp_path / "snapshot_only_limit.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        conn.commit()

    class _Plugin:
        def __init__(self, db_path_value: str) -> None:
            self.db_path = db_path_value

        def _get_current_window_rps_snapshot(self) -> dict[str, float]:
            return {"snap-only": 12.0}

        def _get_burst_count(self, key: str) -> int:  # noqa: ARG002
            raise RuntimeError("burst-read-fail")

        def _get_recalculated_allowed_rps(
            self, key: str, avg_rps: float, samples: int
        ) -> object:  # noqa: ARG002
            raise RuntimeError("recalc-read-fail")

    relative_db_path = os.path.relpath(str(db_path), start="/home/zack/work/foghorn")
    plugin = _Plugin(relative_db_path)

    _reset_rate_limit_cache()
    cfg = {
        "plugins": [
            {
                "module": "rate_limit",
                "config": {
                    "db_path": str(db_path),
                    "warmup_windows": 5,
                    "warmup_max_rps": 10.0,
                },
            }
        ]
    }
    data = helpers._collect_rate_limit_stats(cfg, plugins=[plugin])
    summary = data["databases"][0]
    assert summary["total_profiles"] == 1
    assert summary["max_current_limit_rps"] == 10.0
    assert summary["profiles"][0]["key"] == "snap-only"


def test_collect_rate_limit_stats_snapshot_reader_exception_and_non_dict_additional(
    tmp_path,
) -> None:
    """Brief: Snapshot reader exception and non-dict payload paths are tolerated.

    Inputs:
      - tmp_path: pytest temp directory for sqlite DB.

    Outputs:
      - Asserts collection succeeds for both snapshot-reader edge cases.
    """

    db_path = tmp_path / "snapshot_edge.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        conn.execute(
            "INSERT INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) VALUES (?, ?, ?, ?, ?)",
            ("client", 5.0, 10.0, 2, int(time.time())),
        )
        conn.commit()

    class _RaisePlugin:
        def __init__(self, db_path_value: str) -> None:
            self.db_path = db_path_value

        def _get_current_window_rps_snapshot(self) -> dict[str, float]:
            raise RuntimeError("snapshot-fail")

    class _ListPlugin:
        def __init__(self, db_path_value: str) -> None:
            self.db_path = db_path_value

        def _get_current_window_rps_snapshot(self) -> list[float]:
            return [1.0]

    relative_db_path = os.path.relpath(str(db_path), start="/home/zack/work/foghorn")
    cfg = {"plugins": [{"module": "rate_limit", "config": {"db_path": str(db_path)}}]}

    _reset_rate_limit_cache()
    data_raise = helpers._collect_rate_limit_stats(
        cfg, plugins=[_RaisePlugin(relative_db_path)]
    )
    assert len(data_raise["databases"]) == 1
    assert data_raise["databases"][0]["total_profiles"] == 1

    _reset_rate_limit_cache()
    data_list = helpers._collect_rate_limit_stats(
        cfg, plugins=[_ListPlugin(relative_db_path)]
    )
    assert len(data_list["databases"]) == 1
    assert data_list["databases"][0]["total_profiles"] == 1


def test_collect_rate_limit_stats_appends_fallback_global_row_additional(
    tmp_path,
) -> None:
    """Brief: Global fallback query row is appended when top-200 profile query excludes global keys.

    Inputs:
      - tmp_path: pytest temp directory for sqlite DB.

    Outputs:
      - Asserts global profile appears via fallback append logic.
    """

    db_path = tmp_path / "global_fallback.db"
    now = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        rows = [
            (f"client-{idx:03d}", float(1000 - idx), float(1000 - idx), 5, now)
            for idx in range(205)
        ]
        rows.append(("__global__", 0.001, 0.001, 1, now))
        conn.executemany(
            "INSERT INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()

    _reset_rate_limit_cache()
    cfg = {"plugins": [{"module": "rate_limit", "config": {"db_path": str(db_path)}}]}
    data = helpers._collect_rate_limit_stats(cfg, plugins=None)
    summary = data["databases"][0]
    keys = {row["key"] for row in summary["profiles"]}
    assert "global" in keys


def test_collect_rate_limit_stats_window_conversion_and_query_error_paths_additional(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Window-summary conversion errors and query failures are handled safely.

    Inputs:
      - tmp_path: pytest temp directory for sqlite path placeholder.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts _collect_rate_limit_stats succeeds across both defensive window paths.
    """

    fake_path = tmp_path / "fake_windows.db"
    fake_path.write_text("")
    cfg = {
        "plugins": [
            {
                "module": "rate_limit",
                "config": {"db_path": str(fake_path), "stats_window_seconds": 60},
            }
        ]
    }

    class _FakeCursor:
        def __init__(self, mode: str) -> None:
            self.mode = mode
            self._last_sql = ""

        def execute(self, sql: str, params=None):  # noqa: ANN001
            self._last_sql = sql
            if self.mode == "window-query-error" and "rate_profile_windows" in sql:
                raise RuntimeError("window-query-fail")
            return self

        def fetchall(self):  # noqa: ANN201
            if "FROM rate_profiles ORDER BY" in self._last_sql:
                return [("client", 5.0, 10.0, 2, int(time.time()))]
            if "FROM rate_profile_windows" in self._last_sql:
                if self.mode == "window-bad-values":
                    return [("client", object(), object())]
                return []
            return []

        def fetchone(self):  # noqa: ANN201
            return None

    class _FakeConn:
        def __init__(self, mode: str) -> None:
            self.mode = mode

        def __enter__(self) -> "_FakeConn":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
            return False

        def cursor(self) -> _FakeCursor:
            return _FakeCursor(self.mode)

    _reset_rate_limit_cache()
    monkeypatch.setattr(
        helpers.sqlite3, "connect", lambda _path: _FakeConn("window-bad-values")
    )
    data_bad = helpers._collect_rate_limit_stats(cfg, plugins=None)
    assert len(data_bad["databases"]) == 1
    assert data_bad["databases"][0]["total_profiles"] == 1

    _reset_rate_limit_cache()
    monkeypatch.setattr(
        helpers.sqlite3,
        "connect",
        lambda _path: _FakeConn("window-query-error"),
    )
    data_error = helpers._collect_rate_limit_stats(cfg, plugins=None)
    assert len(data_error["databases"]) == 1
    assert data_error["databases"][0]["total_profiles"] == 1


def test_collect_rate_limit_stats_row_and_snapshot_recalculated_threshold_paths_additional(
    tmp_path,
) -> None:
    """Brief: Recalculated-threshold tuple validation covers invalid row values and valid snapshot values.

    Inputs:
      - tmp_path: pytest temp directory for sqlite DB.

    Outputs:
      - Asserts row invalid-threshold fallback and snapshot valid-threshold path both execute.
    """

    db_path = tmp_path / "recalc_paths.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        conn.execute(
            "INSERT INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) VALUES (?, ?, ?, ?, ?)",
            ("client", 25.0, 30.0, 10, int(time.time())),
        )
        conn.commit()

    class _Plugin:
        def __init__(self, db_path_value: str) -> None:
            self.db_path = db_path_value

        def _get_current_window_rps(self, key: str) -> float:  # noqa: ARG002
            return 12.0

        def _get_current_window_rps_snapshot(self) -> dict[str, float]:
            return {"snapshot-only": 9.0}

        def _get_burst_count(self, key: str) -> int:  # noqa: ARG002
            return 0

        def _get_recalculated_allowed_rps(
            self,
            key: str,
            avg_rps: float,
            samples: int,
        ) -> object:  # noqa: ARG002
            if key == "client":
                return "invalid"
            return (11.0, 7.0)

    relative_db_path = os.path.relpath(str(db_path), start="/home/zack/work/foghorn")
    plugin = _Plugin(relative_db_path)
    cfg = {
        "plugins": [
            {
                "module": "rate_limit",
                "config": {
                    "db_path": str(db_path),
                    "min_enforce_rps": 1.0,
                    "warmup_windows": 0,
                },
            }
        ]
    }

    _reset_rate_limit_cache()
    data = helpers._collect_rate_limit_stats(cfg, plugins=[plugin])
    summary = data["databases"][0]
    assert summary["total_profiles"] >= 2
    keys = {row["key"] for row in summary["profiles"]}
    assert "client" in keys
    assert "snapshot-only" in keys


def test_collect_rate_limit_stats_snapshot_only_global_key_burst_none_branch_additional(
    tmp_path,
) -> None:
    """Brief: Snapshot-only global key path handles burst_threshold_rps=None without max update.

    Inputs:
      - tmp_path: pytest temp directory for sqlite DB.

    Outputs:
      - Asserts global snapshot profile is emitted even when burst threshold is None.
    """

    db_path = tmp_path / "snapshot_global_only.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        conn.commit()

    class _Plugin:
        def __init__(self, db_path_value: str) -> None:
            self.db_path = db_path_value

        def _get_current_window_rps_snapshot(self) -> dict[str, float]:
            return {"__global__": 8.0}

    relative_db_path = os.path.relpath(str(db_path), start="/home/zack/work/foghorn")
    plugin = _Plugin(relative_db_path)
    cfg = {
        "plugins": [
            {
                "module": "rate_limit",
                "config": {
                    "db_path": str(db_path),
                    "global_max_rps": 5.0,
                },
            }
        ]
    }

    _reset_rate_limit_cache()
    data = helpers._collect_rate_limit_stats(cfg, plugins=[plugin])
    summary = data["databases"][0]
    assert summary["total_profiles"] == 1
    assert summary["profiles"][0]["key"] == "global"
