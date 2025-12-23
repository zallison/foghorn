import types

import pytest
from fastapi.testclient import TestClient

import foghorn.servers.webserver as web_mod
from foghorn.servers.webserver import RingBuffer, RuntimeState, create_app


def test_thread_is_alive_handles_is_running_exception() -> None:
    """Brief: _thread_is_alive returns False when is_running raises.

    Inputs:
      - Object exposing is_running() that raises.

    Outputs:
      - Returns False.
    """

    class BoomRunning:
        def is_running(self) -> bool:
            raise RuntimeError("boom")

    assert web_mod._thread_is_alive(BoomRunning()) is False
    # No is_alive/is_running -> fall through to final return False.
    assert web_mod._thread_is_alive(object()) is False


def test_get_package_build_info_pep610_commit_id_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _get_package_build_info should read commit_id when no env override exists.

    Inputs:
      - Monkeypatched distribution().read_text('direct_url.json') with vcs_info.commit_id.

    Outputs:
      - info['git_sha'] is populated from commit_id.
    """

    # Newer implementations of _get_package_build_info may not be wrapped in
    # functools.lru_cache; guard cache_clear() so the test stays compatible with
    # both cached and non-cached designs.
    cache_clear = getattr(web_mod._get_package_build_info, "cache_clear", None)
    if callable(cache_clear):  # pragma: no cover - compatibility path
        cache_clear()

    monkeypatch.delenv("FOGHORN_GIT_SHA", raising=False)
    monkeypatch.delenv("GIT_SHA", raising=False)

    direct_url = '{"url": "https://example.invalid/repo.git", "vcs_info": {"commit_id": "pep610-sha", "requested_revision": "main"}}'

    class DummyDist:
        def read_text(self, name: str) -> str | None:
            return direct_url if name == "direct_url.json" else None

    monkeypatch.setattr(
        web_mod.importlib_metadata, "distribution", lambda _n: DummyDist()
    )

    info = web_mod._get_package_build_info()
    assert info["git_sha"] == "pep610-sha"


def test_expected_listeners_from_config_handles_non_mapping_listen() -> None:
    """Brief: _expected_listeners_from_config tolerates listen being non-dict.

    Inputs:
      - Config with listen set to a non-dict value.

    Outputs:
      - Defaults (udp enabled, others disabled) are used.
    """

    out = web_mod._expected_listeners_from_config({"listen": "not-a-dict"})
    assert out["udp"] is True
    assert out["tcp"] is False


def test_get_web_cfg_and_redact_keys_defensive_paths() -> None:
    """Brief: _get_web_cfg/_get_redact_keys handle non-dict config and scalar redact_keys.

    Inputs:
      - config=None
      - webserver.redact_keys set to a scalar string

    Outputs:
      - _get_web_cfg returns {}
      - _get_redact_keys returns a list[str]
    """

    assert web_mod._get_web_cfg(None) == {}
    keys = web_mod._get_redact_keys({"webserver": {"redact_keys": "token"}})
    assert keys == ["token"]


def test_trim_top_fields_limit_default_and_scalar_dict_values() -> None:
    """Brief: _trim_top_fields defaults limit to 10 and preserves scalar dict values.

    Inputs:
      - payload with list and dict-of-list and dict-of-scalar values.
      - limit=0 to trigger default.

    Outputs:
      - Lists are trimmed to 10.
      - Scalar values in nested dict are preserved.
    """

    payload = {
        "top_clients": list(range(20)),
        "latency": {"p50": 1.0, "values": list(range(20))},
    }

    web_mod._trim_top_fields(payload, 0, ["top_clients", "latency"])
    assert payload["top_clients"] == list(range(10))
    assert payload["latency"]["p50"] == 1.0
    assert payload["latency"]["values"] == list(range(10))


def test_build_stats_payload_includes_dnssec_when_present() -> None:
    """Brief: _build_stats_payload_from_snapshot includes dnssec block when present.

    Inputs:
      - Dummy snapshot object with dnssec_totals set.

    Outputs:
      - Returned payload contains 'dnssec'.
    """

    snap = types.SimpleNamespace(
        created_at="t",
        totals={},
        rcodes={},
        qtypes={},
        uniques={},
        upstreams={},
        top_clients=[],
        top_subdomains=[],
        top_domains=[],
        latency_stats={},
        latency_recent_stats={},
        upstream_rcodes={},
        upstream_qtypes={},
        qtype_qnames={},
        rcode_domains={},
        rcode_subdomains={},
        cache_hit_domains={},
        cache_miss_domains={},
        cache_hit_subdomains={},
        cache_miss_subdomains={},
        rate_limit=None,
        dnssec_totals={"validated": 1},
    )

    payload = web_mod._build_stats_payload_from_snapshot(
        snap, meta={"hostname": "x"}, system_info={}
    )
    assert payload["dnssec"] == {"validated": 1}


def test_build_traffic_payload_top_defaults_to_10() -> None:
    """Brief: _build_traffic_payload_from_snapshot defaults top to 10 when non-positive.

    Inputs:
      - Dummy snapshot with >10 entries.

    Outputs:
      - top lists are limited to 10.
    """

    snap = types.SimpleNamespace(
        created_at="t",
        totals={},
        rcodes={},
        qtypes={},
        top_clients=list(range(50)),
        top_domains=list(range(50)),
        latency_stats={},
    )

    payload = web_mod._build_traffic_payload_from_snapshot(snap, meta=None, top=0)
    assert len(payload["top_clients"]) == 10
    assert len(payload["top_domains"]) == 10


def test_ts_to_utc_iso_exception_falls_back_to_epoch() -> None:
    """Brief: _ts_to_utc_iso uses epoch when conversion fails.

    Inputs:
      - ts='bad'

    Outputs:
      - Returned string contains "1970".
    """

    out = web_mod._ts_to_utc_iso("bad")  # type: ignore[arg-type]
    assert "1970" in out


def test_parse_utc_datetime_empty_and_non_iso_and_tzaware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _parse_utc_datetime rejects empty and parses non-ISO/tz-aware formats.

    Inputs:
      - empty string
      - space-separated datetime
      - ISO with explicit offset

    Outputs:
      - empty raises ValueError
      - parsed datetimes are UTC-aware.
    """

    with pytest.raises(ValueError):
        web_mod._parse_utc_datetime("")

    # Force the fallback strptime path by making fromisoformat raise.
    real_datetime = web_mod.datetime

    class ShimDateTime:
        @staticmethod
        def fromisoformat(_s: str):  # noqa: ANN001
            raise ValueError("force fallback")

        @staticmethod
        def strptime(s: str, fmt: str):  # noqa: ANN001
            return real_datetime.strptime(s, fmt)

    monkeypatch.setattr(web_mod, "datetime", ShimDateTime)
    dt1 = web_mod._parse_utc_datetime("2025-12-10 01:02:03")
    assert dt1.tzinfo is not None
    monkeypatch.setattr(web_mod, "datetime", real_datetime)

    dt2 = web_mod._parse_utc_datetime("2025-12-10T01:02:03+01:00")
    assert dt2.tzinfo is not None


def test_redact_yaml_preserving_layout_redacts_nested_block_keys() -> None:
    """Brief: Layout-preserving YAML redaction should redact keys nested under a redacted block.

    Inputs:
      - YAML with a sensitive parent key (auth) and nested children.

    Outputs:
      - Child keys under auth are redacted.
    """

    raw_yaml = (
        "auth:\n"
        "  token: secret-token  # c1\n"
        "  nested:\n"
        "    password: secret-password\n"
        "note: keep\n"
    )

    out = web_mod._redact_yaml_text_preserving_layout(raw_yaml, ["auth"])
    assert "token: ***" in out
    assert "password: ***" in out
    assert "secret-token" not in out
    assert "secret-password" not in out
    assert "note: keep" in out


def test_collect_rate_limit_stats_cache_hit_and_missing_db_path(tmp_path) -> None:
    """Brief: _collect_rate_limit_stats returns cached payload and skips missing DB paths.

    Inputs:
      - Module cache pre-populated.
      - Config pointing at a non-existent sqlite3 path.

    Outputs:
      - Cache hit returns the cached payload.
      - Missing DB path results in an empty databases list.
    """

    # Cache-hit path.
    with web_mod._RATE_LIMIT_CACHE_LOCK:
        web_mod._last_rate_limit_snapshot = {"databases": [{"db_path": "x"}]}
        web_mod._last_rate_limit_snapshot_ts = web_mod.time.time()

    cached = web_mod._collect_rate_limit_stats({"plugins": []})
    assert cached["databases"][0]["db_path"] == "x"

    # Reset cache and verify missing DB path is skipped.
    with web_mod._RATE_LIMIT_CACHE_LOCK:
        web_mod._last_rate_limit_snapshot = None
        web_mod._last_rate_limit_snapshot_ts = 0.0

    missing = tmp_path / "missing.db"
    cfg = {
        "plugins": [
            {"module": "rate_limit", "config": {"db_path": str(missing)}},
        ]
    }

    data = web_mod._collect_rate_limit_stats(cfg)
    assert data["databases"] == []


def test_query_log_endpoints_disabled_when_no_store() -> None:
    """Brief: Query-log endpoints return disabled when no store is attached.

    Inputs:
      - App created with stats=None.

    Outputs:
      - /api/v1/query_log and /api/v1/query_log/aggregate return status=disabled.
    """

    cfg = {"webserver": {"enabled": True}}
    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())

    client = TestClient(app)

    resp1 = client.get("/api/v1/query_log")
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "disabled"

    resp2 = client.get(
        "/api/v1/query_log/aggregate",
        params={
            "interval": 15,
            "interval_units": "minutes",
            "start": "2025-12-10 01:00:00",
            "end": "2025-12-10 02:00:00",
        },
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "disabled"


def test_upstream_status_more_defensive_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Exercise additional defensive branches in /api/v1/upstream_status.

    Inputs:
      - App with upstreams configured as non-list and list containing invalid entries.
      - Monkeypatched upstream_max_concurrent and health with bad values.

    Outputs:
      - Endpoint returns a payload without raising.
    """

    import asyncio

    cfg = {"webserver": {"enabled": True}, "upstreams": "not-a-list"}
    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())

    # Use a truthy negative value so the "or 1" doesn't short-circuit to 1.
    monkeypatch.setattr(
        web_mod.DNSUDPHandler, "upstream_max_concurrent", -1, raising=False
    )
    monkeypatch.setattr(
        web_mod.DNSUDPHandler,
        "upstream_health",
        {"health-only": {"fail_count": "bad", "down_until": "bad"}},
        raising=False,
    )

    route = next(
        r
        for r in app.router.routes
        if getattr(r, "path", None) == "/api/v1/upstream_status"
    )

    async def run() -> None:
        body1 = await route.endpoint()  # type: ignore[func-returns-value]
        assert body1["max_concurrent"] == 1

        # Now switch config to include invalid upstream entries.
        app.state.config = {
            "webserver": {"enabled": True},
            "upstreams": [
                "not-a-dict",
                {},
                {"host": "1.1.1.1", "port": 53, "transport": "udp"},
            ],
        }
        body2 = await route.endpoint()  # type: ignore[func-returns-value]
        assert "items" in body2

    asyncio.run(run())


def test_threaded_runtime_state_mark_startup_complete() -> None:
    """Brief: RuntimeState.mark_startup_complete flips startup_complete in snapshot.

    Inputs:
      - RuntimeState with startup_complete=False.

    Outputs:
      - snapshot()['startup_complete'] becomes True after mark_startup_complete().
    """

    state = RuntimeState(startup_complete=False)
    assert state.snapshot()["startup_complete"] is False
    state.mark_startup_complete()
    assert state.snapshot()["startup_complete"] is True
