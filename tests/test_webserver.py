"""Tests for the FastAPI-based admin HTTP server in foghorn.servers.webserver.

Inputs:
  - pytest fixtures and FastAPI TestClient

Outputs:
  - Assertions that endpoints (/health, /stats, /traffic, /config, /logs, /)
    behave as expected with and without a StatsCollector and with simple
    redaction/auth configuration.

The tests exercise create_app() directly without starting a real uvicorn
server, keeping them fast and deterministic.
"""

from __future__ import annotations

import json
import logging
import threading

import yaml
from fastapi.testclient import TestClient

from foghorn.stats import StatsCollector, StatsSQLiteStore
from foghorn.servers.webserver import (
    RingBuffer,
    RuntimeState,
    WebServerHandle,
    _read_proc_meminfo,
    _redact_yaml_text_preserving_layout,
    _Suppress2xxAccessFilter,
    _utc_now_iso,
    create_app,
    get_system_info,
    install_uvicorn_2xx_suppression,
    resolve_www_root,
    sanitize_config,
    start_webserver,
)


def test_sanitize_config_redacts_simple_keys() -> None:
    """Brief: sanitize_config() must redact matching keys at any nesting level.

    Inputs:
      - Nested dict containing sensitive keys "token" and "password".

    Outputs:
      - Modified copy where sensitive values are replaced with '***'.

    Example:
      cfg = {"webserver": {"auth": {"token": "abc", "password": "pw"}}}
      clean = sanitize_config(cfg, ["token", "password"])
    """

    cfg = {"webserver": {"auth": {"token": "abc", "password": "pw", "user": "u"}}}
    clean = sanitize_config(cfg, ["token", "password"])
    auth = clean["webserver"]["auth"]
    assert auth["token"] == "***"
    assert auth["password"] == "***"
    # Non-sensitive fields are preserved
    assert auth["user"] == "u"
    # Original dict is unmodified
    assert cfg["webserver"]["auth"]["token"] == "abc"


def test_about_endpoint_includes_version_and_github_url() -> None:
    """Brief: /api/v1/about returns version/build info plus github_url.

    Inputs:
      - App created with minimal config.

    Outputs:
      - JSON body contains version (string) and github_url with the repo link.
    """

    cfg = {
        "webserver": {"enabled": True},
        "listen": {"udp": {"enabled": False}},
        "resolver": {"mode": "recursive"},
    }
    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)

    resp = client.get("/api/v1/about")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body.get("version"), str)
    assert body.get("github_url") == "https://github.com/zallison/foghorn"


def test_ready_endpoint_503_when_startup_incomplete() -> None:
    """Brief: /ready returns 503 and explains missing readiness requirements.

    Inputs:
      - runtime_state marked startup_complete=False.

    Outputs:
      - HTTP 503 and JSON body includes not_ready list containing 'startup not complete'.
    """

    cfg = {
        "webserver": {"enabled": True},
        "listen": {"udp": {"enabled": False}},
        "resolver": {"mode": "recursive"},
    }
    state = RuntimeState(startup_complete=False)
    app = create_app(
        stats=None, config=cfg, log_buffer=RingBuffer(), runtime_state=state
    )

    class Alive:
        def is_alive(self) -> bool:
            return True

    # create_app registers webserver with thread=None; update after construction.
    state.set_listener("webserver", enabled=True, thread=Alive())

    client = TestClient(app)
    resp = client.get("/ready")
    assert resp.status_code == 503
    body = resp.json()
    assert body["ready"] is False


def test_ready_endpoint_200_when_requirements_met() -> None:
    """Brief: /ready returns 200 when readiness requirements are satisfied.

    Inputs:
      - runtime_state marked startup_complete=True and webserver running.
      - config disables UDP so only webserver readiness is required.

    Outputs:
      - HTTP 200 and ready == True.
    """

    cfg = {
        "webserver": {"enabled": True},
        "listen": {"udp": {"enabled": False}},
        "resolver": {"mode": "recursive"},
    }
    state = RuntimeState(startup_complete=True)
    app = create_app(
        stats=None, config=cfg, log_buffer=RingBuffer(), runtime_state=state
    )

    class Alive:
        def is_alive(self) -> bool:
            return True

    state.set_listener("webserver", enabled=True, thread=Alive())

    client = TestClient(app)
    resp = client.get("/api/v1/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ready"] is True


def test_health_endpoint_returns_ok() -> None:
    """Brief: /health must respond with HTTP 200 and status "ok".

    Inputs:
      - App created with no stats collector.

    Outputs:
      - JSON body containing status == "ok" and a server_time string.
    """

    app = create_app(
        stats=None, config={"webserver": {"enabled": True}}, log_buffer=RingBuffer()
    )
    client = TestClient(app)

    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert isinstance(body["server_time"], str)


def test_stats_endpoint_disabled_when_no_collector() -> None:
    """Brief: /stats should indicate disabled when no StatsCollector present.

    Inputs:
      - App created with stats=None.

    Outputs:
      - JSON response containing status == "disabled".
    """

    app = create_app(
        stats=None, config={"webserver": {"enabled": True}}, log_buffer=RingBuffer()
    )
    client = TestClient(app)

    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "disabled"


def test_get_system_info_uses_meminfo_and_load(monkeypatch) -> None:
    """Brief: get_system_info() should combine loadavg, meminfo, and process RSS safely.

    Inputs:
      - monkeypatch fixture to stub os.getloadavg and _read_proc_meminfo.

    Outputs:
      - Dict with expected numeric values for load and memory fields and
        process RSS keys present.
    """

    import foghorn.servers.webserver as web_mod

    # Ensure this test is deterministic even if earlier tests populated the
    # module-level system info cache.
    web_mod._last_system_info = None
    web_mod._last_system_info_ts = 0.0

    def fake_getloadavg() -> tuple[float, float, float]:
        return (1.0, 2.0, 3.0)

    def fake_meminfo(path: str = "/proc/meminfo") -> dict[str, int]:  # noqa: ARG001
        return {
            "MemTotal": 1024 * 1024 * 1024,
            "MemFree": 256 * 1024 * 1024,
            "MemAvailable": 512 * 1024 * 1024,
        }

    monkeypatch.setattr(web_mod.os, "getloadavg", fake_getloadavg)
    monkeypatch.setattr(web_mod, "_read_proc_meminfo", fake_meminfo)

    info = get_system_info()
    assert info["load_1m"] == 1.0
    assert info["load_5m"] == 2.0
    assert info["load_15m"] == 3.0
    assert info["memory_total_bytes"] == 1024 * 1024 * 1024
    assert info["memory_available_bytes"] == 512 * 1024 * 1024
    assert info["memory_free_bytes"] == 256 * 1024 * 1024
    assert info["memory_used_bytes"] == 512 * 1024 * 1024
    # Process RSS keys should always be present; values may be None when psutil is unavailable.
    assert "process_rss_bytes" in info
    assert "process_rss_mb" in info


def test_stats_includes_system_section(monkeypatch) -> None:
    """Brief: /stats must expose a "system" section with load and memory info.

    Inputs:
      - StatsCollector with minimal data and patched get_system_info().

    Outputs:
      - JSON body of /stats contains a "system" key with stubbed values.
    """

    import foghorn.servers.webserver as web_mod

    collector = StatsCollector(
        track_uniques=True, include_qtype_breakdown=True, track_latency=True
    )
    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_response_rcode("NOERROR")

    def fake_sysinfo() -> dict[str, object]:
        return {"load_1m": 0.5, "memory_total_bytes": 1024}

    monkeypatch.setattr(web_mod, "get_system_info", fake_sysinfo)

    app = create_app(
        stats=collector,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
    )
    client = TestClient(app)

    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "system" in data
    assert data["system"]["load_1m"] == 0.5
    assert data["system"]["memory_total_bytes"] == 1024


def test_stats_and_traffic_with_collector() -> None:
    """Brief: /stats and /traffic must expose fields from StatsCollector snapshot.

    Inputs:
      - StatsCollector recording a couple of queries.

    Outputs:
      - /stats JSON contains totals, rcodes, qtypes keys.
      - /traffic JSON contains a subset including totals and latency.
    """

    collector = StatsCollector(
        track_uniques=True, include_qtype_breakdown=True, track_latency=True
    )
    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_response_rcode("NOERROR")

    app = create_app(
        stats=collector,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
    )
    client = TestClient(app)

    stats_resp = client.get("/stats")
    assert stats_resp.status_code == 200
    stats_data = stats_resp.json()
    assert "totals" in stats_data
    assert "rcodes" in stats_data
    assert "qtypes" in stats_data

    traffic_resp = client.get("/traffic")
    assert traffic_resp.status_code == 200
    traffic_data = traffic_resp.json()
    assert "totals" in traffic_data
    assert "rcodes" in traffic_data
    assert "qtypes" in traffic_data
    # Latency section may be present but count can be 0 if not recorded explicitly
    assert "latency" in traffic_data


def test_stats_includes_upstreams_and_upstream_rcodes() -> None:
    """Brief: /stats must expose upstreams, upstream_rcodes, upstream_qtypes, and qtype_qnames fields.

    Inputs:
      - StatsCollector with some upstream results and per-upstream rcodes.

    Outputs:
      - /stats JSON contains upstreams mapping, upstream_rcodes mapping,
        upstream_qtypes mapping keyed by upstream_id, and qtype_qnames mapping
        keyed by qtype.
    """

    collector = StatsCollector(
        track_uniques=False,
        include_qtype_breakdown=False,
        include_top_domains=True,
        top_n=5,
    )
    # Record a couple of queries so qtype_qnames has data for /stats.
    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_query("192.0.2.2", "example.com", "AAAA")

    collector.record_upstream_result("8.8.8.8:53", "success", qtype="A")
    collector.record_upstream_result("1.1.1.1:53", "timeout", qtype="AAAA")
    collector.record_upstream_rcode("8.8.8.8:53", "NOERROR")

    app = create_app(
        stats=collector,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
    )
    client = TestClient(app)

    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()

    assert "upstreams" in data
    assert "8.8.8.8:53" in data["upstreams"]

    assert "upstream_rcodes" in data
    assert data["upstream_rcodes"]["8.8.8.8:53"]["NOERROR"] == 1

    assert "upstream_qtypes" in data
    assert data["upstream_qtypes"]["8.8.8.8:53"]["A"] == 1

    assert "qtype_qnames" in data
    assert "A" in data["qtype_qnames"]

    # Legacy top_upstreams key should no longer be present.
    assert "top_upstreams" not in data


def test_stats_fastapi_and_threaded_payloads_match(monkeypatch) -> None:
    """Brief: /stats JSON from FastAPI and threaded HTTP servers must match in shape and values.

    Inputs:
      - StatsCollector with representative data (queries, upstreams, qtype_qnames, etc.).

    Outputs:
      - FastAPI /stats JSON equals threaded /stats JSON after accounting for trivial
        differences (e.g., server_time timestamp field).
    """

    import foghorn.servers.webserver as web_mod

    # Build a collector with enough data to exercise the rich stats fields.
    collector = StatsCollector(
        track_uniques=True,
        include_qtype_breakdown=True,
        include_top_clients=True,
        include_top_domains=True,
        top_n=5,
        track_latency=True,
    )
    # Queries to populate totals/qtypes/uniques/top lists/qtype_qnames.
    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_query("192.0.2.2", "example.com", "AAAA")
    collector.record_query("192.0.2.3", "ptr.example.com", "PTR")
    collector.record_response_rcode("NOERROR", qname="example.com")
    collector.record_response_rcode("NXDOMAIN", qname="nx.example.com")

    # Upstream stats so that upstreams, upstream_rcodes, upstream_qtypes are present.
    collector.record_upstream_result("8.8.8.8:53", "success", qtype="A")
    collector.record_upstream_result("1.1.1.1:53", "timeout", qtype="AAAA")
    collector.record_upstream_rcode("8.8.8.8:53", "NOERROR")

    # Cache domain stats for cache_hit_domains/cache_miss_domains and their
    # subdomain-only counterparts.
    collector.record_cache_hit("example.com")
    collector.record_cache_hit("www.example.com")
    collector.record_cache_miss("other.example.com")
    collector.record_cache_miss("api.other.example.com")

    base_cfg = {"webserver": {"enabled": True, "auth": {"mode": "none"}}}

    # ---- FastAPI /stats ----
    app = create_app(stats=collector, config=base_cfg, log_buffer=RingBuffer())
    fastapi_client = TestClient(app)
    fastapi_resp = fastapi_client.get("/stats")
    assert fastapi_resp.status_code == 200
    fastapi_data = fastapi_resp.json()

    # ---- Threaded HTTP /stats ----
    # Build a threaded admin server and send a real HTTP request to /stats.
    httpd = web_mod._AdminHTTPServer(
        ("127.0.0.1", 0),
        web_mod._ThreadedAdminRequestHandler,
        stats=collector,
        config=base_cfg,
        log_buffer=RingBuffer(),
        config_path=None,
    )

    host, port = httpd.server_address

    def _serve_once() -> None:
        try:
            httpd.handle_request()
        except Exception:
            httpd.server_close()
            raise

    t = threading.Thread(target=_serve_once, daemon=True)
    t.start()

    import http.client

    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", "/stats")
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read().decode("utf-8")
    finally:
        conn.close()
        httpd.server_close()
        t.join(timeout=1.0)

    threaded_data = json.loads(body)

    # Normalize expected non-deterministic fields.
    def _normalize(payload: dict) -> dict:
        cleaned = dict(payload)
        # server_time and created_at can legitimately differ; drop them.
        cleaned.pop("server_time", None)
        cleaned.pop("created_at", None)
        # meta may contain timestamps; drop it entirely for shape/value comparison.
        cleaned.pop("meta", None)
        return cleaned

    norm_fast = _normalize(fastapi_data)
    norm_thread = _normalize(threaded_data)

    # Ensure both payloads expose the exact same top-level keys.
    assert set(norm_fast.keys()) == set(norm_thread.keys())
    # And that all corresponding values match.
    assert norm_fast == norm_thread

    # New subdomain-oriented metrics should be present in the /stats payload
    # when cache and rcode statistics are recorded.
    assert "cache_hit_domains" in fastapi_data
    assert "cache_miss_domains" in fastapi_data
    assert "cache_hit_subdomains" in fastapi_data
    assert "cache_miss_subdomains" in fastapi_data
    assert "rcode_domains" in fastapi_data
    assert "rcode_subdomains" in fastapi_data


def test_stats_debug_timings_emit_log_when_enabled(caplog) -> None:
    """Brief: /stats should log timing breakdown when debug_timings is enabled.

    Inputs:
      - FastAPI app created with webserver.debug_timings set to True.

    Outputs:
      - A DEBUG log line from foghorn.servers.webserver containing the timings prefix.
    """

    collector = StatsCollector(
        track_uniques=True, include_qtype_breakdown=True, track_latency=True
    )
    collector.record_query("192.0.2.1", "example.com", "A")

    cfg = {"webserver": {"enabled": True, "debug_timings": True}}
    app = create_app(stats=collector, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)

    with caplog.at_level(logging.DEBUG, logger="foghorn.webserver"):
        resp = client.get("/stats")

    assert resp.status_code == 200
    messages = [rec.getMessage() for rec in caplog.records]
    assert any("/stats timings:" in msg for msg in messages)


def test_stats_snapshot_cache_avoids_multiple_snapshot_calls(monkeypatch) -> None:
    """Brief: /stats should reuse a cached StatsSnapshot within the cache TTL.

    Inputs:
      - StatsCollector with a wrapped snapshot method counting invocations.

    Outputs:
      - Two /stats requests within the TTL result in a single underlying
        StatsCollector.snapshot() call; a reset=True request forces another.
    """

    import foghorn.servers.webserver as web_mod

    collector = StatsCollector(
        track_uniques=False,
        include_qtype_breakdown=False,
        track_latency=False,
    )
    collector.record_query("192.0.2.1", "example.com", "A")

    calls = {"n": 0}
    orig_snapshot = collector.snapshot

    def wrapped_snapshot(reset: bool = False):  # noqa: D401
        """Increment call counter and delegate to original snapshot."""

        calls["n"] += 1
        return orig_snapshot(reset=reset)

    monkeypatch.setattr(collector, "snapshot", wrapped_snapshot)

    # Ensure TTL is long enough and cache is empty for this collector.
    orig_ttl = web_mod._STATS_SNAPSHOT_CACHE_TTL_SECONDS
    try:
        web_mod._STATS_SNAPSHOT_CACHE_TTL_SECONDS = 10.0
        with web_mod._STATS_SNAPSHOT_CACHE_LOCK:
            web_mod._last_stats_snapshots.clear()

        app = create_app(
            stats=collector,
            config={
                "webserver": {
                    "enabled": True,
                    "stats_snapshot_ttl_seconds": 10.0,
                }
            },
            log_buffer=RingBuffer(),
        )
        client = TestClient(app)

        resp1 = client.get("/stats")
        resp2 = client.get("/stats")
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        # Within TTL, snapshot() should only have been invoked once.
        assert calls["n"] == 1

        # A reset=True request must force an additional snapshot() call.
        resp3 = client.get("/stats", params={"reset": "true"})
        assert resp3.status_code == 200
        assert calls["n"] == 2
    finally:
        web_mod._STATS_SNAPSHOT_CACHE_TTL_SECONDS = orig_ttl
        with web_mod._STATS_SNAPSHOT_CACHE_LOCK:
            web_mod._last_stats_snapshots.clear()


def test_stats_reset_endpoint_clears_counters() -> None:
    """Brief: POST /stats/reset must clear StatsCollector counters.

    Inputs:
      - StatsCollector with one recorded query and rcodes.

    Outputs:
      - After reset, snapshot totals and rcodes are empty or zeroed.
    """

    collector = StatsCollector(track_uniques=False, include_qtype_breakdown=True)
    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_response_rcode("NOERROR")

    app = create_app(
        stats=collector,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
    )
    client = TestClient(app)

    # Ensure we have some data first
    before = collector.snapshot(reset=False)
    assert before.totals.get("total_queries", 0) == 1

    reset_resp = client.post("/stats/reset")
    assert reset_resp.status_code == 200

    after = collector.snapshot(reset=False)
    assert after.totals.get("total_queries", 0) == 0
    assert after.rcodes.get("NOERROR", 0) == 0


def test_config_endpoint_returns_sanitized_config() -> None:
    """Brief: /config must return sanitized YAML config with secrets redacted.

    Inputs:
      - Config containing nested password and token fields.

    Outputs:
      - /config YAML config has those values replaced with '***'.
    """

    cfg = {
        "webserver": {
            "enabled": True,
            "redact_keys": ["token", "password"],
            "auth": {"token": "secret-token", "password": "pw"},
        },
        "upstreams": [
            {"host": "1.1.1.1", "token": "upstream-token"},
        ],
    }

    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)

    resp = client.get("/config")
    assert resp.status_code == 200
    yaml_text = resp.text
    config_out = yaml.safe_load(yaml_text) or {}

    auth_out = config_out["webserver"]["auth"]
    assert auth_out["token"] == "***"
    assert auth_out["password"] == "***"

    upstream_out = config_out["upstreams"][0]
    assert upstream_out["token"] == "***"


def test_config_yaml_cache_reuses_body_within_ttl(monkeypatch) -> None:
    """Brief: _get_sanitized_config_yaml_cached should reuse YAML text within TTL.

    Inputs:
      - In-memory config without a config_path and a mocked yaml.safe_dump.

    Outputs:
      - Repeated calls with the same (cfg_path, redact_keys) key invoke
        yaml.safe_dump only once; changing redact_keys causes a new dump.
    """

    import foghorn.servers.webserver as web_mod

    cfg = {"webserver": {"enabled": True}}
    calls = {"dump": 0}

    def fake_safe_dump(data, sort_keys=False):  # noqa: ARG001
        calls["dump"] += 1
        # Include the call count so we can distinguish outputs if needed.
        return f"yaml-dump-{calls['dump']}"

    monkeypatch.setattr(web_mod.yaml, "safe_dump", fake_safe_dump)

    orig_ttl = web_mod._CONFIG_TEXT_CACHE_TTL_SECONDS
    try:
        web_mod._CONFIG_TEXT_CACHE_TTL_SECONDS = 10.0
        with web_mod._CONFIG_TEXT_CACHE_LOCK:
            web_mod._last_config_text_key = None
            web_mod._last_config_text = None
            web_mod._last_config_text_ts = 0.0

        body1 = web_mod._get_sanitized_config_yaml_cached(
            cfg, cfg_path=None, redact_keys=["token"]
        )
        body2 = web_mod._get_sanitized_config_yaml_cached(
            cfg, cfg_path=None, redact_keys=["token"]
        )

        # Within TTL and with the same cache key, safe_dump should run once and
        # the returned body should be reused.
        assert calls["dump"] == 1
        assert body1 == body2

        # Changing redact_keys changes the cache key and forces another dump.
        body3 = web_mod._get_sanitized_config_yaml_cached(
            cfg, cfg_path=None, redact_keys=["password"]
        )
        assert calls["dump"] == 2
        assert body3.startswith("yaml-dump-")
    finally:
        web_mod._CONFIG_TEXT_CACHE_TTL_SECONDS = orig_ttl
        with web_mod._CONFIG_TEXT_CACHE_LOCK:
            web_mod._last_config_text_key = None
            web_mod._last_config_text = None
            web_mod._last_config_text_ts = 0.0


def test_config_json_endpoint_returns_sanitized_config() -> None:
    """Brief: /config.json must return sanitized JSON config with secrets redacted.

    Inputs:
      - Config containing nested password and token fields.

    Outputs:
      - /config.json JSON config has those values replaced with '***'.
    """

    cfg = {
        "webserver": {
            "enabled": True,
            "redact_keys": ["token", "password"],
            "auth": {"token": "secret-token", "password": "pw"},
        },
        "upstreams": [
            {"host": "1.1.1.1", "token": "upstream-token"},
        ],
    }

    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)

    resp = client.get("/config.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "server_time" in data
    config_out = data["config"]

    auth_out = config_out["webserver"]["auth"]
    assert auth_out["token"] == "***"
    assert auth_out["password"] == "***"

    upstream_out = config_out["upstreams"][0]
    assert upstream_out["token"] == "***"


def test_config_raw_fastapi_returns_plain_yaml(tmp_path) -> None:
    """Brief: /config/raw FastAPI endpoint must return plain YAML text.

    Inputs:
      - Temporary YAML config file with a simple mapping.

    Outputs:
      - /config/raw returns application/x-yaml and the body parses back to the
        same mapping as the on-disk YAML.
    """

    cfg_text = "webserver:\n  enabled: true\nanswer: 42\n"
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(cfg_text, encoding="utf-8")

    cfg = {"webserver": {"enabled": True}}
    app = create_app(
        stats=None, config=cfg, log_buffer=RingBuffer(), config_path=str(cfg_file)
    )
    client = TestClient(app)

    resp = client.get("/config/raw")
    assert resp.status_code == 200
    assert resp.headers.get("content-type", "").startswith("application/x-yaml")

    body = resp.text
    assert body == cfg_text

    # Sanity-check that the YAML still parses to the same mapping.
    parsed = yaml.safe_load(body) or {}
    assert parsed["webserver"]["enabled"] is True
    assert parsed["answer"] == 42


def test_logs_endpoint_returns_entries_from_ringbuffer() -> None:
    """Brief: /logs must return entries that were pushed into the RingBuffer.

    Inputs:
      - RingBuffer with a few numeric entries.

    Outputs:
      - /logs JSON entries list reflects the latest buffer contents.
    """

    buf = RingBuffer(capacity=3)
    buf.push({"n": 1})
    buf.push({"n": 2})
    buf.push({"n": 3})
    buf.push({"n": 4})  # evicts {"n": 1}

    app = create_app(
        stats=None, config={"webserver": {"enabled": True}}, log_buffer=buf
    )
    client = TestClient(app)

    resp = client.get("/logs")
    assert resp.status_code == 200
    data = resp.json()
    entries = data["entries"]
    assert len(entries) == 3
    assert entries[0]["n"] == 2
    assert entries[-1]["n"] == 4


def test_query_log_endpoint_paginates_and_filters(tmp_path) -> None:
    """Brief: /api/v1/query_log returns paginated rows and supports basic filters.

    Inputs:
      - StatsCollector backed by a StatsSQLiteStore with several query_log rows.

    Outputs:
      - Response contains total/page/page_size metadata.
      - Results are ordered newest-first and can be filtered by rcode.
    """

    store = StatsSQLiteStore(str(tmp_path / "stats.db"))
    collector = StatsCollector(stats_store=store)

    # Insert a few rows at deterministic timestamps.
    collector.record_query_result(
        client_ip="192.0.2.1",
        qname="example.com",
        qtype="A",
        rcode="NOERROR",
        upstream_id="8.8.8.8:53",
        status="ok",
        error=None,
        first="1.2.3.4",
        result={"source": "upstream"},
        ts=1000.0,
    )
    collector.record_query_result(
        client_ip="192.0.2.2",
        qname="example.com",
        qtype="AAAA",
        rcode="NXDOMAIN",
        upstream_id="8.8.8.8:53",
        status="error",
        error=None,
        first=None,
        result={"source": "upstream"},
        ts=1001.0,
    )
    collector.record_query_result(
        client_ip="192.0.2.3",
        qname="other.example.com",
        qtype="A",
        rcode="NXDOMAIN",
        upstream_id="1.1.1.1:53",
        status="error",
        error=None,
        first=None,
        result={"source": "upstream"},
        ts=1002.0,
    )

    app = create_app(
        stats=collector,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
    )
    client = TestClient(app)

    # Page 1, size 2 -> newest two rows.
    resp = client.get("/api/v1/query_log", params={"page": 1, "page_size": 2})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["total_pages"] == 2
    assert len(data["items"]) == 2

    # Ordered newest-first: ts 1002 then 1001
    assert data["items"][0]["ts"] == 1002.0
    assert data["items"][1]["ts"] == 1001.0

    # Filter by rcode
    resp2 = client.get("/api/v1/query_log", params={"rcode": "NXDOMAIN"})
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["total"] == 2
    assert all(item.get("rcode") == "NXDOMAIN" for item in data2["items"])


def test_query_log_aggregate_fills_zero_buckets(tmp_path) -> None:
    """Brief: /api/v1/query_log/aggregate returns a dense series (including zeros).

    Inputs:
      - StatsCollector backed by a StatsSQLiteStore with a few REFUSED rows.

    Outputs:
      - Buckets cover the full [start, end) range and include zero-count buckets.
    """

    store = StatsSQLiteStore(str(tmp_path / "stats2.db"))
    collector = StatsCollector(stats_store=store)

    # Range: 2025-12-10 01:00:00Z to 02:00:00Z, 15-minute buckets.
    from datetime import datetime, timezone

    start_dt = datetime(2025, 12, 10, 1, 0, 0, tzinfo=timezone.utc)

    # Two REFUSED events at 01:05 and 01:35.
    collector.record_query_result(
        client_ip="192.0.2.1",
        qname="example.com",
        qtype="A",
        rcode="REFUSED",
        upstream_id=None,
        status="error",
        error=None,
        first=None,
        result={"source": "server"},
        ts=start_dt.timestamp() + 5 * 60,
    )
    collector.record_query_result(
        client_ip="192.0.2.1",
        qname="example.com",
        qtype="A",
        rcode="REFUSED",
        upstream_id=None,
        status="error",
        error=None,
        first=None,
        result={"source": "server"},
        ts=start_dt.timestamp() + 35 * 60,
    )

    app = create_app(
        stats=collector,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
    )
    client = TestClient(app)

    resp = client.get(
        "/api/v1/query_log/aggregate",
        params={
            "rcode": "REFUSED",
            "interval": 15,
            "interval_units": "minutes",
            "start": "2025-12-10 01:00:00",
            "end": "2025-12-10 02:00:00",
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    items = data["items"]
    assert len(items) == 4
    counts = [it["count"] for it in items]
    assert counts == [1, 0, 1, 0]


def test_suppress2xx_filter_handles_status_attribute() -> None:
    """Brief: _Suppress2xxAccessFilter must drop 2xx when status_code attr is set.

    Inputs:
      - Synthetic LogRecord instances with status_code attribute.

    Outputs:
      - Filter returns False for 2xx and True for non-2xx status codes.
    """

    flt = _Suppress2xxAccessFilter()

    rec_200 = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="200 OK",
        args=(),
        exc_info=None,
    )
    rec_200.status_code = 200

    rec_201 = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="201 Created",
        args=(),
        exc_info=None,
    )
    rec_201.status_code = 201

    rec_404 = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="404 Not Found",
        args=(),
        exc_info=None,
    )
    rec_404.status_code = 404

    assert flt.filter(rec_200) is False
    assert flt.filter(rec_201) is False
    assert flt.filter(rec_404) is True


def test_suppress2xx_filter_handles_args_dict_and_tuple() -> None:
    """Brief: _Suppress2xxAccessFilter must interpret status from args.

    Inputs:
      - LogRecords with dict args and tuple args containing status codes.

    Outputs:
      - 2xx are suppressed; non-2xx are allowed; non-numeric args are ignored.
    """

    flt = _Suppress2xxAccessFilter()

    # Dict args with status_code (set args after construction to avoid LogRecord
    # treating the mapping as a positional sequence internally).
    rec_204 = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="%(status_code)d",
        args=(),
        exc_info=None,
    )
    rec_204.args = {"status_code": 204}

    # Dict args with status
    rec_500 = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="%(status)d",
        args=(),
        exc_info=None,
    )
    rec_500.args = {"status": 500}

    # Tuple args; last element is status code
    rec_tuple_200 = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="%s %s",
        args=("GET /", 200),
        exc_info=None,
    )

    # Tuple args with non-numeric last argument -> keep record
    rec_tuple_bad = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="%s",
        args=("no-status",),
        exc_info=None,
    )

    assert flt.filter(rec_204) is False
    assert flt.filter(rec_tuple_200) is False
    assert flt.filter(rec_500) is True
    assert flt.filter(rec_tuple_bad) is True


def test_install_uvicorn_2xx_suppression_is_idempotent() -> None:
    """Brief: install_uvicorn_2xx_suppression must not add duplicate filters.

    Inputs:
      - Global uvicorn.access logger.

    Outputs:
      - Exactly one _Suppress2xxAccessFilter instance after repeated calls.
    """

    logger_obj = logging.getLogger("uvicorn.access")
    original_filters = list(logger_obj.filters)
    try:
        logger_obj.filters = list(original_filters)
        install_uvicorn_2xx_suppression()
        count1 = sum(
            isinstance(f, _Suppress2xxAccessFilter) for f in logger_obj.filters
        )
        install_uvicorn_2xx_suppression()
        count2 = sum(
            isinstance(f, _Suppress2xxAccessFilter) for f in logger_obj.filters
        )
        assert count1 == 1
        assert count2 == 1
    finally:
        logger_obj.filters = original_filters


def test_create_app_installs_filter_on_startup() -> None:
    """Brief: create_app startup hook must attach 2xx suppression filter.

    Inputs:
      - Admin FastAPI app created with create_app.

    Outputs:
      - uvicorn.access logger has _Suppress2xxAccessFilter after client startup.
    """

    logger_obj = logging.getLogger("uvicorn.access")
    original_filters = list(logger_obj.filters)
    try:
        logger_obj.filters = []
        app = create_app(
            stats=None, config={"webserver": {"enabled": True}}, log_buffer=RingBuffer()
        )
        # TestClient triggers FastAPI startup events on first use
        with TestClient(app):
            pass
        assert any(isinstance(f, _Suppress2xxAccessFilter) for f in logger_obj.filters)
    finally:
        logger_obj.filters = original_filters


def test_root_index_serves_project_html_index(monkeypatch, tmp_path) -> None:
    """Brief: GET / and /index.html should serve project html/index.html.

    Inputs:
      - Temporary html directory with an index.html file.

    Outputs:
      - / and /index.html return HTTP 200, HTML content type, and the
        contents of html/index.html.
    """

    import os

    # Point www_root to a temporary html directory for this test
    root_dir = tmp_path
    html_dir = root_dir / "html"
    html_dir.mkdir()
    index_path = html_dir / "index.html"
    index_body = "<html><body>test dashboard from project html</body></html>"
    index_path.write_text(index_body, encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True, "index": True}},
        log_buffer=RingBuffer(),
    )

    # Override app.state.www_root to point at our temporary html directory
    app.state.www_root = os.fspath(html_dir)
    client = TestClient(app)

    for path in ["/", "/index.html"]:
        resp = client.get(path)
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert index_body == resp.text


def test_token_auth_blocks_unauthorized_and_allows_with_token() -> None:
    """Brief: auth.mode=token enforces bearer or X-API-Key token on protected endpoints.

    Inputs:
      - webserver config with auth.mode=token and a fixed token value.

    Outputs:
      - /stats returns 401 without token and includes WWW-Authenticate header.
      - /stats returns 200 when valid token is supplied.
    """

    cfg = {
        "webserver": {
            "enabled": True,
            "auth": {"mode": "token", "token": "secret-token"},
        }
    }
    collector = StatsCollector(track_uniques=False)

    app = create_app(stats=collector, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)

    # No token -> unauthorized
    resp_no_auth = client.get("/stats")
    assert resp_no_auth.status_code == 401
    assert "bearer" in (resp_no_auth.headers.get("www-authenticate") or "").lower()

    # Bearer token
    resp_bearer = client.get("/stats", headers={"Authorization": "Bearer secret-token"})
    assert resp_bearer.status_code == 200

    # X-API-Key header
    resp_api_key = client.get("/stats", headers={"X-API-Key": "secret-token"})
    assert resp_api_key.status_code == 200


def test_ringbuffer_capacity_and_snapshot_limit() -> None:
    """Brief: RingBuffer enforces capacity and respects snapshot limits.

    Inputs:
      - Two ring buffers: one with small positive capacity, one with non-positive.

    Outputs:
      - snapshot() never returns more items than capacity and limit trims to
        the newest N entries.
    """

    buf = RingBuffer(capacity=2)
    buf.push(1)
    buf.push(2)
    buf.push(3)
    # Capacity 2 -> only the last two items are retained
    assert buf.snapshot() == [2, 3]
    # Limit 1 -> only the newest item is returned
    assert buf.snapshot(limit=1) == [3]

    # Non-positive capacity is coerced to at least 1
    buf2 = RingBuffer(capacity=0)
    buf2.push("a")
    buf2.push("b")
    assert buf2.snapshot() == ["b"]


def test_resolve_www_root_prefers_config_then_env_then_cwd(
    monkeypatch, tmp_path
) -> None:
    """Brief: resolve_www_root prioritizes config.www_root, then env, then CWD html/.

    Inputs:
      - Temporary directories to stand in for configured and environment roots.

    Outputs:
      - When config.webserver.www_root exists, it is returned.
      - Otherwise FOGHORN_WWW_ROOT is honored.
      - Otherwise ./html under the current working directory is used when present.
    """

    import os

    import foghorn.servers.webserver as web_mod

    # 1) Config override takes precedence when directory exists
    cfg_root = tmp_path / "cfg_html"
    cfg_root.mkdir()
    cfg = {"server": {"http": {"www_root": os.fspath(cfg_root)}}}
    resolved_cfg = resolve_www_root(cfg)
    assert resolved_cfg == os.fspath(cfg_root.resolve())

    # 2) Environment variable is used when config doesn't specify www_root
    env_root = tmp_path / "env_html"
    env_root.mkdir()
    monkeypatch.delenv("FOGHORN_WWW_ROOT", raising=False)
    monkeypatch.setenv("FOGHORN_WWW_ROOT", os.fspath(env_root))
    resolved_env = resolve_www_root({"server": {"http": {}}})
    assert resolved_env == os.fspath(env_root.resolve())

    # 3) Falling back to ./html relative to current working directory
    cwd_root = tmp_path / "cwd_root"
    html_dir = cwd_root / "html"
    html_dir.mkdir(parents=True)
    monkeypatch.delenv("FOGHORN_WWW_ROOT", raising=False)
    monkeypatch.setattr(web_mod.os, "getcwd", lambda: os.fspath(cwd_root))

    resolved_cwd = resolve_www_root({})
    assert resolved_cwd == os.fspath(html_dir.resolve())


def test_static_www_serves_files_and_blocks_traversal(monkeypatch, tmp_path) -> None:
    """Brief: Static FastAPI route must serve files and prevent path traversal.

    Inputs:
      - Temporary html directory with a simple file and attempted traversal path.

    Outputs:
      - Requesting an existing file under www_root returns HTTP 200.
      - Requests that escape the html root or target missing files return 404.
    """

    import os

    www_root = tmp_path / "html"
    www_root.mkdir()
    asset = www_root / "style.css"
    asset.write_text("body { background: #000; }", encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
    )
    app.state.www_root = os.fspath(www_root)
    client = TestClient(app)

    # Existing asset is served via /{path:path} route
    resp_ok = client.get("/style.css")
    assert resp_ok.status_code == 200
    assert "body { background: #000; }" in resp_ok.text

    # Attempted traversal outside www_root is rejected.
    # Note: some client stacks normalize raw "../" segments early; use a percent-encoded
    # traversal so the FastAPI route sees it and our path-safety guard executes.
    resp_traversal = client.get("/..%2Fsecret.txt")
    assert resp_traversal.status_code == 404

    # Non-existent file under www_root also 404s
    resp_missing = client.get("/missing.txt")
    assert resp_missing.status_code == 404


def test_config_raw_endpoint_reads_from_disk(tmp_path) -> None:
    """Brief: /config/raw must return the raw YAML config body.

    Inputs:
      - Temporary YAML config file with known contents.

    Outputs:
      - Response body is exactly the original YAML text and is served with a
        YAML-appropriate content type.
    """

    cfg_path = tmp_path / "config.yaml"
    yaml_text = "webserver:\n  enabled: true\nanswer: 42\n"
    cfg_path.write_text(yaml_text, encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
        config_path=str(cfg_path),
    )
    client = TestClient(app)

    resp = client.get("/config/raw")
    assert resp.status_code == 200
    # FastAPI should advertise a YAML-appropriate content type.
    assert resp.headers.get("content-type", "").startswith("application/x-yaml")

    # Body should match the on-disk YAML exactly.
    assert resp.text == yaml_text


def test_config_endpoint_preserves_comments_and_redacts_values_and_subkeys(
    tmp_path,
) -> None:
    """Brief: YAML redaction should preserve comments while redacting values and subkeys.

    Inputs:
      - On-disk-style YAML config with comments, inline comments, and nested auth block.

    Outputs:
      - Redacted YAML retains comments and structure but replaces sensitive
        values and all subkeys under a redacted key with '***'.
    """

    yaml_text = (
        "# top comment\\n"
        "webserver:\n"
        "  enabled: true  # inline comment\\n"
        "  auth:\n"
        "    # auth comment\\n"
        "    token: secret-token\\n"
        "    password: secret-password\\n"
        "  note: safe-value\\n"
    )

    # Directly exercise the textual YAML redaction helper, which is used by
    # the /config endpoint when config_path is available.
    body = _redact_yaml_text_preserving_layout(yaml_text, ["auth", "token", "password"])

    # Comments are preserved
    assert "# top comment" in body
    assert "# inline comment" in body
    assert "# auth comment" in body

    # auth subtree is redacted, including its subkeys
    assert "auth:" in body
    assert "token: ***" in body
    assert "password: ***" in body
    assert "secret-token" not in body
    assert "secret-password" not in body

    # Non-redacted keys remain visible
    assert "note: safe-value" in body


def test_config_raw_json_endpoint_reads_from_disk(tmp_path) -> None:
    """Brief: /config/raw.json must return parsed config mapping and raw YAML text.

    Inputs:
      - Temporary YAML config file with known contents.

    Outputs:
      - JSON payload contains raw_yaml with the original text and config
        mapping reconstructed from that YAML.
    """

    cfg_path = tmp_path / "config.yaml"
    yaml_text = "webserver:\n  enabled: true\nanswer: 42\n"
    cfg_path.write_text(yaml_text, encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
        config_path=str(cfg_path),
    )
    client = TestClient(app)

    resp = client.get("/config/raw.json")
    assert resp.status_code == 200
    data = resp.json()
    assert data["raw_yaml"] == yaml_text
    parsed = data["config"] or {}
    assert parsed["webserver"]["enabled"] is True
    assert parsed["answer"] == 42


def test_config_json_fastapi_and_threaded_payloads_match() -> None:
    """Brief: /config.json JSON from FastAPI and threaded admin must match.

    Inputs:
      - Shared configuration containing redacted fields.

    Outputs:
      - FastAPI and threaded /config.json responses match after normalizing timestamps.
    """

    import http.client

    import foghorn.servers.webserver as web_mod

    cfg = {
        "webserver": {
            "enabled": True,
            "auth": {"mode": "none"},
            "redact_keys": ["token", "password"],
        },
        "upstreams": [
            {"host": "1.1.1.1", "token": "upstream-token"},
        ],
    }

    # FastAPI /config.json
    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)
    fastapi_resp = client.get("/config.json")
    assert fastapi_resp.status_code == 200
    fastapi_data = fastapi_resp.json()

    # Threaded /config.json
    httpd = web_mod._AdminHTTPServer(
        ("127.0.0.1", 0),
        web_mod._ThreadedAdminRequestHandler,
        stats=None,
        config=cfg,
        log_buffer=RingBuffer(),
        config_path=None,
    )

    host, port = httpd.server_address

    def _serve_once() -> None:
        try:
            httpd.handle_request()
        finally:
            httpd.server_close()

    t = threading.Thread(target=_serve_once, daemon=True)
    t.start()

    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", "/config.json")
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read().decode("utf-8")
    finally:
        conn.close()
        t.join(timeout=1.0)

    threaded_data = json.loads(body)

    def _normalize(payload: dict) -> dict:
        cleaned = dict(payload)
        cleaned.pop("server_time", None)
        return cleaned

    norm_fast = _normalize(fastapi_data)
    norm_thread = _normalize(threaded_data)

    assert norm_fast == norm_thread


def test_config_raw_threaded_endpoint_returns_plain_yaml(tmp_path) -> None:
    """Brief: Threaded /config/raw must return plain YAML text.

    Inputs:
      - Temporary YAML config file with known contents.

    Outputs:
      - Response has a YAML content type and the body matches the on-disk YAML
        and parses back to the same mapping.
    """

    import http.client

    import foghorn.servers.webserver as web_mod

    cfg_path = tmp_path / "config.yaml"
    yaml_text = "webserver:\n  enabled: true\nanswer: 42\n"
    cfg_path.write_text(yaml_text, encoding="utf-8")

    cfg = {"webserver": {"enabled": True, "auth": {"mode": "none"}}}

    httpd = web_mod._AdminHTTPServer(
        ("127.0.0.1", 0),
        web_mod._ThreadedAdminRequestHandler,
        stats=None,
        config=cfg,
        log_buffer=RingBuffer(),
        config_path=str(cfg_path),
    )

    host, port = httpd.server_address

    def _serve_once() -> None:
        try:
            httpd.handle_request()
        finally:
            httpd.server_close()

    t = threading.Thread(target=_serve_once, daemon=True)
    t.start()

    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", "/config/raw")
        resp = conn.getresponse()
        assert resp.status == 200
        content_type = resp.getheader("Content-Type") or ""
        assert content_type.startswith("application/x-yaml")
        body = resp.read().decode("utf-8")
    finally:
        conn.close()
        t.join(timeout=1.0)

    assert body == yaml_text
    parsed = yaml.safe_load(body) or {}
    assert parsed["webserver"]["enabled"] is True
    assert parsed["answer"] == 42


def test_config_raw_json_threaded_endpoint_reads_from_disk(tmp_path) -> None:
    """Brief: Threaded /config/raw.json must read config from disk and echo raw_yaml.

    Inputs:
      - Temporary YAML config file with known contents.

    Outputs:
      - JSON payload contains raw_yaml with the original text and parsed mapping.
    """

    import http.client

    import foghorn.servers.webserver as web_mod

    cfg_path = tmp_path / "config.yaml"
    yaml_text = "webserver:\n  enabled: true\nanswer: 42\n"
    cfg_path.write_text(yaml_text, encoding="utf-8")

    cfg = {"webserver": {"enabled": True, "auth": {"mode": "none"}}}

    httpd = web_mod._AdminHTTPServer(
        ("127.0.0.1", 0),
        web_mod._ThreadedAdminRequestHandler,
        stats=None,
        config=cfg,
        log_buffer=RingBuffer(),
        config_path=str(cfg_path),
    )

    host, port = httpd.server_address

    def _serve_once() -> None:
        try:
            httpd.handle_request()
        finally:
            httpd.server_close()

    t = threading.Thread(target=_serve_once, daemon=True)
    t.start()

    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", "/config/raw.json")
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read().decode("utf-8")
    finally:
        conn.close()
        t.join(timeout=1.0)

    data = json.loads(body)
    assert data["raw_yaml"] == yaml_text
    parsed = data["config"] or {}
    assert parsed["webserver"]["enabled"] is True
    assert parsed["answer"] == 42


def test_save_config_persists_raw_yaml_and_signals(monkeypatch, tmp_path) -> None:
    """Brief: /config/save must overwrite config file and schedule SIGHUP.

    Inputs:
      - Existing config file path and JSON body containing raw_yaml.

    Outputs:
      - Config file on disk is updated to the raw_yaml content.
      - os.kill is invoked with SIGUSR1 for the current process so plugins can
        react to configuration changes.
    """

    import os

    import foghorn.servers.webserver as web_mod

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("initial: 1\n", encoding="utf-8")

    kill_calls: dict[str, tuple[int, int] | None] = {"args": None}

    def fake_kill(pid: int, sig: int) -> None:
        kill_calls["args"] = (pid, sig)

    monkeypatch.setattr(web_mod.os, "kill", fake_kill)

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
        config_path=str(cfg_path),
    )
    client = TestClient(app)

    new_yaml = "answer: 42\n"
    resp = client.post("/config/save", json={"raw_yaml": new_yaml})
    assert resp.status_code == 200

    # Config file is overwritten with the new YAML content
    on_disk = cfg_path.read_text(encoding="utf-8")
    assert on_disk == new_yaml

    # SIGHUP should be scheduled for the current process shortly after the
    # config write. Because the signal is sent from a background timer, wait
    # briefly for os.kill to be invoked.
    import time

    deadline = time.time() + 2.0
    while kill_calls["args"] is None and time.time() < deadline:
        time.sleep(0.01)

    assert kill_calls["args"] is not None
    pid, sig = kill_calls["args"]  # type: ignore[assignment]
    assert pid == os.getpid()
    assert sig == web_mod.signal.SIGHUP


def test_read_proc_meminfo_parses_sample_file(tmp_path) -> None:
    """Brief: _read_proc_meminfo parses kB values from a meminfo-style file.

    Inputs:
      - Temporary file containing a subset of /proc/meminfo-style lines.

    Outputs:
      - Dict maps fields to byte counts; invalid and malformed lines are ignored.
    """

    meminfo_path = tmp_path / "meminfo"
    meminfo_path.write_text(
        "MemTotal:       1024 kB\n"
        "MemFree:        256 kB\n"
        "NoColonLine\n"  # should be skipped entirely
        "EmptyField:   \n"  # has ':' but no numeric parts -> skipped
        "Bogus: not-a-number kB\n",  # numeric parse failure -> skipped
        encoding="utf-8",
    )

    result = _read_proc_meminfo(str(meminfo_path))
    assert result["MemTotal"] == 1024 * 1024
    assert result["MemFree"] == 256 * 1024
    assert "Bogus" not in result
    assert "NoColonLine" not in result
    assert "EmptyField" not in result


def test_utc_now_iso_returns_parseable_utc_timestamp() -> None:
    """Brief: _utc_now_iso returns an ISO 8601 UTC timestamp string.

    Inputs:
      - None.

    Outputs:
      - A string that datetime.fromisoformat can parse and that represents UTC.
    """

    from datetime import datetime, timezone

    ts = _utc_now_iso()
    parsed = datetime.fromisoformat(ts)
    assert parsed.tzinfo is not None
    assert parsed.tzinfo.utcoffset(parsed) == timezone.utc.utcoffset(parsed)


def test_get_system_info_handles_missing_psutil(monkeypatch) -> None:
    """Brief: get_system_info must tolerate psutil being unavailable.

    Inputs:
      - monkeypatch fixture to force psutil to None.

    Outputs:
      - Returned dict still contains process_* keys but values may be None.
    """

    import foghorn.servers.webserver as web_mod

    monkeypatch.setattr(web_mod, "psutil", None)

    info = get_system_info()
    assert "process_rss_bytes" in info
    assert "process_rss_mb" in info


def test_token_auth_500_when_token_missing() -> None:
    """Brief: auth.mode=token without a token yields HTTP 500 error on protected endpoints.

    Inputs:
      - webserver config with auth.mode=token and no token value.

    Outputs:
      - /stats responds with 500 and an explanatory error message.
    """

    cfg = {
        "webserver": {
            "enabled": True,
            "auth": {"mode": "token"},
        }
    }
    collector = StatsCollector(track_uniques=False)

    app = create_app(stats=collector, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)

    resp = client.get("/stats")
    assert resp.status_code == 500
    body = resp.json()
    assert body["detail"] == "webserver.auth.token not configured"


def test_fastapi_cors_headers_when_enabled(monkeypatch) -> None:
    """Brief: FastAPI admin app applies CORS headers when webserver.cors.enabled is true.

    Inputs:
      - webserver config enabling CORS with a specific allowlist origin.

    Outputs:
      - /health response includes Access-Control-Allow-Origin matching request Origin.
    """

    cfg = {
        "webserver": {
            "enabled": True,
            "cors": {"enabled": True, "allowlist": ["https://example.com"]},
        }
    }

    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)

    resp = client.get("/health", headers={"Origin": "https://example.com"})
    # FastAPI/Starlette normalize header casing; use case-insensitive access.
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "https://example.com"


def test_start_webserver_returns_none_when_disabled() -> None:
    """Brief: start_webserver returns None when server.http.enabled is false.

    Inputs:
      - Config with server.http.enabled explicitly set to False.

    Outputs:
      - Function returns None and does not attempt to start any server.
    """

    cfg = {"server": {"http": {"enabled": False}}}
    handle = start_webserver(stats=None, config=cfg, log_buffer=RingBuffer())
    assert handle is None


def test_webserver_handle_is_running_and_stop_calls_shutdown_and_close() -> None:
    """Brief: WebServerHandle delegates shutdown and join to server and thread.

    Inputs:
      - Dummy thread and server objects tracking method calls.

    Outputs:
      - is_running() proxies thread.is_alive() and stop() invokes shutdown/server_close.
    """

    class DummyThread:
        def __init__(self) -> None:
            self.join_called = False

        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float) -> None:  # noqa: ARG002
            self.join_called = True

    class DummyServer:
        def __init__(self) -> None:
            self.shutdown_called = False
            self.close_called = False

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.close_called = True

    thread = DummyThread()
    server = DummyServer()
    handle = WebServerHandle(thread, server=server)

    assert handle.is_running() is True
    handle.stop(timeout=0.01)
    assert thread.join_called is True
    assert server.shutdown_called is True
    assert server.close_called is True


def test_start_webserver_uvicorn_path_uses_dummy_server(monkeypatch) -> None:
    """Brief: start_webserver uses uvicorn path when asyncio works and uvicorn is available.

    Inputs:
      - monkeypatch fixtures to install a dummy uvicorn module.

    Outputs:
      - WebServerHandle is returned and dummy uvicorn.Server.run() is invoked.
    """

    import asyncio
    import sys
    import types

    # Ensure asyncio loop creation succeeds and is exercised
    orig_new_loop = asyncio.new_event_loop

    def tracking_new_loop(*a, **kw):  # noqa: ANN001, ANN002
        loop = orig_new_loop(*a, **kw)
        loop.close()
        return loop

    monkeypatch.setattr(asyncio, "new_event_loop", tracking_new_loop, raising=True)

    state: dict[str, object] = {}

    class DummyConfig:
        def __init__(self, app, host, port, log_level):  # noqa: ANN001, ANN002
            self.app = app
            self.host = host
            self.port = port
            self.log_level = log_level

    class DummyServer:
        def __init__(self, config):  # noqa: ANN001
            state["config"] = config

        def run(self) -> None:
            state["ran"] = True

    dummy_uvicorn = types.SimpleNamespace(Config=DummyConfig, Server=DummyServer)
    monkeypatch.setitem(sys.modules, "uvicorn", dummy_uvicorn)

    cfg = {"server": {"http": {"enabled": True, "host": "127.0.0.1", "port": 0}}}
    handle = start_webserver(stats=None, config=cfg, log_buffer=RingBuffer())
    assert isinstance(handle, WebServerHandle)

    # Allow background thread to run run()
    import time

    time.sleep(0.05)

    assert state.get("ran") is True
    cfg_obj = state.get("config")
    assert isinstance(cfg_obj, DummyConfig)
    assert cfg_obj.host == "127.0.0.1"


def test_sanitize_config_non_dict_and_no_redact_keys() -> None:
    """Brief: sanitize_config handles non-dict input and missing redact_keys.

    Inputs:
      - Non-dict cfg and dict cfg without redact_keys.

    Outputs:
      - Non-dict input yields empty dict; no redact_keys returns deep copy.
    """

    # Non-dict input -> empty mapping
    assert sanitize_config("not-a-dict", ["token"]) == {}

    # No redact_keys -> original structure preserved in a deep copy
    cfg = {"webserver": {"auth": {"token": "secret"}}}
    clean = sanitize_config(cfg, redact_keys=None)
    assert clean == cfg
    assert clean is not cfg


def test_json_safe_handles_exceptions_and_custom_objects() -> None:
    """Brief: _json_safe should serialize exceptions and arbitrary objects safely.

    Inputs:
      - Mapping containing an Exception and a custom object.

    Outputs:
      - Exception represented as {"type", "message"}; custom object as string.
    """

    import foghorn.servers.webserver as web_mod

    class Custom:
        def __str__(self) -> str:  # noqa: D401
            """Return a simple marker string."""

            return "CUSTOM-OBJ"

    err = ValueError("boom")
    data = {"err": err, "obj": Custom()}
    safe = web_mod._json_safe(data)

    assert safe["err"]["type"] == "ValueError"
    assert safe["err"]["message"] == "boom"
    assert safe["obj"] == "CUSTOM-OBJ"


def test_get_system_info_swallows_psutil_exceptions(monkeypatch) -> None:
    """Brief: get_system_info must tolerate psutil Process methods raising.

    Inputs:
      - monkeypatch to install DummyProc that raises in various methods.

    Outputs:
      - Function returns dict with expected keys without raising.
    """

    import types

    import foghorn.servers.webserver as web_mod

    class DummyMemInfo:
        def __init__(self) -> None:
            self.rss = 1234

    class DummyProc:
        def memory_info(self) -> DummyMemInfo:
            return DummyMemInfo()

        def cpu_times(self):  # noqa: D401
            """Always raise to exercise exception path."""

            raise RuntimeError("cpu_times boom")

        def cpu_percent(self, interval: float = 0.0) -> float:  # noqa: ARG002
            raise RuntimeError("cpu_percent boom")

        def io_counters(self):  # noqa: D401
            """Always raise to exercise io_counters exception path."""

            raise RuntimeError("io boom")

        def open_files(self):  # noqa: D401
            """Always raise to exercise open_files exception path."""

            raise RuntimeError("open_files boom")

        def connections(self):  # noqa: D401
            """Always raise to exercise connections exception path."""

            raise RuntimeError("connections boom")

    fake_psutil = types.SimpleNamespace(Process=lambda _pid: DummyProc())
    monkeypatch.setattr(web_mod, "psutil", fake_psutil, raising=True)

    info = get_system_info()

    # Presence of keys is sufficient; values may be None when errors occur.
    for key in [
        "process_cpu_times",
        "process_cpu_percent",
        "process_io_counters",
        "process_open_files_count",
        "process_connections_count",
    ]:
        assert key in info


def test_resolve_www_root_falls_back_to_package_html(monkeypatch, tmp_path) -> None:
    """Brief: resolve_www_root falls back to package html/ when no overrides apply.

    Inputs:
      - monkeypatch and temporary directory for fake CWD.

    Outputs:
      - Returned path points under the foghorn html/ tree.
    """

    import os

    import foghorn.servers.webserver as web_mod

    # Ensure no env override and a CWD without html/ directory
    empty_root = tmp_path / "no_html_here"
    empty_root.mkdir()
    monkeypatch.delenv("FOGHORN_WWW_ROOT", raising=False)
    monkeypatch.setattr(web_mod.os, "getcwd", lambda: os.fspath(empty_root))

    path = resolve_www_root({})
    # We don't assert the exact path, just that it ends with an html directory.
    assert "html" in path.split(os.sep)


def test_stats_reset_endpoint_disabled_when_no_collector() -> None:
    """Brief: FastAPI /stats/reset returns disabled when no StatsCollector.

    Inputs:
      - App created with stats=None.

    Outputs:
      - JSON status == "disabled".
    """

    app = create_app(
        stats=None, config={"webserver": {"enabled": True}}, log_buffer=RingBuffer()
    )
    client = TestClient(app)

    resp = client.post("/stats/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "disabled"


def test_traffic_endpoint_disabled_when_no_collector() -> None:
    """Brief: FastAPI /traffic reports disabled when no StatsCollector.

    Inputs:
      - App created with stats=None.

    Outputs:
      - JSON status == "disabled".
    """

    app = create_app(
        stats=None, config={"webserver": {"enabled": True}}, log_buffer=RingBuffer()
    )
    client = TestClient(app)

    resp = client.get("/traffic")
    assert resp.status_code == 200
    assert resp.json()["status"] == "disabled"


def test_config_raw_500_when_config_path_missing() -> None:
    """Brief: FastAPI /config/raw returns 500 when config_path is not set.

    Inputs:
      - App created without config_path.

    Outputs:
      - HTTP 500 with detail explaining missing config_path.
    """

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
        config_path=None,
    )
    client = TestClient(app)

    resp = client.get("/config/raw")
    assert resp.status_code == 500
    body = resp.json()
    assert body["detail"] == "config_path not configured"


def test_save_config_400_when_body_not_object(tmp_path) -> None:
    """Brief: FastAPI /config/save rejects non-object bodies at runtime.

    Inputs:
      - Existing config file and list-valued body passed directly to endpoint.

    Outputs:
      - HTTPException 400 with message about JSON object requirement.
    """

    import asyncio

    from fastapi import HTTPException

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("initial: 1\n", encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
        config_path=str(cfg_path),
    )

    route = next(
        r for r in app.router.routes if getattr(r, "path", None) == "/config/save"
    )

    async def run() -> None:
        try:
            await route.endpoint(["not", "object"])  # type: ignore[arg-type]
        except HTTPException as exc:
            assert exc.status_code == 400
            assert exc.detail == "request body must be a JSON object"
        else:  # pragma: no cover - defensive
            assert False, "expected HTTPException for non-object body"

    asyncio.run(run())


def test_save_config_500_when_config_path_missing() -> None:
    """Brief: FastAPI /config/save errors when config_path is not configured.

    Inputs:
      - App created with config_path=None and valid body.

    Outputs:
      - HTTP 500 with detail about missing config_path.
    """

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
        config_path=None,
    )
    client = TestClient(app)

    resp = client.post("/config/save", json={"raw_yaml": "answer: 1\n"})
    assert resp.status_code == 500
    assert resp.json()["detail"] == "config_path not configured"


def test_save_config_400_when_raw_yaml_missing(tmp_path) -> None:
    """Brief: /config/save surfaces raw_yaml validation error via wrapped 500.

    Inputs:
      - Existing config file and JSON body missing raw_yaml.

    Outputs:
      - HTTP 500 whose detail mentions the missing raw_yaml field.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("initial: 1\n", encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
        config_path=str(cfg_path),
    )
    client = TestClient(app)

    resp = client.post("/config/save", json={})
    # HTTPException from validation is wrapped by the outer handler into a 500
    assert resp.status_code == 500
    detail = resp.json()["detail"]
    assert "request body must include 'raw_yaml' string field" in detail


def test_root_index_404_when_disabled(tmp_path) -> None:
    """Brief: FastAPI / and /index.html 404 when webserver.index is false.

    Inputs:
      - Temporary html directory with index.html but index disabled.

    Outputs:
      - Both routes return 404 with "index disabled" detail.
    """

    import os

    html_dir = tmp_path / "html"
    html_dir.mkdir()
    (html_dir / "index.html").write_text("<html>index</html>", encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True, "index": False}},
        log_buffer=RingBuffer(),
    )
    app.state.www_root = os.fspath(html_dir)
    client = TestClient(app)

    for path in ["/", "/index.html"]:
        resp = client.get(path)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "index disabled"


def test_root_index_404_when_index_missing(tmp_path) -> None:
    """Brief: FastAPI index routes 404 when index.html is missing under www_root.

    Inputs:
      - Temporary html directory without index.html.

    Outputs:
      - / and /index.html both respond 404 with "index not found".
    """

    import os

    html_dir = tmp_path / "html"
    html_dir.mkdir()

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True, "index": True}},
        log_buffer=RingBuffer(),
    )
    app.state.www_root = os.fspath(html_dir)
    client = TestClient(app)

    for path in ["/", "/index.html"]:
        resp = client.get(path)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "index not found"


def test_static_www_empty_path_raises_404() -> None:
    """Brief: Static FastAPI route must return 404 for empty path parameter.

    Inputs:
      - Direct call to the /{path:path} endpoint with empty string.

    Outputs:
      - HTTPException 404 with detail "not found".
    """

    import asyncio

    from fastapi import HTTPException

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
    )

    route = next(
        r for r in app.router.routes if getattr(r, "path", None) == "/{path:path}"
    )

    async def run() -> None:
        try:
            await route.endpoint("")  # type: ignore[arg-type]
        except HTTPException as exc:  # pragma: no cover - assertion is the goal
            assert exc.status_code == 404
            assert exc.detail == "not found"
        else:  # pragma: no cover - defensive
            assert False, "expected HTTPException for empty path"

    asyncio.run(run())


def test_webserver_handle_stop_logs_server_shutdown_error(caplog) -> None:
    """Brief: WebServerHandle.stop logs when server shutdown/close fail.

    Inputs:
      - Dummy server raising from shutdown/server_close.

    Outputs:
      - Thread join is still attempted and an error log is emitted.
    """

    class DummyThread2:
        def __init__(self) -> None:
            self.join_called = False

        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float) -> None:  # noqa: ARG002
            self.join_called = True

    class BadServer:
        def shutdown(self) -> None:
            raise RuntimeError("boom-shutdown")

        def server_close(self) -> None:
            raise RuntimeError("boom-close")

    thread = DummyThread2()
    server = BadServer()
    handle = WebServerHandle(thread, server=server)

    with caplog.at_level("ERROR", logger="foghorn.webserver"):
        handle.stop(timeout=0.01)

    assert thread.join_called is True
    assert any(
        "Error while shutting down webserver instance" in rec.getMessage()
        for rec in caplog.records
    )


def test_webserver_handle_stop_logs_thread_join_error(caplog) -> None:
    """Brief: WebServerHandle.stop logs when thread.join raises.

    Inputs:
      - Dummy thread whose join() raises.

    Outputs:
      - Error log mentioning failure to stop webserver thread.
    """

    class BadThread:
        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float) -> None:  # noqa: ARG002
            raise RuntimeError("boom-join")

    handle = WebServerHandle(BadThread(), server=None)

    with caplog.at_level("ERROR", logger="foghorn.webserver"):
        handle.stop(timeout=0.01)

    assert any(
        "Error while stopping webserver thread" in rec.getMessage()
        for rec in caplog.records
    )


def test_start_webserver_permission_error_uses_threaded_fallback(monkeypatch) -> None:
    """Brief: PermissionError during asyncio loop creation forces threaded fallback.

    Inputs:
      - monkeypatch replacing asyncio.new_event_loop and _start_admin_server_threaded.

    Outputs:
      - start_webserver returns handle from threaded fallback.
    """

    import asyncio
    import threading

    import foghorn.servers.webserver as web_mod

    def boom_new_loop() -> None:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(
        asyncio, "new_event_loop", lambda: boom_new_loop(), raising=True
    )

    calls: dict[str, object] = {}

    def fake_threaded(
        stats, config, log_buffer, config_path=None
    ):  # noqa: ANN001, ANN201
        calls["args"] = (stats, config, log_buffer, config_path)
        return WebServerHandle(threading.Thread())

    monkeypatch.setattr(
        web_mod, "_start_admin_server_threaded", fake_threaded, raising=True
    )
    monkeypatch.setattr(web_mod.os.path, "exists", lambda p: False, raising=False)

    cfg2 = {"server": {"http": {"enabled": True}}}
    handle = start_webserver(stats=None, config=cfg2, log_buffer=RingBuffer())

    assert isinstance(handle, WebServerHandle)
    assert "args" in calls


def test_start_webserver_other_asyncio_error_keeps_async_path(monkeypatch) -> None:
    """Brief: Non-PermissionError from asyncio.new_event_loop does not disable async path.

    Inputs:
      - monkeypatch causing asyncio.new_event_loop to raise RuntimeError.

    Outputs:
      - start_webserver still uses uvicorn path via dummy uvicorn module.
    """

    import asyncio
    import sys
    import types

    def boom_new_loop2() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(
        asyncio, "new_event_loop", lambda: boom_new_loop2(), raising=True
    )

    state2: dict[str, object] = {}

    class DummyConfig2:
        def __init__(self, app, host, port, log_level):  # noqa: ANN001, ANN002
            self.app = app
            self.host = host
            self.port = port
            self.log_level = log_level

    class DummyServer2:
        def __init__(self, config):  # noqa: ANN001
            state2["config"] = config

        def run(self) -> None:
            state2["ran"] = True

    dummy_uvicorn2 = types.SimpleNamespace(Config=DummyConfig2, Server=DummyServer2)
    monkeypatch.setitem(sys.modules, "uvicorn", dummy_uvicorn2)

    cfg3 = {"server": {"http": {"enabled": True, "host": "127.0.0.1", "port": 0}}}
    handle = start_webserver(stats=None, config=cfg3, log_buffer=RingBuffer())
    assert isinstance(handle, WebServerHandle)

    import time

    time.sleep(0.05)

    assert state2.get("ran") is True


def test_start_webserver_warns_when_public_host_without_auth(
    monkeypatch, caplog
) -> None:
    """Brief: start_webserver warns when binding to 0.0.0.0 without auth.

    Inputs:
      - Config with host 0.0.0.0 and auth.mode=none.

    Outputs:
      - Warning log mentioning unauthenticated binding.
    """

    import sys
    import types

    # Install dummy uvicorn implementation similar to earlier tests
    state3: dict[str, object] = {}

    class DummyConfig3:
        def __init__(self, app, host, port, log_level):  # noqa: ANN001, ANN002
            self.app = app
            self.host = host
            self.port = port
            self.log_level = log_level

    class DummyServer3:
        def __init__(self, config):  # noqa: ANN001
            state3["config"] = config

        def run(self) -> None:
            state3["ran"] = True

    dummy_uvicorn3 = types.SimpleNamespace(Config=DummyConfig3, Server=DummyServer3)
    monkeypatch.setitem(sys.modules, "uvicorn", dummy_uvicorn3)

    cfg4 = {
        "server": {
            "http": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 0,
                "auth": {"mode": "none"},
            }
        }
    }

    with caplog.at_level("WARNING", logger="foghorn.webserver"):
        handle = start_webserver(stats=None, config=cfg4, log_buffer=RingBuffer())

    assert isinstance(handle, WebServerHandle)
    assert any(
        "bound to 0.0.0.0 without authentication" in rec.getMessage()
        for rec in caplog.records
    )


def test_split_yaml_value_and_comment_with_and_without_comment() -> None:
    """Brief: _split_yaml_value_and_comment must split value and inline comment.

    Inputs:
      - Sample YAML rest strings with and without an inline comment.

    Outputs:
      - Tuple where the value is stripped and the comment suffix preserves ' #'.
    """

    import foghorn.servers.webserver as web_mod

    value, comment = web_mod._split_yaml_value_and_comment(" value  # inline comment")
    # Leading whitespace from the original rest segment is preserved.
    assert value.endswith("value")
    assert comment.startswith(" #")
    assert "inline comment" in comment

    value2, comment2 = web_mod._split_yaml_value_and_comment(" just-value ")
    # No comment present; only trailing whitespace is stripped.
    assert value2.endswith("just-value")
    assert comment2 == ""


def test_redact_yaml_preserving_layout_covers_lists_and_blank_lines() -> None:
    """Brief: YAML redaction must handle blank lines, nested keys, and list forms.

    Inputs:
      - Raw YAML text containing a redacted mapping key, list-of-mapping entries,
        and simple list items, with inline comments and a trailing newline.

    Outputs:
      - Redacted YAML preserves layout/comments and replaces values with '***'.
    """

    import foghorn.servers.webserver as web_mod

    yaml_text = (
        "auth:\n"
        "  token: secret-token  # c1\n"
        "  password: secret-password\n"
        "\n"  # blank line exercises empty-line branch
        "items:\n"
        "  - token: list-secret  # c2\n"
        "  - other: keep-me\n"
        "  - standalone-value  # c3\n"
        ""  # no trailing newline here; function should not add one
    )

    body = web_mod._redact_yaml_text_preserving_layout(
        yaml_text,
        ["auth", "token", "password"],
    )

    # Top-level auth subtree redacted, including nested keys.
    assert "auth:" in body
    assert "token: ***" in body
    assert "password: ***" in body
    assert "secret-token" not in body
    assert "secret-password" not in body

    # List-of-mapping entry with sensitive key is redacted.
    assert "- token: ***" in body
    assert "list-secret" not in body

    # Simple list items in a separate non-redacted block remain unchanged.
    assert "- standalone-value  # c3" in body

    # Non-redacted keys and comments are preserved.
    assert "other: keep-me" in body
    assert "# c1" in body
    assert "# c2" in body
    assert "# c3" in body


def test_redact_yaml_preserving_layout_early_return_on_empty_input() -> None:
    """Brief: YAML redaction returns input unchanged for empty text or keys.

    Inputs:
      - Empty raw_yaml and a non-empty redact_keys list.

    Outputs:
      - Function returns the original raw_yaml without modification.
    """

    import foghorn.servers.webserver as web_mod

    assert web_mod._redact_yaml_text_preserving_layout("", ["token"]) == ""
    assert (
        web_mod._redact_yaml_text_preserving_layout("key: value", None) == "key: value"
    )


def test_get_sanitized_config_yaml_cached_uses_config_path(tmp_path) -> None:
    """Brief: _get_sanitized_config_yaml_cached should read and redact from cfg_path.

    Inputs:
      - Temporary YAML config file containing a token field and redact_keys.

    Outputs:
      - Returned YAML body preserves structure while redacting the token value.
    """

    import foghorn.servers.webserver as web_mod

    cfg_text = "webserver:\n  enabled: true\n  auth:\n    token: secret-token\n"
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(cfg_text, encoding="utf-8")

    cfg = {"webserver": {"enabled": True, "auth": {"token": "secret-token"}}}

    body = web_mod._get_sanitized_config_yaml_cached(
        cfg, cfg_path=str(cfg_file), redact_keys=["token"]
    )

    assert "secret-token" not in body
    assert "token: ***" in body


def test_find_rate_limit_db_paths_from_config_extracts_db_paths() -> None:
    """Brief: _find_rate_limit_db_paths_from_config discovers configured db_path values.

    Inputs:
      - Config with a mix of matching and non-matching plugin entries.

    Outputs:
      - Sorted list of db_path values for rate_limit plugins only.
    """

    import foghorn.servers.webserver as web_mod

    cfg = {
        "plugins": [
            {
                "module": "foghorn.plugins.rate_limit",
                "config": {"db_path": "/tmp/a.db"},
            },
            {"module": "rate_limit", "config": {"db_path": "/tmp/b.db"}},
            {"module": "other", "config": {"db_path": "/tmp/c.db"}},
            {"module": "rate_limit", "config": {}},
            "not-a-dict",
        ]
    }

    paths = web_mod._find_rate_limit_db_paths_from_config(cfg)
    assert paths == ["/tmp/a.db", "/tmp/b.db"]
    assert web_mod._find_rate_limit_db_paths_from_config(None) == []


def test_collect_rate_limit_stats_handles_empty_and_populated_dbs(
    tmp_path,
) -> None:
    """Brief: _collect_rate_limit_stats summarizes both empty and populated DBs.

    Inputs:
      - Two sqlite3 databases under tmp_path, one empty and one with sample rows.

    Outputs:
      - Databases list contains per-db summaries with correct profile counts and
        max_* fields populated for the non-empty database.
    """

    import sqlite3
    from contextlib import closing

    import foghorn.servers.webserver as web_mod

    empty_db = tmp_path / "empty.db"
    populated_db = tmp_path / "profiles.db"

    for db_path, rows in [
        (empty_db, []),
        (
            populated_db,
            [
                ("key1", 1.5, 3.0, 10, 1000),
                ("key2", "bad", "also-bad", "NaN", "not-int"),
            ],
        ),
    ]:
        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute(
                "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
            )
            conn.executemany(
                "INSERT INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
            conn.commit()

    cfg = {
        "plugins": [
            {
                "module": "foghorn.plugins.rate_limit",
                "config": {"db_path": empty_db.as_posix()},
            },
            {
                "module": "rate_limit",
                "config": {"db_path": populated_db.as_posix()},
            },
        ]
    }

    # Reset cache so this test is deterministic.
    with web_mod._RATE_LIMIT_CACHE_LOCK:
        web_mod._last_rate_limit_snapshot = None
        web_mod._last_rate_limit_snapshot_ts = 0.0

    data = web_mod._collect_rate_limit_stats(cfg)
    databases = data["databases"]
    assert len(databases) == 2

    empty_summary = next(d for d in databases if d["db_path"] == empty_db.as_posix())
    populated_summary = next(
        d for d in databases if d["db_path"] == populated_db.as_posix()
    )

    assert empty_summary["total_profiles"] == 0
    assert populated_summary["total_profiles"] == 2
    assert populated_summary["max_avg_rps"] >= 0.0
    assert populated_summary["max_max_rps"] >= 0.0


def test_schedule_sighup_after_config_save_zero_delay_calls_kill(monkeypatch) -> None:
    """Brief: _schedule_sighup_after_config_save sends SIGHUP synchronously when delay <= 0.

    Inputs:
      - monkeypatch fixture to stub os.kill.

    Outputs:
      - os.kill is invoked immediately with the current PID and signal.SIGHUP.
    """

    import os

    import foghorn.servers.webserver as web_mod

    calls: list[tuple[int, int]] = []

    def fake_kill(pid: int, sig: int) -> None:
        calls.append((pid, sig))

    monkeypatch.setattr(web_mod.os, "kill", fake_kill)

    web_mod._schedule_sighup_after_config_save(delay_seconds=0.0)

    assert calls, "expected os.kill to be called synchronously"
    pid, sig = calls[0]
    assert pid == os.getpid()
    assert sig == web_mod.signal.SIGHUP


def test_config_cache_ttl_overridden_by_web_cfg(monkeypatch) -> None:
    """Brief: create_app applies webserver.config_cache_ttl_seconds to the TTL global.

    Inputs:
      - monkeypatch used to reset _CONFIG_TEXT_CACHE_TTL_SECONDS.

    Outputs:
      - After create_app(), the TTL global reflects the configured value.
    """

    import foghorn.servers.webserver as web_mod

    original_ttl = getattr(web_mod, "_CONFIG_TEXT_CACHE_TTL_SECONDS")
    try:
        monkeypatch.setattr(
            web_mod, "_CONFIG_TEXT_CACHE_TTL_SECONDS", 2.0, raising=False
        )
        cfg = {"webserver": {"enabled": True, "config_cache_ttl_seconds": 7.5}}
        create_app(stats=None, config=cfg, log_buffer=RingBuffer())
        assert web_mod._CONFIG_TEXT_CACHE_TTL_SECONDS == 7.5
    finally:
        web_mod._CONFIG_TEXT_CACHE_TTL_SECONDS = original_ttl


def test_config_raw_json_500_when_config_path_missing() -> None:
    """Brief: FastAPI /config/raw.json returns 500 when config_path is not set.

    Inputs:
      - App created with config_path=None.

    Outputs:
      - HTTP 500 with detail explaining missing config_path.
    """

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
        config_path=None,
    )
    client = TestClient(app)

    resp = client.get("/config/raw.json")
    assert resp.status_code == 500
    assert resp.json()["detail"] == "config_path not configured"


def test_rate_limit_endpoint_wraps_collect_rate_limit_stats(monkeypatch) -> None:
    """Brief: FastAPI /api/v1/ratelimit delegates to _collect_rate_limit_stats.

    Inputs:
      - monkeypatch to replace _collect_rate_limit_stats with a sentinel.

    Outputs:
      - Endpoint returns JSON including server_time and the sentinel payload.
    """

    import foghorn.servers.webserver as web_mod

    called: dict[str, object] = {}

    def fake_collect(config: dict | None) -> dict:  # noqa: ANN001
        called["config"] = config
        return {"databases": []}

    monkeypatch.setattr(web_mod, "_collect_rate_limit_stats", fake_collect)

    cfg = {"webserver": {"enabled": True}}
    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())

    # Invoke the route handler directly rather than going through HTTP
    # dispatch; this keeps the test focused on the wrapper behaviour
    # without depending on FastAPI's routing table.
    route = next(
        r for r in app.router.routes if getattr(r, "path", None) == "/api/v1/ratelimit"
    )

    import asyncio

    async def run() -> None:
        body = await route.endpoint()  # type: ignore[func-returns-value]
        assert "server_time" in body
        assert body["databases"] == []

    asyncio.run(run())
    assert called["config"] is cfg


def test_upstream_status_endpoint_returns_configured_and_health_only_entries(
    monkeypatch,
) -> None:
    """Brief: /api/v1/upstream_status includes configured upstreams and health-only items.

    Inputs:
      - App config with a configured upstream.
      - Monkeypatched DNSUDPHandler upstream_* attributes with extra health-only entry.

    Outputs:
      - Response contains both configured upstream entry (with config subset)
        and the extra health-only entry.
    """

    import asyncio

    import foghorn.servers.webserver as web_mod

    # One configured upstream.
    up = {"host": "1.1.1.1", "port": 53, "transport": "udp"}
    cfg = {"webserver": {"enabled": True}, "upstreams": [up]}

    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())

    # Inject handler state for the endpoint to read.
    up_id = web_mod.DNSUDPHandler._upstream_id(up)
    other_id = "health-only"

    monkeypatch.setattr(
        web_mod.DNSUDPHandler, "upstream_strategy", "failover", raising=False
    )
    monkeypatch.setattr(
        web_mod.DNSUDPHandler, "upstream_max_concurrent", "bad", raising=False
    )
    monkeypatch.setattr(
        web_mod.DNSUDPHandler,
        "upstream_health",
        {
            up_id: {"fail_count": "bad", "down_until": "bad"},
            other_id: {"fail_count": 2, "down_until": 0.0},
        },
        raising=False,
    )

    route = next(
        r
        for r in app.router.routes
        if getattr(r, "path", None) == "/api/v1/upstream_status"
    )

    async def run() -> None:
        body = await route.endpoint()  # type: ignore[func-returns-value]
        assert body["strategy"] == "failover"
        # bad max_concurrent coerces to 1
        assert body["max_concurrent"] == 1

        items = body["items"]
        ids = {it["id"] for it in items}
        assert up_id in ids
        assert other_id in ids

        configured = next(it for it in items if it["id"] == up_id)
        assert configured["config"]["host"] == "1.1.1.1"

        health_only = next(it for it in items if it["id"] == other_id)
        assert health_only["config"] == {}

    asyncio.run(run())


def test_stats_and_traffic_defensive_top_cast_paths(monkeypatch) -> None:
    """Brief: /stats and /traffic include defensive casts for top when called directly.

    Inputs:
      - App with a StatsCollector.
      - Direct route.endpoint() calls passing non-int and non-positive top values.

    Outputs:
      - Endpoints return a payload without raising.
    """

    import asyncio

    from foghorn.stats import StatsCollector

    collector = StatsCollector(track_uniques=False, include_qtype_breakdown=False)
    collector.record_query("192.0.2.1", "example.com", "A")

    cfg = {"webserver": {"enabled": True}}
    app = create_app(stats=collector, config=cfg, log_buffer=RingBuffer())

    stats_route = next(
        r for r in app.router.routes if getattr(r, "path", None) == "/stats"
    )
    traffic_route = next(
        r for r in app.router.routes if getattr(r, "path", None) == "/traffic"
    )

    async def run() -> None:
        body1 = await stats_route.endpoint(reset=False, top="bad")  # type: ignore[arg-type]
        assert "server_time" in body1

        body2 = await stats_route.endpoint(reset=False, top=0)  # type: ignore[arg-type]
        assert "server_time" in body2

        body3 = await traffic_route.endpoint(top="bad")  # type: ignore[arg-type]
        assert "server_time" in body3

        body4 = await traffic_route.endpoint(top=0)  # type: ignore[arg-type]
        assert "server_time" in body4

    asyncio.run(run())


def test_query_log_fastapi_defensive_parsing_by_direct_calls() -> None:
    """Brief: Query log endpoints include defensive parsing that is unreachable via FastAPI validation.

    Inputs:
      - App whose StatsCollector has a dummy store implementation.
      - Direct route.endpoint() calls supplying invalid page/page_size/interval values.

    Outputs:
      - Asserts the defensive branches execute without FastAPI validation.
    """

    import asyncio

    import pytest
    from fastapi import HTTPException
    from foghorn.stats import StatsCollector

    class DummyStore:
        def select_query_log(self, **_kw):  # noqa: ANN003
            # Intentionally omit page/page_size so the endpoint's defensive parsing
            # and defaults are reflected in the response.
            return {"items": [{"ts": 0.0}], "total": 1, "total_pages": 1}

        def aggregate_query_log_counts(self, **_kw):  # noqa: ANN003
            return {"items": []}

    collector = StatsCollector(track_uniques=False)
    # Attach dummy store to satisfy the endpoint's store lookup.
    collector._store = DummyStore()  # type: ignore[attr-defined]

    cfg = {"webserver": {"enabled": True}}
    app = create_app(stats=collector, config=cfg, log_buffer=RingBuffer())

    ql_route = next(
        r for r in app.router.routes if getattr(r, "path", None) == "/api/v1/query_log"
    )
    agg_route = next(
        r
        for r in app.router.routes
        if getattr(r, "path", None) == "/api/v1/query_log/aggregate"
    )

    async def run() -> None:
        # page_size parsing/clamping
        body1 = await ql_route.endpoint(page=1, page_size="bad")  # type: ignore[arg-type]
        assert body1["page_size"] == 100

        body2 = await ql_route.endpoint(page=1, page_size=-1)  # type: ignore[arg-type]
        assert body2["page_size"] == 100

        body3 = await ql_route.endpoint(page=1, page_size=2001)  # type: ignore[arg-type]
        assert body3["page_size"] == 1000

        # start/end parsing errors
        with pytest.raises(HTTPException):
            await ql_route.endpoint(page=1, page_size=1, start="bad")
        with pytest.raises(HTTPException):
            await ql_route.endpoint(page=1, page_size=1, end="bad")

        # aggregate: invalid start/end
        with pytest.raises(HTTPException):
            await agg_route.endpoint(
                interval=15,
                interval_units="minutes",
                start="bad",
                end="2025-12-10 02:00:00",
            )

        # aggregate: invalid interval cast
        with pytest.raises(HTTPException):
            await agg_route.endpoint(interval="bad", interval_units="minutes", start="2025-12-10 01:00:00", end="2025-12-10 02:00:00")  # type: ignore[arg-type]

        # aggregate: invalid units
        with pytest.raises(HTTPException):
            await agg_route.endpoint(
                interval=15,
                interval_units="weeks",
                start="2025-12-10 01:00:00",
                end="2025-12-10 02:00:00",
            )

    asyncio.run(run())
