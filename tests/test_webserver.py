"""Tests for the FastAPI-based admin HTTP server in foghorn.webserver.

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

import logging

from fastapi.testclient import TestClient

from foghorn.stats import StatsCollector
from foghorn.webserver import (RingBuffer, WebServerHandle, _read_proc_meminfo,
                               _Suppress2xxAccessFilter, _utc_now_iso,
                               create_app, get_system_info,
                               install_uvicorn_2xx_suppression,
                               resolve_www_root, sanitize_config,
                               start_webserver)


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

    import foghorn.webserver as web_mod

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

    import foghorn.webserver as web_mod

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
    """Brief: /config must return sanitized config with secrets redacted.

    Inputs:
      - Config containing nested password and token fields.

    Outputs:
      - /config JSON config has those values replaced with '***'.
    """

    cfg = {
        "webserver": {
            "enabled": True,
            "redact_keys": ["token", "password"],
            "auth": {"token": "secret-token", "password": "pw"},
        },
        "upstream": [
            {"host": "1.1.1.1", "token": "upstream-token"},
        ],
    }

    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)

    resp = client.get("/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "config" in data
    config_out = data["config"]

    auth_out = config_out["webserver"]["auth"]
    assert auth_out["token"] == "***"
    assert auth_out["password"] == "***"

    upstream_out = config_out["upstream"][0]
    assert upstream_out["token"] == "***"


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
      - /stats returns 403 without token.
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

    # No token -> forbidden
    resp_no_auth = client.get("/stats")
    assert resp_no_auth.status_code == 403

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

    import foghorn.webserver as web_mod

    # 1) Config override takes precedence when directory exists
    cfg_root = tmp_path / "cfg_html"
    cfg_root.mkdir()
    cfg = {"webserver": {"www_root": os.fspath(cfg_root)}}
    resolved_cfg = resolve_www_root(cfg)
    assert resolved_cfg == os.fspath(cfg_root.resolve())

    # 2) Environment variable is used when config doesn't specify www_root
    env_root = tmp_path / "env_html"
    env_root.mkdir()
    monkeypatch.delenv("FOGHORN_WWW_ROOT", raising=False)
    monkeypatch.setenv("FOGHORN_WWW_ROOT", os.fspath(env_root))
    resolved_env = resolve_www_root({"webserver": {}})
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

    # Attempted traversal outside www_root is rejected
    resp_traversal = client.get("/../secret.txt")
    assert resp_traversal.status_code == 404

    # Non-existent file under www_root also 404s
    resp_missing = client.get("/missing.txt")
    assert resp_missing.status_code == 404


def test_config_raw_endpoint_reads_from_disk(tmp_path) -> None:
    """Brief: /config/raw must return raw YAML text and parsed mapping.

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

    resp = client.get("/config/raw")
    assert resp.status_code == 200
    data = resp.json()
    assert data["raw_yaml"] == yaml_text
    assert data["config"]["answer"] == 42


def test_save_config_persists_raw_yaml_and_signals(monkeypatch, tmp_path) -> None:
    """Brief: /config/save must overwrite config file and send SIGUSR1.

    Inputs:
      - Existing config file path and JSON body containing raw_yaml.

    Outputs:
      - Config file on disk is updated to the raw_yaml content.
      - os.kill is invoked with SIGUSR1 for the current process.
    """

    import os

    import foghorn.webserver as web_mod

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

    # SIGUSR1 was requested for current process
    assert kill_calls["args"] is not None
    pid, sig = kill_calls["args"]  # type: ignore[assignment]
    assert pid == os.getpid()
    assert sig == web_mod.signal.SIGUSR1


def test_read_proc_meminfo_parses_sample_file(tmp_path) -> None:
    """Brief: _read_proc_meminfo parses kB values from a meminfo-style file.

    Inputs:
      - Temporary file containing a subset of /proc/meminfo-style lines.

    Outputs:
      - Dict maps fields to byte counts; invalid lines are ignored.
    """

    meminfo_path = tmp_path / "meminfo"
    meminfo_path.write_text(
        "MemTotal:       1024 kB\n"
        "MemFree:        256 kB\n"
        "Bogus: not-a-number kB\n",
        encoding="utf-8",
    )

    result = _read_proc_meminfo(str(meminfo_path))
    assert result["MemTotal"] == 1024 * 1024
    assert result["MemFree"] == 256 * 1024
    assert "Bogus" not in result


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

    import foghorn.webserver as web_mod

    monkeypatch.setattr(web_mod, "psutil", None)

    info = get_system_info()
    assert "process_rss_bytes" in info
    assert "process_rss_mb" in info
    # With psutil forced to None, these are expected to be None.
    assert info["process_rss_bytes"] is None
    assert info["process_rss_mb"] is None


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
    """Brief: start_webserver returns None when webserver.enabled is false.

    Inputs:
      - Config with webserver.enabled set to False.

    Outputs:
      - Function returns None and does not attempt to start any server.
    """

    cfg = {"webserver": {"enabled": False}}
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

    cfg = {"webserver": {"enabled": True, "host": "127.0.0.1", "port": 0}}
    handle = start_webserver(stats=None, config=cfg, log_buffer=RingBuffer())
    assert isinstance(handle, WebServerHandle)

    # Allow background thread to run run()
    import time

    time.sleep(0.05)

    assert state.get("ran") is True
    cfg_obj = state.get("config")
    assert isinstance(cfg_obj, DummyConfig)
    assert cfg_obj.host == "127.0.0.1"
