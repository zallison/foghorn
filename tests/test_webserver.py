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
from foghorn.webserver import (
    RingBuffer,
    create_app,
    sanitize_config,
    _Suppress2xxAccessFilter,
    install_uvicorn_2xx_suppression,
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


def test_root_index_returns_html_when_enabled(tmp_path) -> None:
    """Brief: GET / should serve index.html when webserver.index is true.

    Inputs:
      - Temporary index.html file placed next to foghorn.webserver module.

    Outputs:
      - / returns HTTP 200 and HTML content type when file exists.
    """

    # Import here to locate the module directory at runtime
    import os
    import foghorn.webserver as web_mod

    here = os.path.dirname(os.path.abspath(web_mod.__file__))
    index_path = os.path.join(here, "index.html")

    # Create a temporary index.html in the module directory
    # (back up any existing file and restore it after test)
    backup_path = None
    if os.path.exists(index_path):
        backup_path = index_path + ".bak"
        os.replace(index_path, backup_path)

    try:
        with open(index_path, "w", encoding="utf-8") as f:
            f.write("<html><body>test dashboard</body></html>")

        app = create_app(
            stats=None,
            config={"webserver": {"enabled": True, "index": True}},
            log_buffer=RingBuffer(),
        )
        client = TestClient(app)

        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "test dashboard" in resp.text
    finally:
        # Clean up: remove temp file and restore backup if needed
        if os.path.exists(index_path):
            os.remove(index_path)
        if backup_path is not None and os.path.exists(backup_path):
            os.replace(backup_path, index_path)


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
