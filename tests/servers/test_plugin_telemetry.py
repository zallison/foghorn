"""Tests for per-plugin execution telemetry in resolve plugin chains.

Brief: Unit tests for foghorn.servers.plugin_telemetry helpers plus an
integration test driving a full query through _resolve_core to verify the
per-plugin millisecond breakdown is logged at DEBUG after each chain
completes and slow plugins trigger a WARNING.

Inputs:
  - None (pytest fixtures only).

Outputs:
  - None (pytest assertions).
"""

import logging
import time

from dnslib import RR, A, DNSRecord

import foghorn.servers.server as srv
from foghorn.servers.plugin_telemetry import (
    DEFAULT_SLOW_PLUGIN_THRESHOLD_MS,
    PluginExecution,
    get_slow_plugin_threshold_ms,
    log_plugin_telemetry,
    time_plugin_call,
)

TEST_LOGGER_NAME = "test.plugin_telemetry"


def _logger():
    return logging.getLogger(TEST_LOGGER_NAME)


def test_time_plugin_call_records_success(caplog):
    """Brief: A successful hook call is recorded with success=True and returns.

    Inputs:
      - None
    Outputs:
      - None; asserts the record fields and pass-through return value.
    """

    records = []
    result = time_plugin_call(records, "FastPlugin", lambda: 42)
    assert result == 42
    assert len(records) == 1
    rec = records[0]
    assert isinstance(rec, PluginExecution)
    assert rec.plugin_name == "FastPlugin"
    assert rec.success is True
    assert rec.error_message is None
    assert rec.duration_ms >= 0.0


def test_time_plugin_call_records_failure_and_reraises():
    """Brief: A raising hook records success=False and re-raises unchanged.

    Inputs:
      - None
    Outputs:
      - None; asserts the record fields and that the exception propagates.
    """

    records = []

    def boom():
        raise ValueError("boom")

    try:
        time_plugin_call(records, "BadPlugin", boom)
    except ValueError as exc:
        assert str(exc) == "boom"
    else:
        raise AssertionError("expected ValueError to propagate")

    assert len(records) == 1
    rec = records[0]
    assert rec.plugin_name == "BadPlugin"
    assert rec.success is False
    assert "ValueError" in rec.error_message
    assert "boom" in rec.error_message


def test_log_plugin_telemetry_debug_breakdown(caplog):
    """Brief: A completed chain logs one DEBUG line with per-plugin ms.

    Inputs:
      - None
    Outputs:
      - None; asserts the DEBUG breakdown content and ordering.
    """

    records = [
        PluginExecution("Alpha", 1.234, True),
        PluginExecution("Beta", 5.678, False, "TimeoutError: slow"),
    ]
    with caplog.at_level(logging.DEBUG, logger=TEST_LOGGER_NAME):
        log_plugin_telemetry(
            _logger(), "pre", "example.com.", records, slow_threshold_ms=100.0
        )

    lines = [r.getMessage() for r in caplog.records]
    telemetry = [line for line in lines if "resolve plugin telemetry" in line]
    assert len(telemetry) == 1
    line = telemetry[0]
    assert "[pre]" in line
    assert "example.com." in line
    assert "Alpha=1.23ms" in line
    assert "Beta=5.68ms" in line
    assert "(error:TimeoutError: slow)" in line
    # Records appear in execution order.
    assert line.index("Alpha=") < line.index("Beta=")


def test_log_plugin_telemetry_slow_warning(caplog):
    """Brief: Plugins over the threshold log a WARNING; others do not.

    Inputs:
      - None
    Outputs:
      - None; asserts exactly one WARNING naming only the slow plugin.
    """

    records = [
        PluginExecution("FastPlugin", 0.5, True),
        PluginExecution("SlowPlugin", 120.0, True),
    ]
    with caplog.at_level(logging.DEBUG, logger=TEST_LOGGER_NAME):
        log_plugin_telemetry(
            _logger(), "post", "example.com.", records, slow_threshold_ms=50.0
        )

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "SlowPlugin" in warnings[0]
    assert "in post chain" in warnings[0]
    assert "50.0ms threshold" in warnings[0]
    assert "FastPlugin" not in warnings[0]


def test_log_plugin_telemetry_empty_records_noop(caplog):
    """Brief: An empty record list emits nothing.

    Inputs:
      - None
    Outputs:
      - None; asserts no records were logged.
    """

    with caplog.at_level(logging.DEBUG, logger=TEST_LOGGER_NAME):
        log_plugin_telemetry(_logger(), "pre", "example.com.", [])
    assert caplog.records == []


def test_get_slow_plugin_threshold_env(monkeypatch):
    """Brief: FOGHORN_SLOW_PLUGIN_MS overrides the default; bad values fall back.

    Inputs:
      - None
    Outputs:
      - None; asserts threshold resolution order.
    """

    monkeypatch.setenv("FOGHORN_SLOW_PLUGIN_MS", "123")
    assert get_slow_plugin_threshold_ms() == 123.0
    monkeypatch.setenv("FOGHORN_SLOW_PLUGIN_MS", "bogus")
    assert get_slow_plugin_threshold_ms() == DEFAULT_SLOW_PLUGIN_THRESHOLD_MS
    monkeypatch.delenv("FOGHORN_SLOW_PLUGIN_MS")
    assert get_slow_plugin_threshold_ms() == DEFAULT_SLOW_PLUGIN_THRESHOLD_MS
    # Explicit value always wins over the environment.
    monkeypatch.setenv("FOGHORN_SLOW_PLUGIN_MS", "123")
    assert get_slow_plugin_threshold_ms(explicit=5.0) == 5.0


def test_resolve_query_bytes_logs_per_plugin_telemetry(
    monkeypatch, set_runtime_snapshot, caplog
):
    """Brief: A full query logs per-plugin ms breakdowns for pre and post chains.

    Inputs:
      - monkeypatch/set_runtime_snapshot/caplog fixtures.
    Outputs:
      - None; asserts resolution still works and both chain breakdowns appear.
    """

    name = "telemetry.example"
    q = DNSRecord.question(name, "A")
    reply = q.reply()
    reply.add_answer(RR(name, rdata=A("1.2.3.4"), ttl=33))

    class SlowPlugin:
        pre_priority = 5
        post_priority = 90

        def pre_resolve(self, qname, qtype, data, ctx):
            time.sleep(0.06)

        def post_resolve(self, qname, qtype, wire, ctx):
            return None

    class FastPlugin:
        pre_priority = 95
        post_priority = 5

        def pre_resolve(self, qname, qtype, data, ctx):
            return None

        def post_resolve(self, qname, qtype, wire, ctx):
            return None

    set_runtime_snapshot(
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        plugins=[SlowPlugin(), FastPlugin()],
        resolver_mode="forward",
        forward_local=False,
    )

    def fake_forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        return reply.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_forward)
    # 1ms threshold guarantees the sleeping plugin trips the slow warning.
    monkeypatch.setenv("FOGHORN_SLOW_PLUGIN_MS", "1")

    with caplog.at_level(logging.DEBUG, logger="foghorn.server"):
        wire = srv.resolve_query_bytes(q.pack(), "127.0.0.1")

    # Zero regression: resolution still produces a response.
    assert wire
    parsed = DNSRecord.parse(wire)
    assert parsed.header.rcode == 0

    texts = [rec.getMessage() for rec in caplog.records]
    pre_lines = [t for t in texts if "resolve plugin telemetry [pre]" in t]
    post_lines = [t for t in texts if "resolve plugin telemetry [post]" in t]
    assert len(pre_lines) == 1
    assert len(post_lines) == 1

    # Pre chain order follows pre_priority: SlowPlugin(5) then FastPlugin(95).
    assert pre_lines[0].index("SlowPlugin=") < pre_lines[0].index("FastPlugin=")
    # Post chain order follows post_priority: FastPlugin(5) then SlowPlugin(90).
    assert post_lines[0].index("FastPlugin=") < post_lines[0].index("SlowPlugin=")

    # Only the pre hook sleeps, so exactly one slow warning (pre chain).
    warnings = [t for t in texts if "Slow resolve plugin SlowPlugin" in t]
    assert len(warnings) == 1
    assert "in pre chain" in warnings[0]


def test_apply_pre_plugins_records_telemetry(set_runtime_snapshot, caplog):
    """Brief: DNSUDPHandler._apply_pre_plugins logs the pre chain on completion.

    Inputs:
      - set_runtime_snapshot/caplog fixtures.
    Outputs:
      - None; asserts a DEBUG breakdown line for the pre chain.
    """

    from foghorn.servers.udp_server import DNSUDPHandler

    class AllowPlugin:
        pre_priority = 50

        def pre_resolve(self, qname, qtype, data, ctx):
            return None

    h = DNSUDPHandler.__new__(DNSUDPHandler)
    h.plugins = [AllowPlugin()]

    with caplog.at_level(logging.DEBUG, logger="foghorn.server"):
        decision = h._apply_pre_plugins(None, "example.com.", 1, b"", None)

    assert decision is None
    texts = [rec.getMessage() for rec in caplog.records]
    pre_lines = [t for t in texts if "resolve plugin telemetry [pre]" in t]
    assert len(pre_lines) == 1
    assert "AllowPlugin=" in pre_lines[0]


def test_plugin_telemetry_enabled_default_info(monkeypatch):
    """Brief: Default INFO logging skips hot-path plugin timing.

    Inputs:
      - monkeypatch fixture.
    Outputs:
      - None; asserts enabled only for DEBUG or explicit env threshold.
    """

    from foghorn.servers.plugin_telemetry import plugin_telemetry_enabled

    monkeypatch.delenv("FOGHORN_SLOW_PLUGIN_MS", raising=False)
    # reset cache
    import foghorn.servers.plugin_telemetry as pt

    pt._cached_env_threshold_ms = None
    pt._cached_env_raw = None

    info_logger = logging.getLogger("test.plugin_telemetry.info")
    info_logger.setLevel(logging.INFO)
    assert plugin_telemetry_enabled(info_logger) is False

    debug_logger = logging.getLogger("test.plugin_telemetry.debug")
    debug_logger.setLevel(logging.DEBUG)
    assert plugin_telemetry_enabled(debug_logger) is True

    monkeypatch.setenv("FOGHORN_SLOW_PLUGIN_MS", "75")
    pt._cached_env_threshold_ms = None
    pt._cached_env_raw = None
    assert plugin_telemetry_enabled(info_logger) is True


def test_time_plugin_call_record_false_skips_allocation():
    """Brief: record=False invokes the hook without appending telemetry.

    Inputs:
      - None
    Outputs:
      - None; asserts empty records and pass-through return.
    """

    records = []
    assert time_plugin_call(records, "X", lambda: 7, record=False) == 7
    assert records == []
