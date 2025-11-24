"""
Brief: Extra tests for EtcHosts plugin edge cases and response correctness.

Inputs:
  - None

Outputs:
  - None
"""

import importlib
import threading

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.base import PluginContext


def test_pre_resolve_override_response_id_matches(tmp_path):
    """
    Brief: Override response preserves the original query transaction ID.

    Inputs:
      - hosts file with a single mapping; A query

    Outputs:
      - None: asserts response header.id equals request header.id
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("10.0.0.1 example.local\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    q = DNSRecord.question("example.local", "A")
    req_wire = q.pack()
    decision = plugin.pre_resolve("example.local", QTYPE.A, req_wire, ctx)
    assert decision is not None and decision.response is not None

    resp = DNSRecord.parse(decision.response)
    assert resp.header.id == q.header.id


def test_pre_resolve_parse_failure_returns_override_with_none_response(tmp_path):
    """
    Brief: When request wire cannot be parsed, override response is None.

    Inputs:
      - invalid raw request bytes with matching hostname

    Outputs:
      - None: asserts override decision with response is None
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("192.0.2.1 broken.local\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    decision = plugin.pre_resolve("broken.local", QTYPE.A, b"not-a-dns-wire", ctx)
    assert decision is not None
    assert decision.action == "override"
    assert decision.response is None


def test_load_hosts_without_lock_sets_mapping(tmp_path):
    """Brief: _load_hosts populates hosts when no _hosts_lock is present.

    Inputs:
      - tmp_path: Temporary directory for a simple hosts file.

    Outputs:
      - None; asserts mapping is assigned without using a lock.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("10.0.0.1 no.lock.local\n", encoding="utf-8")

    # Construct bare instance without running setup so _hosts_lock is absent.
    plugin = EtcHosts.__new__(EtcHosts)  # type: ignore[call-arg]
    plugin.file_paths = [str(hosts_file)]

    # _load_hosts should fall back to assigning self.hosts directly.
    plugin._load_hosts()
    assert plugin.hosts["no.lock.local"] == "10.0.0.1"


def test_pre_resolve_without_lock_uses_plain_hosts_lookup():
    """Brief: pre_resolve uses direct hosts mapping when _hosts_lock is missing.

    Inputs:
      - None; uses a synthetic plugin instance with hosts mapping only.

    Outputs:
      - None; asserts that missing qname returns None without errors.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    plugin = EtcHosts.__new__(EtcHosts)  # type: ignore[call-arg]
    plugin.hosts = {"known.local": "10.0.0.1"}
    ctx = PluginContext(client_ip="127.0.0.1")

    # Query a name that is not in hosts; ip lookup still exercises lock-is-None path.
    decision = plugin.pre_resolve("missing.local", QTYPE.A, b"\x00\x00", ctx)
    assert decision is None


def test_watchdog_handler_should_reload_variants(tmp_path):
    """Brief: _WatchdogHandler._should_reload handles empty and matching paths.

    Inputs:
      - tmp_path: Temporary directory for watched file path.

    Outputs:
      - None; asserts False for empty paths and True when src/dest matches.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    watched = tmp_path / "hosts"
    watched.write_text("127.0.0.1 watched.local\n", encoding="utf-8")

    plugin = EtcHosts(file_paths=[str(watched)], watchdog_enabled=False)
    plugin.setup()

    handler = plugin._WatchdogHandler(plugin, [watched])

    # Neither src nor dest provided -> no reload.
    assert handler._should_reload(None, None) is False

    # Non-matching path -> False.
    assert handler._should_reload(str(tmp_path / "other"), None) is False

    # Matching dest path -> True.
    assert handler._should_reload(None, str(watched)) is True

    plugin.close()


def test_start_watchdog_no_observer_logs_warning(monkeypatch, tmp_path, caplog):
    """Brief: _start_watchdog logs warning and sets observer None when Observer is missing.

    Inputs:
      - monkeypatch/caplog/tmp_path fixtures.

    Outputs:
      - None; asserts observer is None and warning message emitted.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 example.local\n", encoding="utf-8")

    plugin = EtcHosts(file_paths=[str(hosts_file)], watchdog_enabled=False)
    plugin.setup()

    # Force Observer to None to exercise early-return branch.
    monkeypatch.setattr(mod, "Observer", None, raising=False)

    caplog.set_level("WARNING", logger=mod.__name__)
    plugin._start_watchdog()

    assert plugin._observer is None
    assert any(
        "automatic /etc/hosts reload disabled" in r.getMessage() for r in caplog.records
    )


def test_schedule_debounced_reload_immediate_and_existing_timer(monkeypatch, caplog):
    """Brief: _schedule_debounced_reload handles delay<=0 and existing timers.

    Inputs:
      - monkeypatch/caplog fixtures.

    Outputs:
      - None; asserts immediate reload call and that a live timer prevents reschedule.
    """

    import importlib
    from types import SimpleNamespace

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    # Synthetic instance with a reload counter
    plugin = EtcHosts.__new__(EtcHosts)  # type: ignore[call-arg]
    calls = {"reload": 0}

    def fake_reload() -> None:
        calls["reload"] += 1

    plugin._reload_hosts_from_watchdog = fake_reload  # type: ignore[assignment]

    # delay <= 0 -> immediate reload
    plugin._schedule_debounced_reload(0.0)
    assert calls["reload"] == 1

    # Next, configure a dummy lock and an existing live timer object
    plugin._reload_timer_lock = threading.Lock()
    live_timer = SimpleNamespace(is_alive=lambda: True)
    plugin._reload_debounce_timer = live_timer

    # delay > 0 but existing timer is_alive -> should not schedule another reload
    plugin._schedule_debounced_reload(1.0)
    assert calls["reload"] == 1


def test_close_stops_polling_and_cancels_timer(monkeypatch):
    """Brief: close() stops poll thread and cancels any outstanding timer.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts poll_stop Event set, thread joined, and timer cancelled.
    """

    import importlib
    from types import SimpleNamespace

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    plugin = EtcHosts.__new__(EtcHosts)  # type: ignore[call-arg]

    class DummyThread:
        def __init__(self) -> None:
            self.join_called = False

        def join(self, timeout: float) -> None:  # noqa: ARG002
            self.join_called = True

    # Populate attributes expected by close()
    plugin._observer = None
    plugin._poll_stop = threading.Event()
    thread = DummyThread()
    plugin._poll_thread = thread
    cancelled = {"called": False}

    class DummyTimer:
        def cancel(self) -> None:
            cancelled["called"] = True

    plugin._reload_debounce_timer = DummyTimer()

    plugin.close()

    assert plugin._poll_stop.is_set() is True
    assert thread.join_called is True
    assert cancelled["called"] is True
