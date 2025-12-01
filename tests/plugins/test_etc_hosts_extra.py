"""
Brief: Extra tests for EtcHosts plugin edge cases and response correctness.

Inputs:
  - None

Outputs:
  - None
"""

import importlib
import os
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


def test_load_hosts_valueerror_in_reverse_mapping_is_ignored(tmp_path):
    """Brief: _load_hosts handles ValueError when building reverse mapping.

    Inputs:
      - tmp_path: Temporary directory for a crafted hosts file.

    Outputs:
      - None; asserts that a ValueError during reverse mapping does not break loading.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    # Use a Unicode digit in the second octet: isdigit() returns True, but int() fails,
    # triggering the ValueError path in reverse mapping without patching builtins.
    hosts_file.write_text(
        "10.0.0.1 ok.local\n1.①.2.3 bad.local\n",
        encoding="utf-8",
    )

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()

    # Forward mappings are still populated.
    assert plugin.hosts["ok.local"] == "10.0.0.1"
    assert plugin.hosts["bad.local"] == "1.①.2.3"

    # Reverse mapping for the malformed IPv4 is not created due to ValueError.
    assert "3.2.①.1.in-addr.arpa" not in plugin.hosts


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
    # Mimic BasePlugin.__init__ targeting defaults so targets() fast-path works.
    plugin._target_networks = []  # type: ignore[attr-defined]
    plugin._ignore_networks = []  # type: ignore[attr-defined]
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


def test_start_watchdog_with_no_directories(monkeypatch):
    """Brief: _start_watchdog returns early when there are no directories to watch.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that _observer stays None when file_paths is empty.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    plugin = EtcHosts.__new__(EtcHosts)  # type: ignore[call-arg]
    plugin.file_paths = []  # type: ignore[assignment]

    class DummyObserver:
        def __init__(self) -> None:  # pragma: no cover - trivial stub
            pass

    monkeypatch.setattr(mod, "Observer", DummyObserver, raising=False)

    plugin._start_watchdog()
    assert getattr(plugin, "_observer", None) is None


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

    # Case: delay > 0 but no lock configured -> no scheduling or reload.
    plugin_no_lock = EtcHosts.__new__(EtcHosts)  # type: ignore[call-arg]
    plugin_no_lock._reload_hosts_from_watchdog = fake_reload  # type: ignore[assignment]
    plugin_no_lock._reload_timer_lock = None  # type: ignore[assignment]
    plugin_no_lock._schedule_debounced_reload(1.0)
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


def test_setup_enables_polling_when_interval_configured(tmp_path):
    """Brief: setup() with watchdog_poll_interval_seconds starts polling thread.

    Inputs:
      - tmp_path: pytest temporary directory for a simple hosts file.

    Outputs:
      - None; asserts that poll_stop Event and poll_thread are created.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 polling.local\n", encoding="utf-8")

    plugin = EtcHosts(
        file_path=str(hosts_file),
        watchdog_enabled=False,
        watchdog_poll_interval_seconds=0.01,
    )
    plugin.setup()

    assert getattr(plugin, "_poll_interval", 0.0) > 0.0
    assert getattr(plugin, "_poll_stop", None) is not None
    assert getattr(plugin, "_poll_thread", None) is not None

    plugin.close()


def test_start_polling_variants_for_etc_hosts(tmp_path):
    """Brief: _start_polling handles disabled, missing-stop, and enabled cases.

    Inputs:
      - tmp_path: pytest temporary directory for a simple hosts file.

    Outputs:
      - None; asserts that threads are only started when both interval and stop_event are set.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 polling2.local\n", encoding="utf-8")

    plugin = EtcHosts(file_path=str(hosts_file), watchdog_enabled=False)
    plugin.setup()

    # Disabled polling: interval <= 0
    plugin._poll_interval = 0.0  # type: ignore[assignment]
    plugin._poll_stop = threading.Event()
    plugin._poll_thread = None  # type: ignore[assignment]
    plugin._start_polling()
    assert getattr(plugin, "_poll_thread", None) is None

    # Interval set but no stop_event configured -> no thread
    plugin._poll_interval = 0.1  # type: ignore[assignment]
    plugin._poll_stop = None  # type: ignore[assignment]
    plugin._poll_thread = None  # type: ignore[assignment]
    plugin._start_polling()
    assert getattr(plugin, "_poll_thread", None) is None

    # Proper configuration starts a polling thread.
    plugin._poll_interval = 0.01  # type: ignore[assignment]
    plugin._poll_stop = threading.Event()
    plugin._start_polling()
    assert getattr(plugin, "_poll_thread", None) is not None
    plugin.close()


def test_poll_loop_early_return_and_iteration(tmp_path):
    """Brief: _poll_loop returns early when misconfigured and loops once when configured.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - None; asserts both the early-return and single-iteration behaviours.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 poll.local\n", encoding="utf-8")

    plugin = EtcHosts(file_path=str(hosts_file), watchdog_enabled=False)
    plugin.setup()

    # Early return when stop_event is None.
    plugin._poll_stop = None  # type: ignore[assignment]
    plugin._poll_interval = 0.1  # type: ignore[assignment]
    plugin._poll_loop()

    # Single iteration when configured; have_files_changed clears the stop event.
    stop = threading.Event()
    plugin._poll_stop = stop  # type: ignore[assignment]
    plugin._poll_interval = 0.01  # type: ignore[assignment]

    def fake_have_files_changed() -> bool:
        stop.set()
        return False

    plugin._have_files_changed = fake_have_files_changed  # type: ignore[assignment]
    plugin._poll_loop()


def test_have_files_changed_handles_missing_and_oserror(monkeypatch, tmp_path):
    """Brief: _have_files_changed handles FileNotFoundError and OSError gracefully.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: temporary directory for existing/missing/error files.

    Outputs:
      - None; asserts that snapshots are recorded even when stat() fails.
    """

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 existing.local\n", encoding="utf-8")

    plugin = EtcHosts(file_path=str(hosts_file), watchdog_enabled=False)
    plugin.setup()

    missing = tmp_path / "missing"
    error = tmp_path / "error"
    error.write_text("boom\n", encoding="utf-8")

    real_stat = os.stat

    def fake_stat(path: str):
        if path == str(missing):
            raise FileNotFoundError
        if path == str(error):
            raise OSError("boom")
        return real_stat(path)

    plugin.file_paths = [str(hosts_file), str(missing), str(error)]  # type: ignore[assignment]

    monkeypatch.setattr(os, "stat", fake_stat)

    # First call establishes snapshot.
    assert plugin._have_files_changed() is True
    # Second call with same stats returns False.
    assert plugin._have_files_changed() is False
