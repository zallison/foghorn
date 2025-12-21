import importlib
import os
import pathlib
import threading

import pytest
from dnslib import QTYPE, RCODE, DNSRecord

from foghorn.plugins.base import PluginContext


def _make_query(name: str, qtype: int) -> bytes:
    """Create a minimal DNS query for the given name and qtype.

    Inputs:
      name: Domain name to query.
      qtype: Numeric DNS record type code.

    Outputs:
      Raw DNS query bytes suitable for passing to CustomRecords.pre_resolve.
    """
    # dnslib expects the qtype either as a mnemonic string (e.g. "A") or as a
    # QTYPE instance; when we receive the numeric code, map it back to its
    # mnemonic for constructing the question.
    qtype_name = QTYPE.get(qtype, str(qtype))
    q = DNSRecord.question(name, qtype=qtype_name)
    return q.pack()


def test_load_records_uniques_and_preserves_order_single_file(
    tmp_path: pathlib.Path,
) -> None:
    """CustomRecords._load_records keeps first TTL and value order from a single file.

    Inputs:
      tmp_path: pytest-provided temporary directory.

    Outputs:
      Asserts that duplicate values are dropped while preserving the order of
      first occurrences and the initial TTL.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                "example.com|A|300|1.1.1.1",
                "example.com|A|300|2.2.2.2",
                # Duplicate value with a different TTL; should be ignored.
                "example.com|A|600|1.1.1.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    key = ("example.com", int(QTYPE.A))
    ttl, values = plugin.records[key]

    assert ttl == 300
    assert values == ["1.1.1.1", "2.2.2.2"]


def test_load_records_across_multiple_files_order_and_dedup(
    tmp_path: pathlib.Path,
) -> None:
    """Values from multiple files are merged in config order with later dups dropped.

    Inputs:
      tmp_path: pytest temporary directory fixture.

    Outputs:
      Asserts that values appear in order of first definition across files and
      that later duplicates do not change TTL or ordering.
    """
    f1 = tmp_path / "records1.txt"
    f2 = tmp_path / "records2.txt"

    f1.write_text(
        "\n".join(
            [
                "example.com|A|100|1.1.1.1",
                "example.com|A|100|2.2.2.2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    f2.write_text(
        "\n".join(
            [
                # New value should be appended after existing ones.
                "example.com|A|200|3.3.3.3",
                # Duplicate of an earlier value with different TTL; ignored.
                "example.com|A|400|2.2.2.2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(f1), str(f2)])
    plugin.setup()

    key = ("example.com", int(QTYPE.A))
    ttl, values = plugin.records[key]

    # TTL comes from the first occurrence, and values follow their first
    # appearance order across files.
    assert ttl == 100
    assert values == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_pre_resolve_uses_value_order_from_config(tmp_path: pathlib.Path) -> None:
    """pre_resolve answers follow the order of values defined in the records files.

    Inputs:
      tmp_path: pytest temporary directory fixture.

    Outputs:
      Asserts that the order of A records in the DNS answer matches the order
      of values from the records file.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                "ordered.example|A|300|2.2.2.2",
                "ordered.example|A|300|1.1.1.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req_bytes = _make_query("ordered.example", int(QTYPE.A))

    decision = plugin.pre_resolve("ordered.example", int(QTYPE.A), req_bytes, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    ips = [str(a.rdata) for a in response.rr if a.rtype == QTYPE.A]

    # The answers must appear in the same order as in the config file.
    assert ips == ["2.2.2.2", "1.1.1.1"]


def test_normalize_paths_raises_when_no_paths(tmp_path: pathlib.Path) -> None:
    """Brief: _normalize_paths and setup() fail when neither file_path nor file_paths are provided.

    Inputs:
      - tmp_path: pytest temporary directory (unused but kept for consistency).

    Outputs:
      - Asserts that ValueError is raised when no paths are configured.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords()
    with pytest.raises(ValueError):
        plugin.setup()


def test_load_records_skips_blank_and_comment_lines(tmp_path: pathlib.Path) -> None:
    """Brief: _load_records ignores empty and comment-only lines.

    Inputs:
      - tmp_path: pytest-provided temporary directory.

    Outputs:
      - Asserts that only valid record lines contribute entries.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                "   # comment-only line",
                "",
                "example.com|A|300|1.1.1.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    key = ("example.com", int(QTYPE.A))
    ttl, values = plugin.records[key]

    assert ttl == 300
    assert values == ["1.1.1.1"]


def test_load_records_malformed_line_wrong_field_count(tmp_path: pathlib.Path) -> None:
    """Brief: _load_records raises ValueError when a line does not have four fields.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a ValueError is raised for malformed lines.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("bad-line-without-separators\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    with pytest.raises(ValueError):
        plugin.setup()


def test_load_records_malformed_line_empty_field(tmp_path: pathlib.Path) -> None:
    """Brief: _load_records raises ValueError when any of the four fields is empty.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a ValueError is raised for lines with empty fields.
    """
    records_file = tmp_path / "records.txt"
    # Empty value field after the last '|'.
    records_file.write_text("example.com|A|300|\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    with pytest.raises(ValueError):
        plugin.setup()


def test_load_records_qtype_numeric_and_negative_ttl(tmp_path: pathlib.Path) -> None:
    """Brief: _load_records accepts numeric qtype but rejects negative TTL values.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a ValueError is raised when TTL is negative even with numeric qtype.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|1|-10|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    with pytest.raises(ValueError):
        plugin.setup()


def test_load_records_invalid_ttl_non_integer(tmp_path: pathlib.Path) -> None:
    """Brief: _load_records rejects TTL values that cannot be parsed as integers.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a ValueError is raised for non-integer TTL.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|abc|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    with pytest.raises(ValueError):
        plugin.setup()


def test_load_records_qtype_fallback_to_get_int(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: _load_records uses QTYPE.get when getattr raises AttributeError.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that qtype_code is taken from QTYPE.get when it returns an int.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|FOO|300|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.zone-records")

    class DummyQType:
        def __getattr__(self, name: str) -> int:
            raise AttributeError(name)

        def get(self, name, default=None):  # type: ignore[override]
            return 42

    monkeypatch.setattr(mod, "QTYPE", DummyQType())
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    key = ("example.com", 42)
    assert key in plugin.records


def test_load_records_qtype_unknown_raises(monkeypatch, tmp_path: pathlib.Path) -> None:
    """Brief: _load_records raises ValueError when QTYPE.get does not return an int.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a ValueError is raised when qtype_code would be None.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|BAR|300|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.zone-records")

    class DummyQType:
        def __getattr__(self, name: str) -> int:
            raise AttributeError(name)

        def get(self, name, default=None):  # type: ignore[override]
            return "NOT_INT"

    monkeypatch.setattr(mod, "QTYPE", DummyQType())
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    with pytest.raises(ValueError):
        plugin.setup()


def test_load_records_assigns_without_lock(tmp_path: pathlib.Path) -> None:
    """Brief: _load_records assigns records directly when no _records_lock is present.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that records are populated even when _records_lock is None.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    # Remove the lock and force a reload to exercise the lock-is-None path.
    plugin._records_lock = None  # type: ignore[assignment]
    plugin._load_records()

    assert plugin.records[("example.com", int(QTYPE.A))][1] == ["1.2.3.4"]


def test_pre_resolve_no_entry_and_no_lock(tmp_path: pathlib.Path) -> None:
    """Brief: pre_resolve returns None and logs when no records entry exists.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that pre_resolve returns None when key is missing and _records_lock is None.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    # Remove lock so we exercise the lock-is-None branch.
    plugin._records_lock = None  # type: ignore[assignment]

    ctx = PluginContext(client_ip="127.0.0.1")
    req_bytes = _make_query("other.example", int(QTYPE.A))

    decision = plugin.pre_resolve("other.example", int(QTYPE.A), req_bytes, ctx)
    assert decision is None


def test_pre_resolve_returns_none_when_rr_parsing_fails(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: pre_resolve returns None when RR.fromZone raises for all values.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that no override decision is made when answers cannot be built.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    # Force RR.fromZone to fail so that no answers are added.
    monkeypatch.setattr(
        mod,
        "RR",
        type(
            "_RR",
            (),
            {
                "fromZone": staticmethod(
                    lambda zone: (_ for _ in ()).throw(RuntimeError("bad"))
                )
            },
        ),
    )

    ctx = PluginContext(client_ip="127.0.0.1")
    req_bytes = _make_query("example.com", int(QTYPE.A))

    decision = plugin.pre_resolve("example.com", int(QTYPE.A), req_bytes, ctx)
    assert decision is None


def test_watchdog_handler_should_reload_and_on_any_event(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: _WatchdogHandler only reloads for matching file events.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts _should_reload and on_any_event behaviour for various event shapes.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")
    watched = [records_file]

    class DummyPlugin:
        def __init__(self) -> None:
            self.reloaded = 0

        def _reload_records_from_watchdog(self) -> None:
            self.reloaded += 1

    plugin = DummyPlugin()
    handler = ZoneRecords._WatchdogHandler(plugin, watched)

    # No paths -> False
    assert handler._should_reload(None, None) is False

    # Unrelated path -> False
    assert handler._should_reload("/not/watched", None) is False

    # Matching source path -> True
    assert handler._should_reload(str(records_file), None) is True

    class Event:
        def __init__(
            self,
            is_directory: bool,
            event_type: str,
            src_path: str | None = None,
            dest_path: str | None = None,
        ) -> None:
            self.is_directory = is_directory
            self.event_type = event_type
            self.src_path = src_path
            self.dest_path = dest_path

    # Directory events are ignored.
    handler.on_any_event(
        Event(is_directory=True, event_type="modified", src_path=str(records_file))
    )
    assert plugin.reloaded == 0

    # Unsupported event types are ignored.
    handler.on_any_event(
        Event(is_directory=False, event_type="deleted", src_path=str(records_file))
    )
    assert plugin.reloaded == 0

    # Supported event type with matching path triggers reload.
    handler.on_any_event(
        Event(is_directory=False, event_type="modified", src_path=str(records_file))
    )
    assert plugin.reloaded == 1


def test_start_watchdog_observer_none(monkeypatch, tmp_path: pathlib.Path) -> None:
    """Brief: _start_watchdog logs and disables observer when Observer is None.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that _observer is left as None when Observer is unavailable.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(records_file)], watchdog_enabled=False)
    plugin.setup()

    # Force Observer to be treated as unavailable.
    monkeypatch.setattr(mod, "Observer", None)

    plugin._start_watchdog()
    assert getattr(plugin, "_observer", None) is None


def test_start_watchdog_with_no_directories(monkeypatch) -> None:
    """Brief: _start_watchdog returns early when there are no directories to watch.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.

    Outputs:
      - Asserts that _observer is set to None when file_paths is empty.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    # Construct a bare instance without going through __init__ to allow empty file_paths.
    plugin = ZoneRecords.__new__(ZoneRecords)
    plugin.file_paths = []  # type: ignore[assignment]
    plugin._observer = None  # type: ignore[assignment]

    # Force Observer to be a dummy sentinel so we can see if it would be used.
    class DummyObserver:
        def __init__(self) -> None:
            self.started = False

        def start(self) -> None:
            self.started = True

    monkeypatch.setattr(mod, "Observer", DummyObserver)

    plugin._start_watchdog()
    # When there are no concrete directories to watch, _observer remains None.
    assert plugin._observer is None


def test_start_polling_configuration(monkeypatch, tmp_path: pathlib.Path) -> None:
    """Brief: _start_polling only starts a thread when interval and stop_event are set.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that polling thread is only started when both interval and stop_event are set.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    # Disabled polling: interval <= 0
    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()
    plugin._poll_interval = 0.0  # type: ignore[assignment]
    plugin._poll_stop = threading.Event()
    plugin._start_polling()
    assert getattr(plugin, "_poll_thread", None) is None

    # Interval set but no stop_event configured -> no thread
    plugin2 = ZoneRecords(file_paths=[str(records_file)])
    plugin2.setup()
    plugin2._poll_interval = 0.1  # type: ignore[assignment]
    plugin2._poll_stop = None  # type: ignore[assignment]
    plugin2._start_polling()
    assert getattr(plugin2, "_poll_thread", None) is None

    # Proper configuration starts a polling thread.
    plugin3 = ZoneRecords(
        file_paths=[str(records_file)], watchdog_poll_interval_seconds=0.01
    )
    plugin3.setup()
    assert getattr(plugin3, "_poll_thread", None) is not None
    plugin3.close()


def test_poll_loop_early_return_and_iteration(tmp_path: pathlib.Path) -> None:
    """Brief: _poll_loop returns early when misconfigured and loops once when configured.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts both the early-return and single-iteration behaviours.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(records_file)])
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


def test_have_files_changed_tracks_snapshot(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: _have_files_changed builds snapshots and detects changes.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that the first call returns True and subsequent identical stats return False.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    missing = tmp_path / "missing.txt"

    real_stat = os.stat

    def fake_stat(path: str):
        if path == str(missing):
            raise FileNotFoundError
        if path.endswith("error.txt"):
            raise OSError("boom")
        return real_stat(path)

    extra = tmp_path / "error.txt"
    extra.write_text("ignore\n", encoding="utf-8")

    plugin.file_paths = [str(records_file), str(missing), str(extra)]  # type: ignore[assignment]

    monkeypatch.setattr(mod.os, "stat", fake_stat)

    # First call establishes snapshot.
    assert plugin._have_files_changed() is True
    # Second call with same stats returns False.
    assert plugin._have_files_changed() is False


def test_schedule_debounced_reload_variants(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: _schedule_debounced_reload covers immediate, lock-less, and timer cases.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that reload is called immediately for zero delay and scheduled via Timer otherwise.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    called = {"count": 0}

    def fake_reload() -> None:
        called["count"] += 1

    plugin._reload_records_from_watchdog = fake_reload  # type: ignore[assignment]

    # Immediate path when delay <= 0.
    plugin._schedule_debounced_reload(0.0)
    assert called["count"] == 1

    # No lock configured -> no scheduling.
    plugin2 = ZoneRecords(file_paths=[str(records_file)])
    plugin2.setup()
    plugin2._reload_records_from_watchdog = fake_reload  # type: ignore[assignment]
    plugin2._reload_timer_lock = None  # type: ignore[assignment]
    plugin2._schedule_debounced_reload(1.0)
    assert called["count"] == 1

    # Existing live timer prevents new scheduling.
    class DummyTimer:
        def is_alive(self) -> bool:  # pragma: no cover - trivial.
            return True

    plugin3 = ZoneRecords(file_paths=[str(records_file)])
    plugin3.setup()
    plugin3._reload_records_from_watchdog = fake_reload  # type: ignore[assignment]
    plugin3._reload_timer_lock = threading.Lock()  # type: ignore[assignment]
    plugin3._reload_debounce_timer = DummyTimer()  # type: ignore[assignment]
    plugin3._schedule_debounced_reload(1.0)
    assert called["count"] == 1

    # Normal scheduling path with Timer replacement that calls callback immediately.
    calls = {"timer_cb": 0}

    def make_timer(delay, cb):  # type: ignore[override]
        class ImmediateTimer:
            def __init__(self) -> None:
                self.delay = delay
                self._cb = cb

            def is_alive(self) -> bool:  # pragma: no cover - not used in this branch.
                return False

            def start(self) -> None:
                cb()

            @property
            def daemon(self) -> bool:  # pragma: no cover - attribute only.
                return True

            @daemon.setter
            def daemon(self, value: bool) -> None:  # pragma: no cover - ignore.
                pass

        calls["timer_cb"] += 1
        return ImmediateTimer()

    monkeypatch.setattr(mod.threading, "Timer", make_timer)

    plugin4 = ZoneRecords(file_paths=[str(records_file)])
    plugin4.setup()
    plugin4._reload_records_from_watchdog = fake_reload  # type: ignore[assignment]
    plugin4._reload_timer_lock = threading.Lock()  # type: ignore[assignment]
    plugin4._schedule_debounced_reload(0.01)

    assert called["count"] >= 2
    assert calls["timer_cb"] == 1


def test_reload_records_from_watchdog_deferred_and_immediate(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: _reload_records_from_watchdog both defers and immediately reloads.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that short intervals schedule a deferred reload and long ones call _load_records.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    # Deferred path: elapsed < min_interval. Use a fixed time source for determinism.
    monkeypatch.setattr(mod.time, "time", lambda: 105.0)
    plugin._last_watchdog_reload_ts = 100.0  # type: ignore[assignment]
    plugin._watchdog_min_interval = 10.0  # type: ignore[assignment]

    scheduled = {"delay": None}

    def fake_schedule(delay: float) -> None:
        scheduled["delay"] = delay

    plugin._schedule_debounced_reload = fake_schedule  # type: ignore[assignment]
    plugin._reload_records_from_watchdog()
    assert scheduled["delay"] is not None

    # Immediate path: elapsed >= min_interval causes an in-place reload.
    monkeypatch.setattr(mod.time, "time", lambda: 200.0)
    plugin._last_watchdog_reload_ts = 0.0  # type: ignore[assignment]
    called = {"load": 0}

    def fake_load() -> None:
        called["load"] += 1

    plugin._load_records = fake_load  # type: ignore[assignment]
    plugin._watchdog_min_interval = 0.0  # type: ignore[assignment]
    plugin._reload_records_from_watchdog()
    assert called["load"] == 1


def test_close_stops_observer_polling_and_timers() -> None:
    """Brief: close() stops observer, polling loop, and cancels timers.

    Inputs:
      - None.

    Outputs:
      - Asserts that observer, poll_thread, and debounce timer are cleared.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = object.__new__(ZoneRecords)

    class DummyObserver:
        def __init__(self) -> None:
            self.stopped = False
            self.joined = False

        def stop(self) -> None:
            self.stopped = True

        def join(self, timeout: float | None = None) -> None:
            self.joined = True

    class DummyEvent:
        def __init__(self) -> None:
            self.set_called = False

        def set(self) -> None:
            self.set_called = True

    class DummyThread:
        def __init__(self) -> None:
            self.join_called = False

        def join(self, timeout: float | None = None) -> None:
            self.join_called = True

    class DummyTimer:
        def __init__(self) -> None:
            self.cancel_called = False

        def cancel(self) -> None:
            self.cancel_called = True

    observer = DummyObserver()
    stop_event = DummyEvent()
    poll_thread = DummyThread()
    timer = DummyTimer()

    plugin._observer = observer  # type: ignore[assignment]
    plugin._poll_stop = stop_event  # type: ignore[assignment]
    plugin._poll_thread = poll_thread  # type: ignore[assignment]
    plugin._reload_debounce_timer = timer  # type: ignore[assignment]

    plugin.close()

    assert observer.stopped and observer.joined
    assert stop_event.set_called
    assert poll_thread.join_called
    assert plugin._observer is None  # type: ignore[attr-defined]
    assert plugin._poll_thread is None  # type: ignore[attr-defined]
    assert plugin._reload_debounce_timer is None  # type: ignore[attr-defined]


def test_setup_watchdog_enabled_flag_controls_start(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: setup() honours the watchdog_enabled configuration flag.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that _start_watchdog is only called when watchdog_enabled is truthy.
    """
    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    calls = {"start": 0}

    def fake_start(self) -> None:  # type: ignore[override]
        calls["start"] += 1

    monkeypatch.setattr(ZoneRecords, "_start_watchdog", fake_start, raising=False)

    # Explicitly disabled -> no call.
    plugin_disabled = ZoneRecords(
        file_paths=[str(records_file)], watchdog_enabled=False
    )
    plugin_disabled.setup()

    # Truthy non-bool value -> treated as True and calls _start_watchdog.
    plugin_enabled = ZoneRecords(file_paths=[str(records_file)], watchdog_enabled="yes")
    plugin_enabled.setup()

    assert calls["start"] == 1


def test_authoritative_zone_nxdomain_and_nodata(tmp_path: pathlib.Path) -> None:
    """CustomRecords behaves authoritatively inside a zone with SOA.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts NXDOMAIN for a missing name under the zone, and NOERROR/NODATA
        with SOA in the authority section for an existing name with a
        different RR type.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                # Zone apex SOA defines authoritative zone example.com.
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                # Apex A record.
                "example.com|A|300|192.0.2.10",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # NXDOMAIN for a name inside the zone that has no RRsets.
    req_nx = _make_query("missing.example.com", int(QTYPE.A))
    decision_nx = plugin.pre_resolve("missing.example.com", int(QTYPE.A), req_nx, ctx)
    assert decision_nx is not None
    assert decision_nx.action == "override"
    resp_nx = DNSRecord.parse(decision_nx.response)
    assert resp_nx.header.rcode == RCODE.NXDOMAIN
    # Apex SOA should be present in the authority section.
    assert any(rr.rtype == QTYPE.SOA for rr in (resp_nx.auth or []))

    # NODATA for apex name when querying a type that does not exist.
    req_nodata = _make_query("example.com", int(QTYPE.TXT))
    decision_nodata = plugin.pre_resolve("example.com", int(QTYPE.TXT), req_nodata, ctx)
    assert decision_nodata is not None
    assert decision_nodata.action == "override"
    resp_nodata = DNSRecord.parse(decision_nodata.response)
    assert resp_nodata.header.rcode == RCODE.NOERROR
    # No answers but SOA should be in authority.
    assert not resp_nodata.rr
    assert any(rr.rtype == QTYPE.SOA for rr in (resp_nodata.auth or []))


def test_authoritative_cname_and_any_semantics(tmp_path: pathlib.Path) -> None:
    """CNAME at a name answers all qtypes; ANY returns all RRsets.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that CNAME answers for A and ANY when present, and that ANY
        without CNAME returns all RRsets at the name.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                # A pure CNAME owner inside the zone.
                "www.example.com|CNAME|300|target.example.com.",
                # A multi-RRset owner for ANY behaviour.
                "multi.example.com|A|300|192.0.2.1",
                "multi.example.com|AAAA|300|2001:db8::1",
                'multi.example.com|TXT|300|"hello"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.zone-records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # A query to CNAME owner should yield a CNAME answer.
    req_cname_a = _make_query("www.example.com", int(QTYPE.A))
    decision_cname_a = plugin.pre_resolve(
        "www.example.com", int(QTYPE.A), req_cname_a, ctx
    )
    assert decision_cname_a is not None
    resp_cname_a = DNSRecord.parse(decision_cname_a.response)
    assert any(rr.rtype == QTYPE.CNAME for rr in resp_cname_a.rr)

    # ANY query to the same owner should also yield CNAME only.
    req_cname_any = _make_query("www.example.com", int(QTYPE.ANY))
    decision_cname_any = plugin.pre_resolve(
        "www.example.com", int(QTYPE.ANY), req_cname_any, ctx
    )
    assert decision_cname_any is not None
    resp_cname_any = DNSRecord.parse(decision_cname_any.response)
    assert resp_cname_any.header.rcode == RCODE.NOERROR
    assert resp_cname_any.rr
    assert all(rr.rtype == QTYPE.CNAME for rr in resp_cname_any.rr)

    # ANY query to a multi-RRset owner should return all RR types.
    req_multi_any = _make_query("multi.example.com", int(QTYPE.ANY))
    decision_multi_any = plugin.pre_resolve(
        "multi.example.com", int(QTYPE.ANY), req_multi_any, ctx
    )
    assert decision_multi_any is not None
    resp_multi_any = DNSRecord.parse(decision_multi_any.response)
    types = {rr.rtype for rr in resp_multi_any.rr}
    assert QTYPE.A in types
    assert QTYPE.AAAA in types
    assert QTYPE.TXT in types
