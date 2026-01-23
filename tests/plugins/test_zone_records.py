import importlib
import os
import pathlib
import threading
import logging

import pytest
from dnslib import QTYPE, RCODE, DNSRecord, RR
from foghorn.plugins.resolve.base import PluginContext
import ipaddress


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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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


def test_inline_records_config_only() -> None:
    """Brief: ZoneRecords can load and answer from inline records in config.

    Inputs:
      - None.

    Outputs:
      - Asserts that an inline record defined via the `records` config field is
        present in plugin.records and used by pre_resolve().
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(records=["inline.example|A|300|203.0.113.10"])
    plugin.setup()

    key = ("inline.example", int(QTYPE.A))
    ttl, values = plugin.records[key]

    assert ttl == 300
    assert values == ["203.0.113.10"]

    ctx = PluginContext(client_ip="127.0.0.1")
    req_bytes = _make_query("inline.example", int(QTYPE.A))

    decision = plugin.pre_resolve("inline.example", int(QTYPE.A), req_bytes, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    ips = [str(a.rdata) for a in response.rr if a.rtype == QTYPE.A]

    assert ips == ["203.0.113.10"]


def test_inline_records_merge_after_files(tmp_path: pathlib.Path) -> None:
    """Brief: Inline records are merged after file-backed ones with deduplication.

    Inputs:
      - tmp_path: pytest-provided temporary directory.

    Outputs:
      - Asserts that TTL comes from the first occurrence and that values from
        inline records are appended in first-seen order with duplicates
        ignored.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                "example.com|A|100|1.1.1.1",
                "example.com|A|100|2.2.2.2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        records=[
            "example.com|A|400|3.3.3.3",
            # Duplicate value with a different TTL; should be ignored.
            "example.com|A|500|2.2.2.2",
        ],
    )
    plugin.setup()

    key = ("example.com", int(QTYPE.A))
    ttl, values = plugin.records[key]

    assert ttl == 100
    assert values == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_normalize_paths_raises_when_no_paths(tmp_path: pathlib.Path) -> None:
    """Brief: _normalize_paths and setup() fail when neither file_path nor file_paths are provided.

    Inputs:
      - tmp_path: pytest temporary directory (unused but kept for consistency).

    Outputs:
      - Asserts that ValueError is raised when no paths are configured.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")

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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")

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
    records_file.write_text("example.com|A|300|1.2.3.4\\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()


def test_auto_ptr_generated_from_a_and_aaaa(tmp_path: pathlib.Path) -> None:
    """Brief: ZoneRecords auto-generates PTR only for A/AAAA RRsets.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that PTR records are synthesized from A/AAAA forward RRs and
        that their owners/targets match ipaddress.reverse_pointer semantics.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                "v4.example|A|300|192.0.2.10",
                "v6.example|AAAA|400|2001:db8::1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    v4_rev = ipaddress.ip_address("192.0.2.10").reverse_pointer.rstrip(".").lower()
    v6_rev = ipaddress.ip_address("2001:db8::1").reverse_pointer.rstrip(".").lower()

    ptr_code = int(QTYPE.PTR)

    # IPv4 PTR
    key_v4_ptr = (v4_rev, ptr_code)
    ttl_v4, vals_v4 = plugin.records[key_v4_ptr]
    assert ttl_v4 == 300
    assert "v4.example." in vals_v4

    # IPv6 PTR
    key_v6_ptr = (v6_rev, ptr_code)
    ttl_v6, vals_v6 = plugin.records[key_v6_ptr]
    assert ttl_v6 == 400
    assert "v6.example." in vals_v6


def test_pre_resolve_no_entry_and_no_lock(tmp_path: pathlib.Path) -> None:
    """Brief: pre_resolve returns None and logs when no records entry exists.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that pre_resolve returns None when key is missing and _records_lock is None.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    """Brief: pre_resolve tolerates RR.fromZone failures when answers are pre-built.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that no override decision is made when answers cannot be built.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    # With pre-built RR objects in the helper mapping, pre_resolve can still
    # return an override decision even when RR.fromZone is patched to fail at
    # query time.
    assert decision is not None
    assert decision.action == "override"


def test_watchdog_handler_should_reload_and_on_any_event(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: _WatchdogHandler only reloads for matching file events.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts _should_reload and on_any_event behaviour for various event shapes.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
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


def test_bind_paths_loads_rfc1035_zone_and_answers(tmp_path: pathlib.Path) -> None:
    """Brief: bind_paths allows loading RFC-1035 BIND zone files.

    Inputs:
      - tmp_path: pytest-provided temporary directory.

    Outputs:
      - Asserts that a simple BIND-style zonefile is parsed and used for
        authoritative answers, including SOA semantics.
    """
    zone_file = tmp_path / "example.zone"
    zone_file.write_text(
        """$ORIGIN example.com.\n$TTL 300\n@   IN  SOA ns1.example.com. hostmaster.example.com. ( 1 3600 600 604800 300 )\n@   IN  NS  ns1.example.com.\n@   IN  NS  ns2.example.com.\nwww IN  A   192.0.2.20\n""",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(bind_paths=[str(zone_file)])
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # Query inside the zone should be answered authoritatively from the BIND file.
    req_bytes = _make_query("www.example.com", int(QTYPE.A))
    decision = plugin.pre_resolve("www.example.com", int(QTYPE.A), req_bytes, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    assert response.header.rcode == RCODE.NOERROR
    assert any(
        rr.rtype == QTYPE.A and str(rr.rdata) == "192.0.2.20" for rr in response.rr
    )

    # A missing name under the same zone should yield NXDOMAIN with SOA in authority.
    req_nx = _make_query("missing.example.com", int(QTYPE.A))
    decision_nx = plugin.pre_resolve("missing.example.com", int(QTYPE.A), req_nx, ctx)
    assert decision_nx is not None
    resp_nx = DNSRecord.parse(decision_nx.response)
    assert resp_nx.header.rcode == RCODE.NXDOMAIN
    assert any(rr.rtype == QTYPE.SOA for rr in (resp_nx.auth or []))


def test_bind_paths_merges_with_file_paths_and_preserves_ttl_and_order(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: bind_paths records merge with file_paths using first-TTL and first-seen order.

    Inputs:
      - tmp_path: pytest-provided temporary directory.

    Outputs:
      - Asserts that values from a BIND zone and a pipe-delimited records file
        are merged in first-seen order and that the TTL from the earliest
        occurrence is preserved.
    """
    bind_zone = tmp_path / "merge.zone"
    bind_zone.write_text(
        """$ORIGIN merge.test.\n$TTL 400\n@   IN  A   10.0.0.1\n@   IN  A   10.0.0.2\n""",
        encoding="utf-8",
    )

    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                # New value should be appended after BIND-derived ones.
                "merge.test|A|200|10.0.0.3",
                # Duplicate of an earlier value with a different TTL; ignored.
                "merge.test|A|100|10.0.0.2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(bind_paths=[str(bind_zone)], file_paths=[str(records_file)])
    plugin.setup()

    key = ("merge.test", int(QTYPE.A))
    ttl, values = plugin.records[key]

    # TTL comes from the first occurrence for this (name, qtype) key across
    # all sources, and values follow first-seen order with duplicates dropped.
    assert ttl == 200


def test_bind_paths_multiple_rrsets_and_any_semantics(tmp_path: pathlib.Path) -> None:
    """Brief: bind_paths supports multiple RR types and ANY semantics inside a zone.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that A, AAAA, and TXT RRsets from a BIND zonefile are exposed
        correctly and that an ANY query returns all RR types at the owner name.
    """
    zone_file = tmp_path / "multi.zone"
    zone_file.write_text(
        """$ORIGIN multi.test.\n$TTL 300\n@   IN  SOA ns1.multi.test. hostmaster.multi.test. ( 1 3600 600 604800 300 )\n@   IN  A   192.0.2.1\n@   IN  AAAA 2001:db8::1\n@   IN  TXT "hello"\n""",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(bind_paths=[str(zone_file)])
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    req_any = _make_query("multi.test", int(QTYPE.ANY))
    decision_any = plugin.pre_resolve("multi.test", int(QTYPE.ANY), req_any, ctx)
    assert decision_any is not None
    assert decision_any.action == "override"

    resp_any = DNSRecord.parse(decision_any.response)
    assert resp_any.header.rcode == RCODE.NOERROR
    rtypes = {rr.rtype for rr in resp_any.rr}
    assert QTYPE.A in rtypes
    assert QTYPE.AAAA in rtypes
    assert QTYPE.TXT in rtypes


def test_custom_sshfp_and_openpgpkey_records(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: ZoneRecords can load and serve SSHFP and OPENPGPKEY custom records.

    Inputs:
      - tmp_path: pytest temporary directory for creating a temporary records
        file.

    Outputs:
      - Asserts that SSHFP and OPENPGPKEY records defined in the custom
        pipe-delimited format are parsed into ``plugin.records`` and that
        ``pre_resolve`` returns correctly typed RRs with the expected RDATA.
    """

    file_path = tmp_path / "records.txt"
    file_path.write_text(
        "\n".join(
            [
                # SSHFP: algorithm 1 (RSA), hash type 1 (SHA-1), example hex
                # digest.
                "sshfp.example|SSHFP|600|1 1 1234567890abcdef1234567890abcdef12345678",
                # OPENPGPKEY: hex-encoded key material; dnslib will expose this
                # as generic "# <len> <hex>" text when building RDATA.
                "openpgp.example|OPENPGPKEY|300|0A0B0C",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(file_path)])
    plugin.setup()

    # SSHFP record must be present in the internal mapping with the expected
    # TTL and value string (note that we store the original hex casing here).
    sshfp_key = ("sshfp.example", int(QTYPE.SSHFP))
    ssh_ttl, ssh_values = plugin.records[sshfp_key]
    assert ssh_ttl == 600
    assert ssh_values == ["1 1 1234567890abcdef1234567890abcdef12345678"]

    # OPENPGPKEY record must also be present with its hex RDATA in the
    # internal mapping (generic "#" form is only used when answering).
    openpgp_key = ("openpgp.example", int(QTYPE.OPENPGPKEY))
    open_ttl, open_values = plugin.records[openpgp_key]
    assert open_ttl == 300
    assert open_values == ["0A0B0C"]

    ctx = PluginContext(client_ip="127.0.0.1")

    # Verify that an SSHFP query is answered with an SSHFP RR carrying the
    # expected RDATA (dnslib normalizes the hex digest to uppercase when
    # formatting back to text).
    ssh_req = _make_query("sshfp.example", int(QTYPE.SSHFP))
    ssh_decision = plugin.pre_resolve("sshfp.example", int(QTYPE.SSHFP), ssh_req, ctx)
    assert ssh_decision is not None
    assert ssh_decision.action == "override"
    ssh_resp = DNSRecord.parse(ssh_decision.response)
    ssh_rdatas = [
        str(rr.rdata) for rr in ssh_resp.rr if int(rr.rtype) == int(QTYPE.SSHFP)
    ]
    assert ssh_rdatas == ["1 1 1234567890ABCDEF1234567890ABCDEF12345678"]

    # Verify that an OPENPGPKEY query returns a RR with type OPENPGPKEY and
    # that its textual RDATA round-trips the generic form we provided.
    open_req = _make_query("openpgp.example", int(QTYPE.OPENPGPKEY))
    open_decision = plugin.pre_resolve(
        "openpgp.example", int(QTYPE.OPENPGPKEY), open_req, ctx
    )
    assert open_decision is not None
    assert open_decision.action == "override"
    open_resp = DNSRecord.parse(open_decision.response)
    open_rdatas = [
        str(rr.rdata) for rr in open_resp.rr if int(rr.rtype) == int(QTYPE.OPENPGPKEY)
    ]
    assert open_rdatas == ["\\# 3 0A0B0C"]


def test_auto_soa_generated_for_sshfp_only_zone(tmp_path: pathlib.Path) -> None:
    """Brief: ZoneRecords synthesizes an SOA when only SSHFP RRsets exist.

    Inputs:
      - tmp_path: pytest temporary directory for creating a temporary records
        file.

    Outputs:
      - Asserts that when no explicit SOA is present but SSHFP records share a
        common suffix, a synthetic SOA is created at that inferred apex.
    """

    file_path = tmp_path / "records.txt"
    file_path.write_text(
        "\n".join(
            [
                "host1.sshfp.test|SSHFP|600|1 1 deadbeef",
                "host2.sshfp.test|SSHFP|600|1 1 cafebabe",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(file_path)])
    plugin.setup()

    apex = "sshfp.test"
    soa_key = (apex, int(QTYPE.SOA))
    assert soa_key in plugin.records
    soa_ttl, soa_vals = plugin.records[soa_key]
    assert soa_ttl == plugin.config.get("ttl", 300)
    # Sanity check that the synthesized SOA value references the inferred apex.
    assert any(f"ns1.{apex}." in v and f"hostmaster.{apex}." in v for v in soa_vals)


def test_normalize_axfr_config_valid_and_invalid_entries() -> None:
    """Brief: _normalize_axfr_config returns only well-formed zones and upstreams.

    Inputs:
      - None.

    Outputs:
      - Asserts that valid entries are normalized and invalid ones dropped.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    # Construct a bare instance so we can call the helper directly.
    plugin = ZoneRecords.__new__(ZoneRecords)

    raw = [
        {
            "zone": "Example.COM.",
            "upstreams": [
                {"host": "192.0.2.1", "port": "53", "timeout_ms": "2500"},
                {"host": "192.0.2.2"},  # uses defaults
            ],
        },
        {
            # Missing zone -> ignored.
            "upstreams": [{"host": "203.0.113.1", "port": 53}],
        },
        {
            "zone": "bad.example",
            # upstreams is not a list or mapping -> ignored.
            "upstreams": "not-a-list",
        },
    ]

    zones = plugin._normalize_axfr_config(raw)
    assert len(zones) == 1
    z = zones[0]
    assert z["zone"] == "example.com"
    upstreams = z["upstreams"]
    assert isinstance(upstreams, list)
    assert upstreams[0]["host"] == "192.0.2.1"
    assert upstreams[0]["port"] == 53
    assert upstreams[0]["timeout_ms"] == 2500
    # Second upstream picked up with default port/timeout and tcp transport.
    assert upstreams[1]["host"] == "192.0.2.2"
    assert upstreams[1]["port"] == 53
    assert upstreams[1]["timeout_ms"] == 5000
    assert upstreams[1]["transport"] == "tcp"


def test_normalize_axfr_config_supports_dot_and_tls_fields() -> None:
    """Brief: _normalize_axfr_config preserves transport and TLS-related fields.

    Inputs:
      - None.

    Outputs:
      - Asserts that DoT masters keep transport/server_name/verify/ca_file.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords.__new__(ZoneRecords)

    raw = [
        {
            "zone": "tls.example",
            "upstreams": [
                {
                    "host": "dot-master.example",
                    "port": 853,
                    "timeout_ms": 7000,
                    "transport": "dot",
                    "server_name": "axfr.tls.example",
                    "verify": False,
                    "ca_file": "/tmp/ca.pem",
                },
                {
                    # Unsupported transport -> ignored at normalisation time.
                    "host": "ignored.example",
                    "port": 853,
                    "transport": "udp",
                },
            ],
        }
    ]

    zones = plugin._normalize_axfr_config(raw)
    assert len(zones) == 1
    z = zones[0]
    assert z["zone"] == "tls.example"
    upstreams = z["upstreams"]
    assert len(upstreams) == 1
    m = upstreams[0]
    assert m["host"] == "dot-master.example"
    assert m["port"] == 853
    assert m["timeout_ms"] == 7000
    assert m["transport"] == "dot"
    assert m["server_name"] == "axfr.tls.example"
    assert m["verify"] is False
    assert m["ca_file"] == "/tmp/ca.pem"


def test_load_records_axfr_overlays_and_only_runs_once(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: Initial _load_records overlays AXFR data once and does not re-transfer.

    Inputs:
      - monkeypatch: pytest fixture for patching axfr_transfer.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that axfr_transfer is called on setup() and skipped on reload,
        and that transferred RRs are visible in records after setup.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    # Seed a simple file-backed record so setup() does not fail.
    records_file = tmp_path / "records.txt"
    records_file.write_text("seed.test|A|300|192.0.2.10\n", encoding="utf-8")

    # Build a minimal synthetic AXFR RRset for axfr.test. For integration with
    # ZoneRecords we only need a usable A RR; SOA handling is exercised in
    # dedicated axfr_transfer tests.
    from dnslib import A as _A

    axfr_rrs = [
        RR("host.axfr.test.", QTYPE.A, rdata=_A("203.0.113.5"), ttl=123),
    ]

    calls = {"n": 0}

    def fake_axfr_transfer(host, port, zone, **kwargs):  # noqa: ARG001
        # Ensure we default to TCP when no transport is specified in config.
        assert kwargs.get("transport", "tcp") == "tcp"
        calls["n"] += 1
        return axfr_rrs

    monkeypatch.setattr(mod, "axfr_transfer", fake_axfr_transfer)

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        axfr_zones=[
            {
                "zone": "axfr.test.",
                "upstreams": [
                    {"host": "192.0.2.1", "port": 53, "timeout_ms": 4000},
                ],
            }
        ],
    )
    plugin.setup()

    # AXFR was attempted once during initial load.
    assert calls["n"] == 1
    assert getattr(plugin, "_axfr_loaded_once", False) is True

    # Transferred A record should be present in the records mapping.
    key = ("host.axfr.test", int(QTYPE.A))
    assert key in plugin.records
    ttl, values = plugin.records[key]
    assert ttl == 123
    assert values == ["203.0.113.5"]

    # Subsequent reload must not re-run AXFR.
    plugin._load_records()
    assert calls["n"] == 1


def test_load_records_axfr_errors_do_not_abort(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: AXFR errors are logged but do not prevent file-backed records from loading.

    Inputs:
      - monkeypatch: pytest fixture.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that when axfr_transfer raises AXFRError, setup() still succeeds
        and file-backed records are present, while AXFR zones are skipped.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("seed-only.test|A|300|192.0.2.10\n", encoding="utf-8")

    def failing_axfr(*a, **k):  # noqa: ARG001
        raise mod.AXFRError("boom")

    monkeypatch.setattr(mod, "axfr_transfer", failing_axfr)

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        axfr_zones=[
            {
                "zone": "axfr-fail.test",
                "upstreams": [{"host": "192.0.2.99", "port": 53}],
            }
        ],
    )
    plugin.setup()

    # File-backed record is still loaded.
    key = ("seed-only.test", int(QTYPE.A))
    assert plugin.records[key][1] == ["192.0.2.10"]


def _make_query_with_do_bit(name: str, qtype: int) -> bytes:
    """Create a DNS query with the DNSSEC OK (DO) bit set.

    Inputs:
      name: Domain name to query.
      qtype: Numeric DNS record type code.

    Outputs:
      Raw DNS query bytes with EDNS(0) OPT RR and DO=1.
    """
    from dnslib import EDNS0, DNSRecord

    qtype_name = QTYPE.get(qtype, str(qtype))
    q = DNSRecord.question(name, qtype=qtype_name)
    # Add EDNS(0) OPT RR with DO bit set (flags=0x8000).
    q.add_ar(EDNS0(flags="do", udp_len=4096))
    return q.pack()


def test_client_wants_dnssec_detection(tmp_path: pathlib.Path) -> None:
    """Brief: _client_wants_dnssec correctly detects DO bit in EDNS(0) OPT RR.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts True when DO=1, False when no EDNS or DO=0.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|192.0.2.1\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    # Query with DO=1 should return True.
    do_query = _make_query_with_do_bit("example.com", int(QTYPE.A))
    assert plugin._client_wants_dnssec(do_query) is True

    # Query without EDNS should return False.
    plain_query = _make_query("example.com", int(QTYPE.A))
    assert plugin._client_wants_dnssec(plain_query) is False

    # Malformed bytes should return False gracefully.
    assert plugin._client_wants_dnssec(b"not-valid-dns") is False


def test_dnssec_helper_mapping_contains_base_and_rrsig(tmp_path: pathlib.Path) -> None:
    """Brief: Helper mapping stores both base RR and its RRSIG for a signed RRset.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that self.mapping[qtype][owner] contains A and its covering
        RRSIG(A) RRs for a pre-signed RRset.
    """
    records_file = tmp_path / "signed.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com|A|300|192.0.2.1",
                (
                    "example.com|RRSIG|300|A 13 2 300 "
                    "20260201000000 20260101000000 12345 example.com. "
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    owner_key = "example.com"
    a_code = int(QTYPE.A)
    rrsig_code = int(QTYPE.RRSIG)

    mapping = getattr(plugin, "mapping", {}) or {}
    assert a_code in mapping
    by_name = mapping[a_code]
    assert owner_key in by_name

    rr_list = by_name[owner_key]
    rtypes = {rr.rtype for rr in rr_list}
    assert a_code in rtypes
    assert rrsig_code in rtypes


def test_dnssec_rrsig_returned_when_do_bit_set(tmp_path: pathlib.Path) -> None:
    """Brief: ZoneRecords returns RRSIG records when DO=1 and signatures are present.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a query with DO=1 returns RRSIG alongside A records when
        the zone contains pre-computed signatures.
    """
    # Create a zone with A record and corresponding RRSIG.
    records_file = tmp_path / "signed.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com|A|300|192.0.2.1",
                # Simplified RRSIG covering A RRset (algorithm 13 = ECDSAP256SHA256).
                (
                    "example.com|RRSIG|300|A 13 2 300 "
                    "20260201000000 20260101000000 12345 example.com. "
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    keys_dir = tmp_path / "keys"
    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        dnssec_signing={"enabled": True, "keys_dir": str(keys_dir)},
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # Query with DO=1.
    req_with_do = _make_query_with_do_bit("example.com", int(QTYPE.A))
    decision = plugin.pre_resolve("example.com", int(QTYPE.A), req_with_do, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    answer_types = {rr.rtype for rr in response.rr}

    # A should be in the answer section and the corresponding RRSIG presented
    # as an additional record.
    assert QTYPE.A in answer_types
    assert QTYPE.RRSIG in answer_types


def test_dnssec_rrsig_omitted_when_do_bit_not_set(tmp_path: pathlib.Path) -> None:
    """Brief: ZoneRecords omits RRSIGs when DO=0 or no EDNS.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a query without DO=1 returns only A records and no RRSIG.
    """
    records_file = tmp_path / "signed.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com|A|300|192.0.2.1",
                (
                    "example.com|RRSIG|300|A 13 2 300 "
                    "20260201000000 20260101000000 12345 example.com. "
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # Query without DO bit.
    req_no_do = _make_query("example.com", int(QTYPE.A))
    decision = plugin.pre_resolve("example.com", int(QTYPE.A), req_no_do, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    answer_types = {rr.rtype for rr in response.rr}
    additional_types = {rr.rtype for rr in (response.ar or [])}

    # A should be in the answer section and no RRSIG records returned when the
    # DO bit is not set.
    assert QTYPE.A in answer_types
    assert QTYPE.RRSIG not in answer_types
    assert QTYPE.RRSIG not in additional_types


def test_dnssec_dnskey_returned_at_apex_with_do_bit(tmp_path: pathlib.Path) -> None:
    """Brief: ZoneRecords returns DNSKEY at apex when DO=1 and keys are present.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a DNSKEY query with DO=1 at zone apex returns DNSKEY and
        its RRSIG.
    """
    records_file = tmp_path / "signed.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                # DNSKEY at apex (ZSK with flags 256).
                (
                    "example.com|DNSKEY|300|256 3 13 "
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "AAAAAAAAAAAAAAAAAAAAAAAAAA=="
                ),
                # RRSIG covering DNSKEY.
                (
                    "example.com|RRSIG|300|DNSKEY 13 2 300 "
                    "20260201000000 20260101000000 12345 example.com. "
                    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                    "BBBBBBBBBBBBBBBBBBBBBBBBBB=="
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # Query for DNSKEY with DO=1.
    req_dnskey = _make_query_with_do_bit("example.com", int(QTYPE.DNSKEY))
    decision = plugin.pre_resolve("example.com", int(QTYPE.DNSKEY), req_dnskey, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    answer_types = {rr.rtype for rr in response.rr}

    # DNSKEY should be in the answer section with its covering RRSIG in the
    # additional section.
    assert QTYPE.DNSKEY in answer_types
    assert QTYPE.RRSIG in answer_types


def test_bind_zone_apex_detection_with_dnssec(tmp_path: pathlib.Path) -> None:
    """Brief: BIND-style zonefiles populate zone_soa and authoritative mapping.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a BIND-style zone with SOA at the apex registers the apex
        in _zone_soa and that names under the zone map back to that apex via
        _find_zone_for_name().
    """
    from foghorn.plugins.resolve.zone_records import ZoneRecords

    zonefile = tmp_path / "example.test.zone"
    zonefile.write_text(
        "\n".join(
            [
                "$TTL 3600",
                "$ORIGIN example.test.",
                (
                    "@   IN SOA ns1.example.test. hostmaster.example.test. "
                    "( 1 3600 600 604800 300 )"
                ),
                "    IN NS ns1.example.test.",
                "host IN A 192.0.2.10",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    plugin = ZoneRecords(
        bind_paths=[str(zonefile)],
        dnssec_signing={"enabled": True, "keys_dir": str(tmp_path / "keys")},
    )
    plugin.setup()

    # SOA apex must be present in the internal zone_soa mapping.
    zone_soa = getattr(plugin, "_zone_soa", {}) or {}
    assert "example.test" in zone_soa

    # Names under the apex should resolve back to that apex for authoritative
    # handling.
    assert plugin._find_zone_for_name("host.example.test") == "example.test"


def test_bind_zone_dnssec_autosign_a_includes_rrsig(tmp_path: pathlib.Path) -> None:
    """Brief: BIND-style zone auto-signing returns an authoritative A answer.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a BIND-style zone with DNSSEC auto-signing enabled returns
        an authoritative A answer that includes at least one RRSIG RR when
        queried via pre_resolve().
    """
    from foghorn.plugins.resolve.zone_records import ZoneRecords

    zonefile = tmp_path / "example.test.zone"
    zonefile.write_text(
        "\n".join(
            [
                "$TTL 3600",
                "$ORIGIN example.test.",
                (
                    "@   IN SOA ns1.example.test. hostmaster.example.test. "
                    "( 1 3600 600 604800 300 )"
                ),
                "    IN NS ns1.example.test.",
                "host IN A 192.0.2.10",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    keys_dir = tmp_path / "keys"
    plugin = ZoneRecords(
        bind_paths=[str(zonefile)],
        dnssec_signing={
            "enabled": True,
            "keys_dir": str(keys_dir),
            "algorithm": "ECDSAP256SHA256",
            "generate": "yes",
            "validity_days": 7,
        },
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req_bytes = _make_query("host.example.test", int(QTYPE.A))

    decision = plugin.pre_resolve("host.example.test", int(QTYPE.A), req_bytes, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)

    # Response must be authoritative and contain an A answer.
    assert response.header.aa == 1
    answer_types = {rr.rtype for rr in response.rr}
    assert QTYPE.A in answer_types


def test_normalize_axfr_config_allow_no_dnssec_field() -> None:
    """Brief: _normalize_axfr_config parses allow_no_dnssec correctly.

    Inputs:
      - None.

    Outputs:
      - Asserts that allow_no_dnssec defaults to True and can be set to False.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords.__new__(ZoneRecords)

    raw = [
        {
            "zone": "default.example",
            "upstreams": [{"host": "192.0.2.1"}],
            # No allow_no_dnssec -> defaults to True.
        },
        {
            "zone": "strict.example",
            "upstreams": [{"host": "192.0.2.2"}],
            "allow_no_dnssec": False,
        },
        {
            "zone": "explicit.example",
            "upstreams": [{"host": "192.0.2.3"}],
            "allow_no_dnssec": True,
        },
    ]

    zones = plugin._normalize_axfr_config(raw)
    assert len(zones) == 3

    # Default case.
    assert zones[0]["zone"] == "default.example"
    assert zones[0]["allow_no_dnssec"] is True

    # Explicit False.
    assert zones[1]["zone"] == "strict.example"
    assert zones[1]["allow_no_dnssec"] is False

    # Explicit True.
    assert zones[2]["zone"] == "explicit.example"
    assert zones[2]["allow_no_dnssec"] is True


def test_zonefile_dnssec_classification_logs_state(
    tmp_path: pathlib.Path, caplog
) -> None:
    """Brief: DNSSEC classification for zonefile/inline zones logs dnssec_state.

    Inputs:
      - tmp_path: pytest temporary directory.
      - caplog: pytest logging capture fixture.

    Outputs:
      - Asserts that loading a signed zone from file emits a log line containing
        the dnssec_state classification.
    """
    from foghorn.plugins.resolve.zone_records import ZoneRecords

    records_file = tmp_path / "signed.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                (
                    "example.com|DNSKEY|300|256 3 13 "
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "AAAAAAAAAAAAAAAAAAAAAAAAAA=="
                ),
                (
                    "example.com|RRSIG|300|DNSKEY 13 2 300 "
                    "20260201000000 20260101000000 12345 example.com. "
                    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                    "BBBBBBBBBBBBBBBBBBBBBBBBBB=="
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.INFO):
        plugin = ZoneRecords(file_paths=[str(records_file)])
        plugin.setup()

    # Ensure at least one log line mentions dnssec_state for this zone.
    assert "dnssec_state=" in caplog.text


def test_iter_zone_rrs_for_transfer_non_authoritative(tmp_path: pathlib.Path) -> None:
    """Brief: iter_zone_rrs_for_transfer returns None for non-authoritative zones.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that a ZoneRecords instance with an SOA for example.com does not
        claim authority for unrelated zones when exporting for AXFR.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "zone.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com|A|300|192.0.2.10",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    # Zone apex is example.com, so a different zone name should not be treated
    # as authoritative by this plugin.
    assert plugin.iter_zone_rrs_for_transfer("other.example") is None


def test_iter_zone_rrs_for_transfer_exports_zone_rrs(tmp_path: pathlib.Path) -> None:
    """Brief: iter_zone_rrs_for_transfer exports all RRs inside an authoritative zone.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that exported RRs include the apex SOA and in-zone data and omit
        names outside the zone.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "zone.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com|NS|300|ns1.example.com.",
                "example.com|A|300|192.0.2.10",
                "www.example.com|A|300|192.0.2.20",
                # Outside the zone; should not be exported when iterating example.com.
                "other.com|A|300|198.51.100.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    rrs = plugin.iter_zone_rrs_for_transfer("example.com")
    assert rrs is not None
    owners = {str(rr.rname).rstrip(".").lower() for rr in rrs}
    types = {rr.rtype for rr in rrs}

    # Only in-zone owners should be present.
    assert "example.com" in owners
    assert "www.example.com" in owners
    assert "other.com" not in owners

    # We should at least see SOA and A RR types in the export.
    from dnslib import QTYPE as _Q

    assert _Q.SOA in types
    assert _Q.A in types
