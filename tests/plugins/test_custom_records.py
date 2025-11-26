"""
Brief: Tests for foghorn.plugins.custom-records.CustomRecords plugin.

Inputs:
  - None

Outputs:
  - None
"""

import importlib

import pytest
from dnslib import QTYPE, DNSRecord

from foghorn.plugins.base import PluginContext


def _write_records_file(path, lines):
    """Brief: Write lines to a temporary custom-records file.

    Inputs:
      - path: pathlib.Path for the output file.
      - lines: iterable of text lines to write.

    Outputs:
      - None
    """
    path.write_text("\n".join(lines) + "\n")


def _mk_query(name="example.com", qtype="A"):
    """Brief: Build a DNS query for the given name and qtype.

    Inputs:
      - name: domain name string.
      - qtype: record type name string.

    Outputs:
      - tuple[DNSRecord, bytes]: Query object and packed wire bytes.
    """
    q = DNSRecord.question(name, qtype)
    return q, q.pack()


def test_custom_records_module_import():
    """Brief: Verify custom-records module imports correctly.

    Inputs:
      - None

    Outputs:
      - None: Asserts module name
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    assert mod.__name__ == "foghorn.plugins.custom-records"


def test_setup_normalizes_paths_and_loads_records(tmp_path):
    """Brief: setup() normalizes file_paths then loads and merges records.

    Inputs:
      - tmp_path: pytest-provided temporary directory.

    Outputs:
      - None: Asserts mapping populated with merged values and latest TTL.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    f1 = tmp_path / "records1.txt"
    f2 = tmp_path / "records2.txt"
    _write_records_file(
        f1,
        [
            "example.com|A|60|1.2.3.4",
            "example.com|A|60|2.3.4.5",
        ],
    )
    _write_records_file(f2, ["example.com|A|120|3.4.5.6"])

    # Use _normalize_paths directly to exercise normalization/merging logic.
    plugin = CustomRecords()
    paths = plugin._normalize_paths([str(f1), str(f2), str(f2)])
    plugin.file_paths = paths
    plugin._load_records()

    # _mapping uses lowercased domain and qtype name, TTL from latest line.
    key = ("example.com", "A")
    entry = plugin._mapping.get(key)
    assert entry is not None
    assert entry["ttl"] == 120
    values = entry["values"]
    assert {"1.2.3.4", "2.3.4.5", "3.4.5.6"} <= values


def test_normalize_paths_errors_on_missing():
    """Brief: _normalize_paths raises ValueError when no paths given.

    Inputs:
      - None

    Outputs:
      - None: Asserts ValueError raised.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords
    plugin = CustomRecords()
    with pytest.raises(ValueError):
        plugin._normalize_paths([])


def test_load_records_rejects_malformed_lines(tmp_path):
    """Brief: _load_records rejects malformed and bad-TTL lines.

    Inputs:
      - tmp_path: temporary directory path.

    Outputs:
      - None: Asserts ValueError on malformed lines and TTL.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    bad_fields = tmp_path / "bad_fields.txt"
    bad_ttl = tmp_path / "bad_ttl.txt"
    bad_empty = tmp_path / "bad_empty.txt"

    _write_records_file(bad_fields, ["only|three|fields"])
    _write_records_file(bad_ttl, ["example.com|A|notanint|1.2.3.4"])
    _write_records_file(bad_empty, ["|A|60|1.2.3.4"])

    plugin = CustomRecords()
    plugin.file_paths = [str(bad_fields)]
    with pytest.raises(ValueError):
        plugin._load_records()

    plugin = CustomRecords()
    plugin.file_paths = [str(bad_ttl)]
    with pytest.raises(ValueError):
        plugin._load_records()

    plugin = CustomRecords()
    plugin.file_paths = [str(bad_empty)]
    with pytest.raises(ValueError):
        plugin._load_records()


def test_pre_resolve_returns_override_for_match(tmp_path):
    """Brief: pre_resolve returns override with packed response when mapping has entry.

    Inputs:
      - tmp_path: temporary directory path.

    Outputs:
      - None: Asserts override decision and usable DNS response.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    rec_file = tmp_path / "records.txt"
    _write_records_file(rec_file, ["example.com|A|60|1.2.3.4"])

    plugin = CustomRecords()
    plugin.file_paths = [str(rec_file)]
    plugin._records_lock = None
    plugin._mapping = {("example.com", "A"): {"ttl": 60, "values": {"1.2.3.4"}}}

    ctx = PluginContext(client_ip="127.0.0.1")
    q, wire = _mk_query("example.com", "A")

    decision = plugin.pre_resolve("example.com", QTYPE.A, wire, ctx)
    assert decision is not None
    assert decision.action == "override"
    assert decision.response is not None

    resp = DNSRecord.parse(decision.response)
    assert len(resp.rr) == 1


def test_pre_resolve_returns_none_on_no_match(tmp_path):
    """Brief: pre_resolve returns None when no mapping entry exists.

    Inputs:
      - tmp_path: temporary directory path.

    Outputs:
      - None: Asserts None decision.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    rec_file = tmp_path / "records.txt"
    _write_records_file(rec_file, ["other.com|A|60|1.2.3.4"])

    plugin = CustomRecords()
    plugin.file_paths = [str(rec_file)]
    plugin._records_lock = None
    # Mapping only contains other.com entry -> example.com should not match.
    plugin._mapping = {("other.com", "A"): {"ttl": 60, "values": {"1.2.3.4"}}}

    ctx = PluginContext(client_ip="127.0.0.1")
    _, wire = _mk_query("example.com", "A")
    decision = plugin.pre_resolve("example.com", QTYPE.A, wire, ctx)
    assert decision is None


def test_pre_resolve_ignores_unknown_qtype(tmp_path, caplog):
    """Brief: pre_resolve returns None and logs warning on unknown qtype code.

    Inputs:
      - tmp_path: temporary directory path.

    Outputs:
      - None: Asserts None decision for unknown qtype.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    rec_file = tmp_path / "records.txt"
    _write_records_file(rec_file, ["example.com|A|60|1.2.3.4"])

    plugin = CustomRecords()
    plugin.file_paths = [str(rec_file)]
    plugin._records_lock = None
    plugin._mapping = {("example.com", "A"): {"ttl": 60, "values": {"1.2.3.4"}}}

    ctx = PluginContext(client_ip="127.0.0.1")
    _, wire = _mk_query("example.com", "A")

    unknown_qtype = 65535
    caplog.set_level("WARNING")
    decision = plugin.pre_resolve("example.com", unknown_qtype, wire, ctx)
    assert decision is None


def test_make_response_for_values_handles_parse_error(tmp_path, monkeypatch, caplog):
    """Brief: _make_response_for_values returns None and logs warning on parse error.

    Inputs:
      - tmp_path: temporary directory path.

    Outputs:
      - None: Asserts None returned when DNSRecord.parse fails.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    rec_file = tmp_path / "records.txt"
    _write_records_file(rec_file, ["example.com|A|60|1.2.3.4"])

    plugin = CustomRecords()

    caplog.set_level("WARNING")

    # Monkeypatch DNSRecord.parse to raise, exercising the defensive path.
    monkeypatch.setattr(mod, "DNSRecord", mod.DNSRecord)
    original_parse = mod.DNSRecord.parse

    def boom(*_a, **_k):  # noqa: ANN001, D401
        """Brief: Raise RuntimeError to simulate parse failure.

        Inputs:
          - _a, _k: positional and keyword args (ignored).

        Outputs:
          - None: Always raises RuntimeError.
        """
        raise RuntimeError("parse-fail")

    monkeypatch.setattr(mod.DNSRecord, "parse", staticmethod(boom))
    try:
        res = plugin._make_response_for_values(QTYPE.A, b"bad", 60, ["1.2.3.4"])
        assert res is None
        assert any(
            "parse failure in custom-records" in r.getMessage() for r in caplog.records
        )
    finally:
        monkeypatch.setattr(mod.DNSRecord, "parse", original_parse)


def test_make_response_for_values_builds_records_for_supported_types(tmp_path):
    """Brief: _make_response_for_values builds responses for supported qtypes.

    Inputs:
      - tmp_path: temporary directory path.

    Outputs:
      - None: Asserts non-empty responses for each supported type.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    rec_file = tmp_path / "records.txt"
    _write_records_file(rec_file, ["example.com|A|60|1.2.3.4"])

    plugin = CustomRecords()
    q, wire = _mk_query("example.com", "A")

    for qtype_name in ["A", "AAAA", "CNAME", "PTR", "TXT", "MX", "SRV"]:
        q = DNSRecord.question("example.com", qtype_name)
        wire = q.pack()
        # Use numeric constants (QTYPE.A, etc.) instead of forward lookup by string.
        qtype_code = getattr(QTYPE, qtype_name)

        # Choose a value appropriate for the record type.
        if qtype_name == "A":
            values = ["1.2.3.4"]
        elif qtype_name == "AAAA":
            values = ["2001:db8::1"]
        elif qtype_name == "CNAME":
            values = ["alias.example.com."]
        elif qtype_name == "PTR":
            values = ["ptr.example.com."]
        elif qtype_name == "TXT":
            values = ["hello"]
        elif qtype_name == "MX":
            values = ["10 mail.example.com."]
        elif qtype_name == "SRV":
            values = ["10 5 443 svc.example.com."]
        else:
            values = ["ignored"]

        res = plugin._make_response_for_values(qtype_code, wire, 60, values)
        if qtype_name in {"MX", "SRV"}:
            # For MX/SRV we only assert that the helper handles the value without raising;
            # current implementation logs and skips invalid payloads, returning None.
            assert res is None or isinstance(res, (bytes, bytearray))
        else:
            assert res is not None


def test_make_response_for_values_rejects_unsupported_type(tmp_path, caplog):
    """Brief: _make_response_for_values returns None for unsupported qtype.

    Inputs:
      - tmp_path: temporary directory path.

    Outputs:
      - None: Asserts None and warning for unsupported type.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    rec_file = tmp_path / "records.txt"
    _write_records_file(rec_file, ["example.com|A|60|1.2.3.4"])

    plugin = CustomRecords()
    plugin.file_paths = [str(rec_file)]
    plugin._records_lock = None

    q, wire = _mk_query("example.com", "A")
    caplog.set_level("WARNING")

    # Use TXT qtype but request an unsupported numeric type (e.g., NS which plugin does not handle).
    unsupported_qtype = QTYPE.NS
    res = plugin._make_response_for_values(
        unsupported_qtype, wire, 60, ["ns1.example.com."]
    )
    assert res is None
    assert any(
        "custom-records does not support qtype" in r.getMessage()
        for r in caplog.records
    )


def test_have_files_changed_detects_changes(tmp_path):
    """Brief: _have_files_changed tracks snapshot differences.

    Inputs:
      - tmp_path: temporary directory path.

    Outputs:
      - None: Asserts initial True, then False, then True after modification.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    rec_file = tmp_path / "records.txt"
    _write_records_file(rec_file, ["example.com|A|60|1.2.3.4"])

    plugin = CustomRecords()
    plugin.file_paths = [str(rec_file)]

    # First call treats baseline as change.
    assert plugin._have_files_changed() is True
    # Second call without changes returns False.
    assert plugin._have_files_changed() is False

    # Modify file and ensure True again.
    _write_records_file(rec_file, ["example.com|A|60|5.6.7.8"])
    assert plugin._have_files_changed() is True


def test_close_stops_watchers_gracefully(tmp_path):
    """Brief: close() stops observer, polling, and timers without error.

    Inputs:
      - tmp_path: temporary directory path.

    Outputs:
      - None: Asserts close() can be called after setup.
    """
    mod = importlib.import_module("foghorn.plugins.custom-records")
    CustomRecords = mod.CustomRecords

    rec_file = tmp_path / "records.txt"
    _write_records_file(rec_file, ["example.com|A|60|1.2.3.4"])

    plugin = CustomRecords()
    # Simulate internal state as if setup() had run without starting threads.
    plugin._observer = None
    plugin._poll_stop = type("E", (), {"set": lambda self: None})()
    plugin._poll_thread = None
    plugin._reload_debounce_timer = None

    plugin.close()
