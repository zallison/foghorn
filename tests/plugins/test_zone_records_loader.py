"""Brief: Branch-focused tests for zone_records.loader helper and load paths.

Inputs:
  - pytest fixtures (tmp_path, monkeypatch, caplog) and synthetic record content.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

import logging
import pathlib
from types import SimpleNamespace

import pytest
from dnslib import QTYPE

import foghorn.plugins.resolve.zone_records as zone_records_mod
import foghorn.plugins.resolve.zone_records.loader as loader


def _make_zone_records(**kwargs):
    """Brief: Create a ZoneRecords plugin instance with caller-provided config.

    Inputs:
      - **kwargs: Keyword arguments passed to ZoneRecords constructor.

    Outputs:
      - ZoneRecords plugin instance.
    """

    return zone_records_mod.ZoneRecords(**kwargs)


def test_validate_input_path_covers_allowlist_and_warning_branches(tmp_path, caplog):
    """Brief: Input-path validation handles bad values, traversal, allowlist, and absolute path warnings.

    Inputs:
      - tmp_path: pytest temporary path.
      - caplog: pytest log capture fixture.

    Outputs:
      - None: asserts accepted/denied path outcomes for each branch.
    """

    class _BadString:
        def __str__(self) -> str:
            raise RuntimeError("cannot stringify")

    allow_dir = tmp_path / "allow"
    allow_dir.mkdir()
    inside = allow_dir / "inside.txt"
    inside.write_text("ok", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("nope", encoding="utf-8")

    assert (
        loader._validate_input_path(path_text=_BadString(), path_allowlist=[]) is None
    )
    assert (
        loader._validate_input_path(path_text="../outside.txt", path_allowlist=[])
        is None
    )
    assert (
        loader._validate_input_path(
            path_text=str(outside),
            path_allowlist=[allow_dir.resolve()],
        )
        is None
    )

    accepted = loader._validate_input_path(
        path_text=str(inside),
        path_allowlist=[allow_dir.resolve()],
    )
    assert accepted == inside.resolve()

    with caplog.at_level(logging.WARNING):
        absolute = loader._validate_input_path(
            path_text=str(inside.resolve()),
            path_allowlist=[],
        )
    assert absolute == inside.resolve()
    assert any(
        "loading absolute path without path_allowlist" in rec.getMessage()
        for rec in caplog.records
    )


def test_enforce_file_size_limit_covers_stat_failure_and_oversize(tmp_path):
    """Brief: File-size enforcement rejects stat failures and oversized files.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts ValueError on stat failure and on exceeded size budget.
    """

    missing = tmp_path / "missing.txt"
    with pytest.raises(ValueError, match="Failed to stat configured records file"):
        loader._enforce_file_size_limit(path=missing, max_file_size_bytes=1)

    big = tmp_path / "big.txt"
    big.write_text("abcdef", encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds max_file_size_bytes"):
        loader._enforce_file_size_limit(path=big, max_file_size_bytes=3)

    loader._enforce_file_size_limit(path=big, max_file_size_bytes=0)


def test_count_and_clone_helpers_cover_legacy_and_malformed_entries():
    """Brief: Counting/cloning helpers handle 3-tuples, legacy 2-tuples, and malformed entries.

    Inputs:
      - None.

    Outputs:
      - None: asserts clone helpers normalize malformed/legacy structures safely.
    """

    mixed_mapping = {
        ("a.example", int(QTYPE.A)): (60, ["192.0.2.1"], {"src-a"}),
        ("b.example", int(QTYPE.A)): (30, ["192.0.2.2"]),
        ("c.example", int(QTYPE.A)): 123,
    }
    assert loader._count_record_values(mixed_mapping) == 2

    cloned_records = loader._clone_records_mapping(mixed_mapping)
    assert cloned_records[("a.example", int(QTYPE.A))][1] == ["192.0.2.1"]
    assert cloned_records[("b.example", int(QTYPE.A))][2] == set()
    assert cloned_records[("c.example", int(QTYPE.A))][0] == 0
    assert cloned_records[("c.example", int(QTYPE.A))][1] == []

    mixed_name_index = {
        "a.example": {int(QTYPE.A): (60, ["192.0.2.1"], {"src-a"})},
        "b.example": {int(QTYPE.A): (60, ["192.0.2.2"])},
        "c.example": {int(QTYPE.A): 123},
    }
    cloned_name_index = loader._clone_name_index(mixed_name_index)
    assert cloned_name_index["a.example"][int(QTYPE.A)][2] == {"src-a"}
    assert cloned_name_index["b.example"][int(QTYPE.A)][2] == set()
    assert cloned_name_index["c.example"][int(QTYPE.A)][1] == []

    mixed_zone_soa = {
        "example.com": (300, ["ns1.example.com. hostmaster.example.com. 1 2 3 4 5"]),
        "bad.example": 123,
    }
    cloned_zone_soa = loader._clone_zone_soa(mixed_zone_soa)
    assert cloned_zone_soa["example.com"][2] == set()
    assert cloned_zone_soa["bad.example"][0] == 0


def test_merge_rr_value_overwrite_and_legacy_upgrade_paths():
    """Brief: RR merge helper covers overwrite initialization and legacy 2-tuple upgrade.

    Inputs:
      - None.

    Outputs:
      - None: asserts overwrite and legacy upgrade branches update maps correctly.
    """

    mapping = {}
    name_index = {}
    zone_soa = {}
    seen_rrsets = set()
    overwritten_by_source = {}

    loader._merge_rr_value(
        owner="Example.COM.",
        qtype_code=int(QTYPE.A),
        ttl=120,
        value="192.0.2.10",
        source_label="src-1",
        mapping=mapping,
        name_index=name_index,
        zone_soa=zone_soa,
        soa_code=int(QTYPE.SOA),
        load_mode="merge",
        merge_policy="overwrite",
        seen_rrsets=seen_rrsets,
        overwritten_by_source=overwritten_by_source,
    )

    key = ("example.com", int(QTYPE.A))
    assert key in seen_rrsets
    assert mapping[key][1] == ["192.0.2.10"]

    mapping[key] = (300, ["192.0.2.20"])
    name_index["example.com"] = {int(QTYPE.A): (300, ["192.0.2.20"])}
    loader._merge_rr_value(
        owner="example.com",
        qtype_code=int(QTYPE.A),
        ttl=300,
        value="192.0.2.30",
        source_label="src-2",
        mapping=mapping,
        name_index=name_index,
        zone_soa=zone_soa,
        soa_code=int(QTYPE.SOA),
        load_mode="merge",
        merge_policy="add",
        seen_rrsets=set(),
        overwritten_by_source={},
    )
    assert mapping[key][1] == ["192.0.2.20", "192.0.2.30"]
    assert "src-2" in mapping[key][2]

    loader._merge_rr_value(
        owner="example.com",
        qtype_code=int(QTYPE.SOA),
        ttl=300,
        value="ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300",
        source_label="src-soa",
        mapping=mapping,
        name_index=name_index,
        zone_soa=zone_soa,
        soa_code=int(QTYPE.SOA),
        load_mode="merge",
        merge_policy="add",
        seen_rrsets=set(),
        overwritten_by_source={},
    )
    assert "example.com" in zone_soa


def test_process_record_line_covers_qtype_get_failure_and_optional_counter(monkeypatch):
    """Brief: Record-line parsing handles qtype lookup failures and optional counters.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts unknown qtype errors and loaded_records_counter empty-list path.
    """

    def _raise_get(*_args, **_kwargs):
        raise RuntimeError("lookup failed")

    monkeypatch.setattr(loader.QTYPE, "get", _raise_get, raising=False)
    with pytest.raises(ValueError, match="unknown qtype"):
        loader.process_record_line(
            plugin=object(),
            raw_line="example.com|NOT_A_TYPE|60|192.0.2.1",
            source_label="inline",
            lineno=1,
            mapping={},
            name_index={},
            zone_soa={},
            soa_code=int(QTYPE.SOA),
            load_mode="merge",
            merge_policy="add",
            seen_rrsets=set(),
            overwritten_by_source={},
            max_record_value_length=4096,
            max_records=100,
            loaded_records_counter=[0],
        )

    mapping = {}
    loader.process_record_line(
        plugin=object(),
        raw_line="example.com|1|60|192.0.2.1",
        source_label="inline",
        lineno=2,
        mapping=mapping,
        name_index={},
        zone_soa={},
        soa_code=int(QTYPE.SOA),
        load_mode="merge",
        merge_policy="add",
        seen_rrsets=set(),
        overwritten_by_source={},
        max_record_value_length=4096,
        max_records=100,
        loaded_records_counter=[],
    )
    assert mapping[("example.com", 1)][1] == ["192.0.2.1"]


def test_normalize_bind_zone_entry_handles_attribute_and_conversion_failures():
    """Brief: BIND entry normalization handles attr objects and string/int conversion failures.

    Inputs:
      - None.

    Outputs:
      - None: asserts invalid path/origin/ttl values normalize to None where needed.
    """

    class _AttrEntry:
        path = "zone.db"
        origin = " Example.COM. "
        ttl = "600"

    class _BadText:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    class _BadPathEntry:
        path = _BadText()
        origin = "example.com"
        ttl = 300

    class _BadOriginEntry:
        path = "zone.db"
        origin = _BadText()
        ttl = "bad"

    assert loader._normalize_bind_zone_entry(_AttrEntry()) == {
        "path": "zone.db",
        "origin": "Example.COM.",
        "ttl": 600,
    }
    assert loader._normalize_bind_zone_entry(_BadPathEntry()) is None
    assert loader._normalize_bind_zone_entry(_BadOriginEntry()) == {
        "path": "zone.db",
        "origin": None,
        "ttl": None,
    }
    assert loader._normalize_bind_zone_entry({"path": None}) is None


def test_validate_input_path_relative_and_bind_entry_string_branches(
    tmp_path,
    monkeypatch,
):
    """Brief: Relative-path validation and plain-string bind entry normalization follow expected defaults.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts relative paths resolve without allowlist warnings and plain strings normalize.
    """

    rel = tmp_path / "relative.zone"
    rel.write_text("ok", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    resolved = loader._validate_input_path(path_text="relative.zone", path_allowlist=[])
    assert resolved == rel.resolve()
    assert loader._normalize_bind_zone_entry("relative.zone") == {
        "path": "relative.zone",
        "origin": None,
        "ttl": None,
    }


def test_load_records_bind_uses_validated_resolved_path_after_cwd_change(
    tmp_path,
    monkeypatch,
):
    """Brief: BIND loading keeps using the validated resolved path even if cwd changes mid-load.

    Inputs:
      - tmp_path: pytest temporary path.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts BIND parsing reads the originally validated zone file path.
    """

    initial_dir = tmp_path / "initial"
    moved_dir = tmp_path / "moved"
    initial_dir.mkdir()
    moved_dir.mkdir()

    (initial_dir / "zone.db").write_text(
        "$ORIGIN example.com.\n"
        "@ 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300\n"
        "@ 300 IN A 192.0.2.10\n",
        encoding="utf-8",
    )
    (moved_dir / "zone.db").write_text(
        "$ORIGIN example.com.\n"
        "@ 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300\n"
        "@ 300 IN A 198.51.100.20\n",
        encoding="utf-8",
    )

    original_enforce_file_size_limit = loader._enforce_file_size_limit

    def _enforce_file_size_limit_and_switch_cwd(*, path, max_file_size_bytes) -> None:
        original_enforce_file_size_limit(
            path=path,
            max_file_size_bytes=max_file_size_bytes,
        )
        monkeypatch.chdir(moved_dir)

    monkeypatch.setattr(
        loader,
        "_enforce_file_size_limit",
        _enforce_file_size_limit_and_switch_cwd,
    )
    monkeypatch.chdir(initial_dir)

    plugin = _make_zone_records(bind_paths=["zone.db"], load_mode="first")
    plugin.setup()

    a_key = ("example.com", int(QTYPE.A))
    assert a_key in plugin.records
    _ttl, values, _sources = plugin.records[a_key]
    assert "192.0.2.10" in values
    assert "198.51.100.20" not in values


def test_strip_bind_directives_when_overridden_logs_for_both_directives(caplog):
    """Brief: Directive stripping logs warnings when config overrides $ORIGIN and $TTL.

    Inputs:
      - caplog: pytest log capture fixture.

    Outputs:
      - None: asserts directives are removed and both override warnings are emitted.
    """

    text = "$ORIGIN example.com.\n" "$TTL 300\n" "; comment\n" "www IN A 192.0.2.10\n"
    with caplog.at_level(logging.WARNING):
        stripped = loader._strip_bind_directives_when_overridden(
            text=text,
            zone_path=pathlib.Path("zone.db"),
            origin_override="override.example",
            ttl_override=600,
        )
    assert "$ORIGIN" not in stripped
    assert "$TTL" not in stripped
    assert "www IN A 192.0.2.10" in stripped
    assert any("contains $ORIGIN" in rec.getMessage() for rec in caplog.records)
    assert any("contains $TTL" in rec.getMessage() for rec in caplog.records)


def test_strip_bind_directives_when_overridden_without_matching_directives(caplog):
    """Brief: Directive stripping with overrides and no matching directives leaves content unchanged.

    Inputs:
      - caplog: pytest log capture fixture.

    Outputs:
      - None: asserts no override warnings are emitted when directives are absent.
    """

    text = "www IN A 192.0.2.20\n"
    with caplog.at_level(logging.WARNING):
        stripped = loader._strip_bind_directives_when_overridden(
            text=text,
            zone_path=pathlib.Path("zone.db"),
            origin_override="override.example",
            ttl_override=600,
        )
    assert stripped == text
    assert not any("contains $ORIGIN" in rec.getMessage() for rec in caplog.records)
    assert not any("contains $TTL" in rec.getMessage() for rec in caplog.records)


def test_load_records_normalizes_invalid_limits_and_mode_policy(tmp_path, caplog):
    """Brief: load_records warns and defaults invalid limit/mode/policy values.

    Inputs:
      - tmp_path: pytest temporary path.
      - caplog: pytest log capture fixture.

    Outputs:
      - None: asserts invalid knob warnings and successful record load.
    """

    plugin = _make_zone_records(
        records=["example.com|A|60|192.0.2.10"],
        max_file_size_bytes=0,
        max_records=0,
        max_record_value_length=0,
        max_auto_ptr_records=0,
        load_mode="invalid",
        merge_policy="invalid",
    )
    with caplog.at_level(logging.WARNING):
        plugin.setup()

    assert ("example.com", int(QTYPE.A)) in plugin.records
    msgs = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "invalid max_file_size_bytes" in msgs
    assert "invalid max_records" in msgs
    assert "invalid max_record_value_length" in msgs
    assert "invalid max_auto_ptr_records" in msgs
    assert "invalid load_mode" in msgs
    assert "invalid merge_policy" in msgs


def test_load_records_first_mode_bind_and_none_selection_branches(tmp_path):
    """Brief: load_mode=first selects bind sources when available and none when absent.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts bind-only first mode loads records, while empty first mode stays empty.
    """

    zone_file = tmp_path / "zone.db"
    zone_file.write_text(
        "$ORIGIN example.com.\n"
        "@ 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300\n"
        "@ 300 IN A 192.0.2.10\n",
        encoding="utf-8",
    )

    plugin_bind = _make_zone_records(bind_paths=[str(zone_file)], load_mode="first")
    plugin_bind.setup()
    assert ("example.com", int(QTYPE.A)) in plugin_bind.records

    plugin_none = SimpleNamespace(
        config={"load_mode": "first"},
        records={},
        _name_index={},
        _zone_soa={},
        _dnssec_classified_axfr=set(),
        _records_lock=None,
        _path_allowlist=[],
        _inline_records=[],
        _axfr_zones=[],
        _axfr_loaded_once=False,
        _axfr_zone_metadata={},
        file_paths=[],
        bind_paths=[],
    )
    loader.load_records(plugin_none)
    assert plugin_none.records == {}


def test_load_records_first_mode_selects_axfr_source(monkeypatch):
    """Brief: load_mode='first' selects AXFR when inline records are absent and AXFR zones are configured.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: asserts AXFR overlay is invoked and AXFR-first state is updated.
    """

    calls: dict[str, object] = {}

    def _fake_overlay(*args, **kwargs):
        calls["overlay"] = (args, kwargs)

    monkeypatch.setattr(loader._axfr_dnssec, "overlay_axfr_zones", _fake_overlay)

    plugin = SimpleNamespace(
        config={"load_mode": "first", "merge_policy": "add"},
        records={},
        _name_index={},
        _zone_soa={},
        _dnssec_classified_axfr=set(),
        _records_lock=None,
        _path_allowlist=[],
        _inline_records=[],
        _axfr_zones=["example.com"],
        _axfr_loaded_once=False,
        _axfr_zone_metadata={},
        file_paths=[],
        bind_paths=[],
    )
    loader.load_records(plugin)
    assert "overlay" in calls
    assert plugin._axfr_loaded_once is True


def test_load_records_bind_path_validation_continue_branch(tmp_path):
    """Brief: BIND source loading skips entries whose normalized paths fail validation.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts bind entries are skipped when path_allowlist rejects the path.
    """

    allow_dir = tmp_path / "allow"
    allow_dir.mkdir()
    outside = tmp_path / "outside.zone"

    plugin = SimpleNamespace(
        config={"load_mode": "first", "merge_policy": "add"},
        records={},
        _name_index={},
        _zone_soa={},
        _dnssec_classified_axfr=set(),
        _records_lock=None,
        _path_allowlist=[allow_dir.resolve()],
        _inline_records=[],
        _axfr_zones=[],
        _axfr_loaded_once=False,
        _axfr_zone_metadata={},
        file_paths=[],
        bind_paths=[str(outside)],
    )
    loader.load_records(plugin)
    assert plugin.records == {}


def test_load_records_invalid_bind_entry_and_missing_bind_file(tmp_path, caplog):
    """Brief: load_records skips invalid bind entries and raises on unreadable bind files.

    Inputs:
      - tmp_path: pytest temporary path.
      - caplog: pytest log capture fixture.

    Outputs:
      - None: asserts invalid bind_paths entries are warned and missing files raise ValueError.
    """

    plugin_bad = SimpleNamespace(
        config={"load_mode": "first", "merge_policy": "add"},
        records={},
        _name_index={},
        _zone_soa={},
        _dnssec_classified_axfr=set(),
        _records_lock=None,
        _path_allowlist=[],
        _inline_records=[],
        _axfr_zones=[],
        _axfr_loaded_once=False,
        _axfr_zone_metadata={},
        file_paths=[],
        bind_paths=[{"origin": "example.com"}],
    )
    with caplog.at_level(logging.WARNING):
        loader.load_records(plugin_bad)
    assert any(
        "skipping invalid bind_paths entry" in rec.getMessage()
        for rec in caplog.records
    )

    missing_zone = tmp_path / "missing.zone"
    plugin_missing = _make_zone_records(
        bind_paths=[str(missing_zone)],
        load_mode="first",
    )
    with pytest.raises(ValueError, match="Failed to stat configured records file"):
        plugin_missing.setup()


def test_load_records_enforces_bind_value_length_limit(tmp_path):
    """Brief: BIND zone loading enforces max_record_value_length budget.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts oversized bind rdata raises ValueError.
    """

    zone_file = tmp_path / "long.zone"
    zone_file.write_text(
        "$ORIGIN example.com.\n"
        "@ 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300\n"
        "@ 300 IN A 192.0.2.10\n",
        encoding="utf-8",
    )

    plugin = _make_zone_records(
        bind_paths=[str(zone_file)],
        load_mode="first",
        max_record_value_length=5,
    )
    with pytest.raises(ValueError, match="max_record_value_length"):
        plugin.setup()


def test_load_records_bind_multi_rr_counter_and_synthesis_tld_mismatch_branch(tmp_path):
    """Brief: BIND loading handles multi-RR loops and SOA synthesis skips mismatched single-label TLD config.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts multi-RR BIND parsing succeeds and mismatched use_tld prevents SOA synthesis.
    """

    zone_file = tmp_path / "multi.zone"
    zone_file.write_text(
        "$ORIGIN example.com.\n"
        "@ 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300\n"
        "@ 300 IN A 192.0.2.10\n"
        "www 300 IN A 192.0.2.11\n",
        encoding="utf-8",
    )
    plugin_bind = _make_zone_records(bind_paths=[str(zone_file)], load_mode="first")
    plugin_bind.setup()
    assert ("example.com", int(QTYPE.A)) in plugin_bind.records
    assert ("www.example.com", int(QTYPE.A)) in plugin_bind.records

    plugin_mismatch = SimpleNamespace(
        config={
            "load_mode": "merge",
            "merge_policy": "add",
            "soa_synthesis_enabled": True,
            "dnssec_signing": {"use_tld": "other"},
        },
        records={
            ("a.tld", int(QTYPE.A)): (300, ["192.0.2.1"], {"seed"}),
            ("b.tld", int(QTYPE.A)): (300, ["192.0.2.2"], {"seed"}),
            (
                "tld",
                int(QTYPE.SOA),
            ): (
                300,
                ["ns1.tld. hostmaster.tld. 1 3600 600 604800 300"],
                {"seed"},
            ),
        },
        _name_index={
            "a.tld": {int(QTYPE.A): (300, ["192.0.2.1"], {"seed"})},
            "b.tld": {int(QTYPE.A): (300, ["192.0.2.2"], {"seed"})},
            "tld": {
                int(QTYPE.SOA): (
                    300,
                    ["ns1.tld. hostmaster.tld. 1 3600 600 604800 300"],
                    {"seed"},
                )
            },
        },
        _zone_soa={},
        _dnssec_classified_axfr=set(),
        _records_lock=None,
        _path_allowlist=[],
        _inline_records=[],
        _axfr_zones=[],
        _axfr_loaded_once=False,
        _axfr_zone_metadata={},
        file_paths=[],
        bind_paths=[],
    )
    loader.load_records(plugin_mismatch)
    assert ("tld", int(QTYPE.SOA)) in plugin_mismatch.records
    assert plugin_mismatch._zone_soa == {}


def test_load_records_synthesizes_tld_soa_when_use_tld_matches(tmp_path):
    """Brief: SOA synthesis accepts single-label suffix when dnssec_signing.use_tld matches.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts synthesized SOA exists for matching single-label suffix.
    """

    plugin = _make_zone_records(
        records=[
            "a.tld|A|300|192.0.2.1",
            "b.tld|A|300|192.0.2.2",
        ],
        dnssec_signing={"use_tld": "tld", "keys_dir": str(tmp_path)},
        soa_synthesis_enabled=True,
    )
    plugin.setup()
    assert ("tld", int(QTYPE.SOA)) in plugin.records


def test_load_records_auto_ptr_legacy_and_budget_warning_paths(caplog):
    """Brief: Auto-PTR generation handles legacy tuples and max_auto_ptr_records budget.

    Inputs:
      - caplog: pytest log capture fixture.

    Outputs:
      - None: asserts legacy tuple fallback and PTR budget warning behavior.
    """

    plugin = _make_zone_records(
        records=["seed.example|A|300|192.0.2.10"],
        load_mode="merge",
        auto_ptr_enabled=True,
        max_auto_ptr_records=1,
    )
    plugin.setup()

    ptr_key = ("1.0.0.127.in-addr.arpa", int(QTYPE.PTR))
    plugin.records = {ptr_key: (300, ["legacy.ptr."])}
    plugin._name_index = {
        "host.example": {
            int(QTYPE.A): (300, ["2001:db8::1", "127.0.0.1", "127.0.0.2"]),
            int(QTYPE.AAAA): (300, ["127.0.0.3"]),
        }
    }
    plugin._zone_soa = {}

    with caplog.at_level(logging.WARNING):
        loader.load_records(plugin)

    ttl, values, sources = plugin.records[ptr_key]
    assert ttl == 300
    assert "host.example." in values
    assert "ptr-auto" in sources
    assert any(
        "max_auto_ptr_records reached" in rec.getMessage() for rec in caplog.records
    )


def test_load_records_assigns_state_without_lock(tmp_path):
    """Brief: load_records updates plugin fields even when _records_lock is missing.

    Inputs:
      - tmp_path: pytest temporary path.

    Outputs:
      - None: asserts lock-less assignment branch updates records/state.
    """

    plugin = _make_zone_records(records=["example.com|A|300|192.0.2.5"])
    plugin.setup()
    plugin._records_lock = None

    loader.load_records(plugin)
    assert ("example.com", int(QTYPE.A)) in plugin.records
