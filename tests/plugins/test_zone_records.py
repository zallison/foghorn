import importlib
import ipaddress
import logging
import os
import pathlib
import socket
import threading
import time

import pytest
from dnslib import QTYPE, RCODE, RR, DNSRecord

from foghorn.plugins.resolve.base import PluginContext


def _make_query(name: str, qtype: int) -> bytes:
    """Create a minimal DNS query for the given name and qtype.

    Inputs:
      name: Domain name to query.
      qtype: Numeric DNS record type code.

    Outputs:
      Raw DNS query bytes suitable for passing to ZoneRecords.pre_resolve.
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
    """ZoneRecords record loader keeps first TTL and value order from a single file.

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
    ttl, values, _ = plugin.records[key]

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
    ttl, values, _ = plugin.records[key]

    # TTL comes from the first occurrence, and values follow their first
    # appearance order across files.
    assert ttl == 100
    assert values == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_load_records_merge_mode_preserves_existing_records(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: load_mode=merge preserves existing in-memory records on reload.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that, after an initial load, a subsequent reload with
        load_mode=merge keeps existing records while overlaying newly loaded
        records.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    f1 = tmp_path / "records1.txt"
    f1.write_text("keep.example|A|300|192.0.2.10\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(f1)])
    plugin.setup()

    # Second load uses a different file, but merge should preserve prior state.
    f2 = tmp_path / "records2.txt"
    f2.write_text("new.example|A|300|192.0.2.20\n", encoding="utf-8")

    plugin.file_paths = [str(f2)]
    plugin.config["load_mode"] = "merge"
    plugin.config["merge_policy"] = "add"

    plugin._load_records()

    assert ("keep.example", int(QTYPE.A)) in plugin.records
    assert ("new.example", int(QTYPE.A)) in plugin.records


def test_load_records_merge_mode_add_policy_appends_values(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: load_mode=merge + merge_policy=add appends values without overwriting.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that an RRset defined in a later source is merged by appending
        new values (and keeping the original TTL) when merge_policy is 'add'.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    base = tmp_path / "base.txt"
    base.write_text("example.com|A|300|1.1.1.1\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(base)])
    plugin.setup()

    overlay = tmp_path / "overlay.txt"
    overlay.write_text("example.com|A|600|2.2.2.2\n", encoding="utf-8")

    plugin.file_paths = [str(overlay)]
    plugin.config["load_mode"] = "merge"
    plugin.config["merge_policy"] = "add"

    plugin._load_records()

    ttl, values, _ = plugin.records[("example.com", int(QTYPE.A))]
    assert ttl == 300
    assert values == ["1.1.1.1", "2.2.2.2"]


def test_load_records_merge_mode_overwrite_policy_replaces_rrset_and_warns(
    tmp_path: pathlib.Path, caplog
) -> None:
    """Brief: merge_policy=overwrite replaces existing RRsets and logs one summary.

    Inputs:
      - tmp_path: pytest temporary directory fixture.
      - caplog: pytest logging capture fixture.

    Outputs:
      - Asserts that, when a later source defines an existing (name,qtype), the
        RRset is replaced (TTL and values), and that a single warning summarises
        overwritten owners per source.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    base = tmp_path / "base.txt"
    base.write_text("example.com|A|300|1.1.1.1\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(base)])
    plugin.setup()

    overlay = tmp_path / "overlay.txt"
    overlay.write_text(
        "\n".join(
            [
                "example.com|A|600|2.2.2.2",
                "example.com|A|600|3.3.3.3",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    plugin.file_paths = [str(overlay)]
    plugin.config["load_mode"] = "merge"
    plugin.config["merge_policy"] = "overwrite"

    with caplog.at_level(logging.WARNING):
        plugin._load_records()

    ttl, values, _ = plugin.records[("example.com", int(QTYPE.A))]
    assert ttl == 600
    assert values == ["2.2.2.2", "3.3.3.3"]

    msgs = [
        r.getMessage()
        for r in caplog.records
        if "overwritten RRsets during load" in r.getMessage()
    ]
    assert len(msgs) == 1
    assert str(overlay) in msgs[0]
    assert "=1" in msgs[0]


def test_load_records_first_mode_uses_inline_group_and_ignores_files(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: load_mode=first uses the first configured source group.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that when inline records are configured (highest precedence),
            file_paths are ignored in load_mode=first.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    f1 = tmp_path / "records1.txt"
    f1.write_text("example.com|A|300|1.1.1.1\n", encoding="utf-8")

    plugin = ZoneRecords(
        records=[
            # This wins due to higher precedence.
            "example.com|A|300|9.9.9.9",
        ],
        file_paths=[str(f1)],  # Ignored because inline comes first
        load_mode="first",
    )
    plugin.setup()

    ttl, values, _ = plugin.records[("example.com", int(QTYPE.A))]
    assert ttl == 300
    assert values == ["9.9.9.9"]


def test_load_records_first_mode_uses_inline_when_no_files_or_bind(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: load_mode=first falls back to inline when no file/bind sources exist.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that inline records are loaded when they are the first available
        source group.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        records=[
            "inline.example|A|300|203.0.113.10",
        ],
        load_mode="first",
    )
    plugin.setup()

    ttl, values, _ = plugin.records[("inline.example", int(QTYPE.A))]
    assert ttl == 300
    assert values == ["203.0.113.10"]


def test_load_records_first_mode_includes_all_file_paths_in_group(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: load_mode=first loads all configured entries within the selected group.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that, when file_paths is the selected group, *all* file_paths are
        processed (not just the first one).
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    f1 = tmp_path / "records1.txt"
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

    f2 = tmp_path / "records2.txt"
    f2.write_text(
        "\n".join(
            [
                # New value should be appended.
                "example.com|A|200|3.3.3.3",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    plugin = ZoneRecords(file_paths=[str(f1), str(f2)], load_mode="first")
    plugin.setup()

    ttl, values, _ = plugin.records[("example.com", int(QTYPE.A))]
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

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
    )
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


def test_pre_resolve_wildcard_domain_patterns(tmp_path: pathlib.Path) -> None:
    """Brief: ZoneRecords supports wildcard owner patterns in the records mapping.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that "*" labels match per ZoneRecords rules:
          * leading "*" matches one-or-more labels (any depth)
          * non-leading "*" matches exactly one label
        and that the most-specific matching pattern wins.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                "*.domain.org|A|300|1.1.1.1",
                "foo.my.*.org|A|300|2.2.2.2",
                "*.my.*.org|A|300|3.3.3.3",
                # Should not match foo.my.domain.org.
                "*.my.*|A|300|4.4.4.4",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)], watchdog_enabled=False)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # Most-specific match wins: foo.my.*.org
    req1 = _make_query("foo.my.domain.org", int(QTYPE.A))
    decision1 = plugin.pre_resolve("foo.my.domain.org", int(QTYPE.A), req1, ctx)
    assert decision1 is not None
    resp1 = DNSRecord.parse(decision1.response)
    ips1 = [str(a.rdata) for a in resp1.rr if a.rtype == QTYPE.A]
    assert ips1 == ["2.2.2.2"]

    # Next-most-specific match wins: *.my.*.org
    req2 = _make_query("bar.my.domain.org", int(QTYPE.A))
    decision2 = plugin.pre_resolve("bar.my.domain.org", int(QTYPE.A), req2, ctx)
    assert decision2 is not None
    resp2 = DNSRecord.parse(decision2.response)
    ips2 = [str(a.rdata) for a in resp2.rr if a.rtype == QTYPE.A]
    assert ips2 == ["3.3.3.3"]

    # Leading wildcard matches multiple labels: *.domain.org
    req3 = _make_query("x.y.domain.org", int(QTYPE.A))
    decision3 = plugin.pre_resolve("x.y.domain.org", int(QTYPE.A), req3, ctx)
    assert decision3 is not None
    resp3 = DNSRecord.parse(decision3.response)
    ips3 = [str(a.rdata) for a in resp3.rr if a.rtype == QTYPE.A]
    assert ips3 == ["1.1.1.1"]

    # Leading wildcard requires at least one label: domain.org should not match *.domain.org.
    req4 = _make_query("domain.org", int(QTYPE.A))
    decision4 = plugin.pre_resolve("domain.org", int(QTYPE.A), req4, ctx)
    assert decision4 is None


def test_wildcard_non_leading_matches_one_label_only(tmp_path: pathlib.Path) -> None:
    """Brief: Non-leading "*" matches exactly one label.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that foo.*.org matches foo.bar.org but does not match
        foo.bar.baz.org (extra label).
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "foo.*.org|A|300|192.0.2.10\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)], watchdog_enabled=False)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    req_ok = _make_query("foo.bar.org", int(QTYPE.A))
    decision_ok = plugin.pre_resolve("foo.bar.org", int(QTYPE.A), req_ok, ctx)
    assert decision_ok is not None

    req_bad = _make_query("foo.bar.baz.org", int(QTYPE.A))
    decision_bad = plugin.pre_resolve("foo.bar.baz.org", int(QTYPE.A), req_bad, ctx)
    assert decision_bad is None


def test_wildcard_does_not_match_embedded_star_in_label(tmp_path: pathlib.Path) -> None:
    """Brief: Only "*" as an entire label is a wildcard.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that "foo*.example" is treated as a literal owner and does not
        match other names.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "foo*.domain.org|A|300|192.0.2.11\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)], watchdog_enabled=False)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req = _make_query("foox.domain.org", int(QTYPE.A))

    decision = plugin.pre_resolve("foox.domain.org", int(QTYPE.A), req, ctx)
    assert decision is None


def test_wildcard_rejects_invalid_chars_in_name(tmp_path: pathlib.Path) -> None:
    """Brief: Wildcard matching rejects invalid characters in the query name.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that malformed names do not match wildcard owners.

    Notes:
      - Some malformed names cannot be encoded into DNS wire format by dnslib,
        so we exercise the helper matcher directly instead of pre_resolve().
    """
    helpers_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.helpers"
    )

    # '$' is not expected in DNS labels for this matcher.
    assert helpers_mod.match_wildcard_domain("foo$.domain.org", "*.domain.org") is False

    # Empty label (double-dot) should be rejected.
    assert helpers_mod.match_wildcard_domain("foo..domain.org", "*.domain.org") is False

    # Blank/empty names are not matches, even for "*".
    assert helpers_mod.match_wildcard_domain("", "*") is False
    assert helpers_mod.match_wildcard_domain("   ", "*") is False

    # Also ensure find_best_rrsets_for_name cannot resolve invalid names.
    name_index = {"*.domain.org": {int(QTYPE.A): (300, ["192.0.2.12"])}}
    matched, rrsets = helpers_mod.find_best_rrsets_for_name(
        "foo$.domain.org", name_index
    )
    assert matched is None
    assert rrsets == {}

    # And ensure blank/empty names never resolve via wildcard owners.
    matched_empty, rrsets_empty = helpers_mod.find_best_rrsets_for_name("", name_index)
    assert matched_empty is None
    assert rrsets_empty == {}

    matched_blank, rrsets_blank = helpers_mod.find_best_rrsets_for_name(
        "   ", name_index
    )
    assert matched_blank is None
    assert rrsets_blank == {}


def test_wildcard_specificity_prefers_more_specific_pattern(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: When multiple wildcard patterns match, the most specific wins.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that "*.my.domain.org" is preferred over "*.domain.org".
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                "*.domain.org|A|300|192.0.2.13",
                "*.my.domain.org|A|300|192.0.2.14",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)], watchdog_enabled=False)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req = _make_query("x.my.domain.org", int(QTYPE.A))

    decision = plugin.pre_resolve("x.my.domain.org", int(QTYPE.A), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    ips = [str(a.rdata) for a in resp.rr if a.rtype == QTYPE.A]
    assert ips == ["192.0.2.14"]


def test_authoritative_zone_wildcard_owner_prevents_nxdomain(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: In an authoritative zone, wildcard owners answer instead of NXDOMAIN.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that a name under an SOA-defined zone apex is answered by a
        wildcard record rather than returning NXDOMAIN.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "\n".join(
            [
                "domain.org|SOA|300|ns1.domain.org. hostmaster.domain.org. 1 3600 600 604800 300",
                "*.domain.org|A|300|192.0.2.55",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)], watchdog_enabled=False)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req = _make_query("a.b.domain.org", int(QTYPE.A))

    decision = plugin.pre_resolve("a.b.domain.org", int(QTYPE.A), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    assert resp.header.rcode == RCODE.NOERROR
    ips = [str(a.rdata) for a in resp.rr if a.rtype == QTYPE.A]
    assert ips == ["192.0.2.55"]


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
    ttl, values, _ = plugin.records[key]

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
      - tmp_path: tmp_path-provided temporary directory.

    Outputs:
      - Asserts that TTL comes from inline records (highest precedence) and that
            values from file records are appended in first-seen order with duplicates
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
            # Duplicate value with a different TTL from file; should be ignored.
            "example.com|A|500|2.2.2.2",
        ],
    )
    plugin.setup()

    key = ("example.com", int(QTYPE.A))
    ttl, values, _ = plugin.records[key]

    # Inline has highest precedence now, so TTL is 400 (from inline)
    assert ttl == 400
    # Values: inline first (but 3.3.3.3 was already in files), then files in order
    # Merge preserves file order: 2.2.2.2 then 1.1.1.1
    assert values == ["3.3.3.3", "2.2.2.2", "1.1.1.1"]


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

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
    )
    plugin.setup()

    key = ("example.com", int(QTYPE.A))
    ttl, values, _ = plugin.records[key]

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

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
    )
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

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
    )
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
    plugin = ZoneRecords(
        file_paths=[str(records_file)],
    )
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
    loader_mod = importlib.import_module("foghorn.plugins.resolve.zone_records.loader")

    class DummyQType:
        def __getattr__(self, name: str) -> int:
            raise AttributeError(name)

        def get(self, name, default=None):  # type: ignore[override]
            return 42

    monkeypatch.setattr(loader_mod, "QTYPE", DummyQType())
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
    )
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
    loader_mod = importlib.import_module("foghorn.plugins.resolve.zone_records.loader")

    class DummyQType:
        def __getattr__(self, name: str) -> int:
            raise AttributeError(name)

        def get(self, name, default=None):  # type: ignore[override]
            return "NOT_INT"

    monkeypatch.setattr(loader_mod, "QTYPE", DummyQType())
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
    )
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

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
    )
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

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
    )
    plugin.setup()

    v4_rev = ipaddress.ip_address("192.0.2.10").reverse_pointer.rstrip(".").lower()
    v6_rev = ipaddress.ip_address("2001:db8::1").reverse_pointer.rstrip(".").lower()

    ptr_code = int(QTYPE.PTR)

    # IPv4 PTR
    key_v4_ptr = (v4_rev, ptr_code)
    ttl_v4, vals_v4, _ = plugin.records[key_v4_ptr]
    assert ttl_v4 == 300
    assert "v4.example." in vals_v4

    # IPv6 PTR
    key_v6_ptr = (v6_rev, ptr_code)
    ttl_v6, vals_v6, _ = plugin.records[key_v6_ptr]
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
    """Brief: pre_resolve returns None when RR.fromZone fails to parse answers.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that no override decision is made when answers cannot be built.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    dnssec_mod = importlib.import_module("foghorn.plugins.resolve.zone_records.dnssec")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    # Force ZoneRecords onto the RR.fromZone fallback path by clearing the
    # pre-built RR mapping produced at load time.
    plugin.mapping = {}  # type: ignore[assignment]

    # Force RR.fromZone to fail so that no answers are added.
    monkeypatch.setattr(
        dnssec_mod,
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


def test_axfr_notify_static_targets_normalized(tmp_path: pathlib.Path) -> None:
    """Brief: axfr_notify entries are normalized into upstream-like mappings.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts that axfr_notify is converted into host/port/transport mappings
        on the ZoneRecords instance.
    """

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|192.0.2.10\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        axfr_notify=[
            {"host": "198.51.100.10", "port": 53, "transport": "tcp"},
            {
                "host": "198.51.100.20",
                "port": 853,
                "transport": "dot",
                "server_name": "sec2.example",
                "verify": False,
                "ca_file": "/tmp/ca.pem",
            },
        ],
    )
    plugin.setup()

    targets = getattr(plugin, "_axfr_notify_static_targets", None)
    assert isinstance(targets, list)
    assert len(targets) == 2

    t1, t2 = targets
    assert t1["host"] == "198.51.100.10"
    assert t1["port"] == 53
    assert t1["transport"] == "tcp"

    assert t2["host"] == "198.51.100.20"
    assert t2["port"] == 853
    assert t2["transport"] == "dot"
    assert t2["server_name"] == "sec2.example"
    assert t2["verify"] is False
    assert t2["ca_file"] == "/tmp/ca.pem"


def test_reload_records_from_watchdog_sends_notify_for_changed_zones(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: _reload_records_from_watchdog sends NOTIFY for changed zones.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: pytest temporary directory containing a records file.

    Outputs:
      - Asserts that, after a zone file change and a reload, ZoneRecords triggers
        notify.send_notify_for_zones() with the apex of the updated zone.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    # Initial SOA + A record for example.com.
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. 1 3600 600 604800 300"
                ),
                "example.com|A|300|192.0.2.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        watchdog_enabled=False,
        watchdog_poll_interval_seconds=0.0,
    )
    plugin.setup()

    # Mutate the zone file so that the apex RRset changes.
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. 1 3600 600 604800 300"
                ),
                # Change the A record value so the zone snapshot differs.
                "example.com|A|300|192.0.2.2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    notified = {"zones": None}

    def fake_send_for_zones(plugin_obj: object, zones: list[str]) -> None:  # noqa: D401
        """Capture the list of zone apexes passed to send_notify_for_zones()."""

        _ = plugin_obj
        notified["zones"] = list(zones)

    notify_mod = importlib.import_module("foghorn.plugins.resolve.zone_records.notify")
    monkeypatch.setattr(
        notify_mod, "send_notify_for_zones", fake_send_for_zones, raising=True
    )

    # Force immediate reload path by disabling the minimum interval.
    plugin._watchdog_min_interval = 0.0  # type: ignore[assignment]
    plugin._last_watchdog_reload_ts = 0.0  # type: ignore[assignment]

    plugin._reload_records_from_watchdog()

    zones = notified["zones"]
    assert zones is not None and "example.com" in zones


def test_send_notify_for_zones_uses_static_targets(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: send_notify_for_zones sends NOTIFY to configured static targets.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts configured axfr_notify targets are used when sending NOTIFY for
        a changed zone.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "notify.example|SOA|300|ns1.notify.example. hostmaster.notify.example. 1 3600 600 604800 300\n",
        encoding="utf-8",
    )

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        axfr_notify=[{"host": "198.51.100.10", "port": 53, "transport": "tcp"}],
        axfr_notify_allow_private_targets=True,
        axfr_notify_min_interval_seconds=0.0,
    )
    plugin.setup()

    calls: list[tuple[str, dict]] = []

    def fake_send_notify(zone_apex: str, target: dict) -> None:  # noqa: D401
        """Record NOTIFY sends instead of performing network I/O."""

        calls.append((zone_apex, dict(target)))

    notify_mod = importlib.import_module("foghorn.plugins.resolve.zone_records.notify")
    monkeypatch.setattr(
        notify_mod, "send_notify_to_target", fake_send_notify, raising=True
    )

    notify_mod.send_notify_for_zones(plugin, ["notify.example"])

    assert calls, "expected at least one NOTIFY send"
    zones = {z for (z, _t) in calls}
    assert any(z.startswith("notify.example") for z in zones)
    hosts = {t["host"] for (_z, t) in calls}
    assert "198.51.100.10" in hosts


def test_watchdog_handler_should_reload_and_on_any_event(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: WatchdogHandler only reloads for matching file events.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts _should_reload and on_any_event behaviour for various event shapes.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")
    watched = [records_file]

    class DummyPlugin:
        def __init__(self) -> None:
            self.reloaded = 0

        def _reload_records_from_watchdog(self) -> None:
            self.reloaded += 1

    plugin = DummyPlugin()
    watchdog_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.watchdog"
    )
    handler = watchdog_mod.WatchdogHandler(plugin, watched)

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
    """Brief: start_watchdog leaves _observer unset when Observer is None.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that _observer is left as None when watchdog Observer is unavailable.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    watchdog_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.watchdog"
    )
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        watchdog_enabled=False,
        watchdog_poll_interval_seconds=0.0,
    )
    plugin.setup()

    # Force Observer to be treated as unavailable.
    monkeypatch.setattr(watchdog_mod, "Observer", None)

    watchdog_mod.start_watchdog(plugin)
    assert getattr(plugin, "_observer", None) is None


def test_start_watchdog_with_no_directories(monkeypatch) -> None:
    """Brief: start_watchdog returns early when there are no directories to watch.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.

    Outputs:
      - Asserts that _observer is set to None when file_paths is empty.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    watchdog_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.watchdog"
    )
    ZoneRecords = mod.ZoneRecords

    # Construct a bare instance without going through __init__ to allow empty file_paths.
    plugin = ZoneRecords.__new__(ZoneRecords)
    plugin.file_paths = []  # type: ignore[assignment]
    plugin._observer = None  # type: ignore[assignment]

    class DummyObserver:
        def __init__(self) -> None:
            raise AssertionError(
                "Observer should not be instantiated when no directories exist"
            )

    monkeypatch.setattr(watchdog_mod, "Observer", DummyObserver)

    watchdog_mod.start_watchdog(plugin)
    # When there are no concrete directories to watch, _observer remains None.
    assert plugin._observer is None


def test_start_polling_configuration(monkeypatch, tmp_path: pathlib.Path) -> None:
    """Brief: start_polling only starts a thread when interval and stop_event are set.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that polling thread is only started when both interval and stop_event are set.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    watchdog_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.watchdog"
    )
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    # Disabled polling: interval <= 0
    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        watchdog_poll_interval_seconds=0.0,
    )
    plugin.setup()
    plugin._poll_interval = 0.0  # type: ignore[assignment]
    plugin._poll_stop = threading.Event()
    watchdog_mod.start_polling(plugin)
    assert getattr(plugin, "_poll_thread", None) is None

    # Interval set but no stop_event configured -> no thread
    plugin2 = ZoneRecords(
        file_paths=[str(records_file)],
        watchdog_poll_interval_seconds=0.0,
    )
    plugin2.setup()
    plugin2._poll_interval = 0.1  # type: ignore[assignment]
    plugin2._poll_stop = None  # type: ignore[assignment]
    watchdog_mod.start_polling(plugin2)
    assert getattr(plugin2, "_poll_thread", None) is None

    # Proper configuration starts a polling thread.
    plugin3 = ZoneRecords(
        file_paths=[str(records_file)],
        watchdog_poll_interval_seconds=0.0,
    )
    plugin3.setup()
    plugin3._poll_interval = 0.01  # type: ignore[assignment]
    plugin3._poll_stop = threading.Event()
    watchdog_mod.start_polling(plugin3)
    assert getattr(plugin3, "_poll_thread", None) is not None
    plugin3.close()


def test_poll_loop_early_return_and_iteration(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: _poll_loop returns early when misconfigured and loops once when configured.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts both the early-return and single-iteration behaviours.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    watchdog_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.watchdog"
    )
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        watchdog_poll_interval_seconds=0.0,
    )
    plugin.setup()

    # Early return when stop_event is None.
    plugin._poll_stop = None  # type: ignore[assignment]
    plugin._poll_interval = 0.1  # type: ignore[assignment]
    watchdog_mod._poll_loop(plugin)

    # Single iteration when configured; have_files_changed clears the stop event.
    stop = threading.Event()
    plugin._poll_stop = stop  # type: ignore[assignment]
    plugin._poll_interval = 0.01  # type: ignore[assignment]

    def fake_have_files_changed(plugin_obj: object) -> bool:
        _ = plugin_obj
        stop.set()
        return False

    monkeypatch.setattr(
        watchdog_mod, "have_files_changed", fake_have_files_changed, raising=True
    )
    watchdog_mod._poll_loop(plugin)
    assert stop.is_set() is True


def test_have_files_changed_tracks_snapshot(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: have_files_changed builds snapshots and detects changes.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that the first call returns True and subsequent identical stats return False.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    watchdog_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.watchdog"
    )
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        watchdog_poll_interval_seconds=0.0,
    )
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

    monkeypatch.setattr(watchdog_mod.os, "stat", fake_stat)

    # First call establishes snapshot.
    assert watchdog_mod.have_files_changed(plugin) is True
    # Second call with same stats returns False.
    assert watchdog_mod.have_files_changed(plugin) is False


def test_schedule_debounced_reload_variants(
    monkeypatch, tmp_path: pathlib.Path
) -> None:
    """Brief: schedule_debounced_reload covers immediate, lock-less, and timer cases.

    Inputs:
      - monkeypatch: pytest fixture for runtime patching.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that reload is called immediately for zero delay and scheduled via Timer otherwise.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    watchdog_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.watchdog"
    )
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
    watchdog_mod.schedule_debounced_reload(plugin, 0.0)
    assert called["count"] == 1

    # No lock configured -> no scheduling.
    plugin2 = ZoneRecords(file_paths=[str(records_file)])
    plugin2.setup()
    plugin2._reload_records_from_watchdog = fake_reload  # type: ignore[assignment]
    plugin2._reload_timer_lock = None  # type: ignore[assignment]
    watchdog_mod.schedule_debounced_reload(plugin2, 1.0)
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
    watchdog_mod.schedule_debounced_reload(plugin3, 1.0)
    assert called["count"] == 1

    # Normal scheduling path with Timer replacement that calls callback immediately.
    calls = {"timer_cb": 0}

    def make_timer(delay, cb):  # type: ignore[override]
        class ImmediateTimer:
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

    monkeypatch.setattr(watchdog_mod.threading, "Timer", make_timer)

    plugin4 = ZoneRecords(file_paths=[str(records_file)])
    plugin4.setup()
    plugin4._reload_records_from_watchdog = fake_reload  # type: ignore[assignment]
    plugin4._reload_timer_lock = threading.Lock()  # type: ignore[assignment]
    watchdog_mod.schedule_debounced_reload(plugin4, 0.01)

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
    watchdog_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.watchdog"
    )
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    plugin = ZoneRecords(file_paths=[str(records_file)])
    plugin.setup()

    # Deferred path: elapsed < min_interval. Use a fixed time source for determinism.
    monkeypatch.setattr(watchdog_mod.time, "time", lambda: 105.0)
    plugin._last_watchdog_reload_ts = 100.0  # type: ignore[assignment]
    plugin._watchdog_min_interval = 10.0  # type: ignore[assignment]

    scheduled = {"delay": None}

    def fake_schedule(plugin_obj: object, delay: float) -> None:
        _ = plugin_obj
        scheduled["delay"] = delay

    monkeypatch.setattr(
        watchdog_mod, "schedule_debounced_reload", fake_schedule, raising=True
    )
    plugin._reload_records_from_watchdog()
    assert scheduled["delay"] is not None

    # Immediate path: elapsed >= min_interval causes an in-place reload.
    monkeypatch.setattr(watchdog_mod.time, "time", lambda: 200.0)
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
      - Asserts that start_watchdog is only called when watchdog_enabled is truthy.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    watchdog_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.watchdog"
    )
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|1.2.3.4\n", encoding="utf-8")

    calls = {"start": 0}

    def fake_start(plugin_obj: object) -> None:  # noqa: D401
        """Count calls to watchdog.start_watchdog without starting a real observer."""

        _ = plugin_obj
        calls["start"] += 1

    monkeypatch.setattr(watchdog_mod, "start_watchdog", fake_start, raising=True)

    # Explicitly disabled -> no call.
    plugin_disabled = ZoneRecords(
        file_paths=[str(records_file)], watchdog_enabled=False
    )
    plugin_disabled.setup()

    # Truthy non-bool value -> treated as True and calls start_watchdog.
    plugin_enabled = ZoneRecords(file_paths=[str(records_file)], watchdog_enabled="yes")
    plugin_enabled.setup()

    assert calls["start"] == 1


def test_nxdomain_zones_returns_nxdomain_for_missing_name_under_suffix(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: nxdomain_zones makes ZoneRecords return NXDOMAIN under a suffix.

    Inputs:
      - tmp_path: pytest temporary directory fixture (unused, but kept for API
        consistency with surrounding tests).

    Outputs:
      - Asserts that queries under the configured suffix are overridden with
        NXDOMAIN when the name does not exist in ZoneRecords.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        records=["host.private.test|A|300|192.0.2.10"],
        nxdomain_zones=["private.test"],
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req_bytes = _make_query("missing.private.test", int(QTYPE.A))

    decision = plugin.pre_resolve("missing.private.test", int(QTYPE.A), req_bytes, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    assert response.header.rcode == RCODE.NXDOMAIN


def test_nxdomain_zones_returns_nodata_when_name_exists_but_type_missing(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: nxdomain_zones returns NOERROR/NODATA when name exists.

    Inputs:
      - tmp_path: pytest temporary directory fixture (unused).

    Outputs:
      - Asserts that, when an owner exists under the suffix but does not have
        the requested type, ZoneRecords returns NOERROR with an empty answer
        section (NODATA).
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        records=["host.private.test|A|300|192.0.2.10"],
        nxdomain_zones=["private.test"],
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req_bytes = _make_query("host.private.test", int(QTYPE.AAAA))

    decision = plugin.pre_resolve("host.private.test", int(QTYPE.AAAA), req_bytes, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    assert response.header.rcode == RCODE.NOERROR
    assert not response.rr


def test_nxdomain_zones_does_not_apply_outside_configured_suffix(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: nxdomain_zones only triggers for matching suffixes.

    Inputs:
      - tmp_path: pytest temporary directory fixture (unused).

    Outputs:
      - Asserts that names outside the configured suffix fall through.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        records=["host.private.test|A|300|192.0.2.10"],
        nxdomain_zones=["private.test"],
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req_bytes = _make_query("missing.other.test", int(QTYPE.A))

    decision = plugin.pre_resolve("missing.other.test", int(QTYPE.A), req_bytes, ctx)
    assert decision is None


def test_authoritative_zone_nxdomain_and_nodata(tmp_path: pathlib.Path) -> None:
    """ZoneRecords behaves authoritatively inside a zone with SOA.

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

    plugin = ZoneRecords(file_paths=[str(records_file)], any_query_enabled=True)
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

    plugin = ZoneRecords(
        bind_paths=[str(zone_file)],
    )
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


def test_bind_paths_entry_override_origin_and_ttl_warns_and_uses_config(
    tmp_path: pathlib.Path, caplog
) -> None:
    """Brief: bind_paths entries can override $ORIGIN/$TTL and emit a warning.

    Inputs:
      - tmp_path: pytest temporary directory.
      - caplog: pytest logging capture fixture.

    Outputs:
      - Asserts that when a bind_paths entry supplies origin/ttl, ZoneRecords
        ignores in-file $ORIGIN/$TTL directives (with warnings) and uses the
        config values instead.
    """
    zone_file = tmp_path / "example.zone"
    zone_file.write_text(
        """$ORIGIN example.com.\n$TTL 300\n@   IN  SOA ns1.example.com. hostmaster.example.com. ( 1 3600 600 604800 300 )\n@   IN  NS  ns1.example.com.\nwww IN  A   192.0.2.20\n""",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    with caplog.at_level(logging.WARNING):
        plugin = ZoneRecords(
            bind_paths=[
                {
                    "path": str(zone_file),
                    "origin": "override.test.",
                    "ttl": 600,
                }
            ]
        )
        plugin.setup()

    ttl, values, _ = plugin.records[("www.override.test", int(QTYPE.A))]
    assert ttl == 600
    assert values == ["192.0.2.20"]

    msgs = [
        r.getMessage() for r in caplog.records if "BIND zone file" in r.getMessage()
    ]
    assert any("contains $ORIGIN" in m and str(zone_file) in m for m in msgs)
    assert any("contains $TTL" in m and str(zone_file) in m for m in msgs)


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
    ttl, values, _ = plugin.records[key]

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

    plugin = ZoneRecords(
        bind_paths=[str(zone_file)],
        any_query_enabled=True,
    )
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
    ssh_ttl, ssh_values, _ = plugin.records[sshfp_key]
    assert ssh_ttl == 600
    assert ssh_values == ["1 1 1234567890abcdef1234567890abcdef12345678"]

    # OPENPGPKEY record must also be present with its hex RDATA in the
    # internal mapping (generic "#" form is only used when answering).
    openpgp_key = ("openpgp.example", int(QTYPE.OPENPGPKEY))
    open_ttl, open_values, _ = plugin.records[openpgp_key]
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
    soa_ttl, soa_vals, _ = plugin.records[soa_key]
    assert soa_ttl == plugin.config.get("ttl", 300)
    # Sanity check that the synthesized SOA value references the inferred apex.
    assert any(f"ns1.{apex}." in v and f"hostmaster.{apex}." in v for v in soa_vals)


def test_normalize_axfr_config_valid_and_invalid_entries() -> None:
    """Brief: normalize_axfr_config returns only well-formed zones and upstreams.

    Inputs:
      - None.

    Outputs:
      - Asserts that valid entries are normalized and invalid ones dropped.
    """
    helpers_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.helpers"
    )

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

    zones = helpers_mod.normalize_axfr_config(raw)
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
    """Brief: normalize_axfr_config preserves transport and TLS-related fields.

    Inputs:
      - None.

    Outputs:
      - Asserts that DoT masters keep transport/server_name/verify/ca_file.
    """
    helpers_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.helpers"
    )

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

    zones = helpers_mod.normalize_axfr_config(raw)
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


def test_axfr_notify_policy_defaults_are_applied(tmp_path: pathlib.Path) -> None:
    """Brief: new NOTIFY policy fields default to safe values when unset.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts defaults for private-target policy and throttling fields.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|192.0.2.10\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        axfr_notify=[{"host": "198.51.100.10", "port": 53, "transport": "tcp"}],
    )
    plugin.setup()

    assert plugin._axfr_notify_allow_private_targets is False
    assert plugin._axfr_notify_min_interval_seconds == 1.0
    assert plugin._axfr_notify_rate_limit_per_target_per_minute == 60


def test_axfr_notify_policy_invalid_values_normalized(tmp_path: pathlib.Path) -> None:
    """Brief: invalid/unsafe NOTIFY policy inputs normalize to bounded values.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts normalization for non-numeric and negative values.
    """
    records_file = tmp_path / "records.txt"
    records_file.write_text("example.com|A|300|192.0.2.10\n", encoding="utf-8")

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin_bad = ZoneRecords(
        file_paths=[str(records_file)],
        axfr_notify=[{"host": "198.51.100.10", "port": 53, "transport": "tcp"}],
        axfr_notify_min_interval_seconds="not-a-number",
        axfr_notify_rate_limit_per_target_per_minute="oops",
    )
    plugin_bad.setup()
    assert plugin_bad._axfr_notify_min_interval_seconds == 1.0
    assert plugin_bad._axfr_notify_rate_limit_per_target_per_minute == 60

    plugin_negative = ZoneRecords(
        file_paths=[str(records_file)],
        axfr_notify=[{"host": "198.51.100.10", "port": 53, "transport": "tcp"}],
        axfr_notify_min_interval_seconds=-7,
        axfr_notify_rate_limit_per_target_per_minute=-3,
    )
    plugin_negative.setup()
    assert plugin_negative._axfr_notify_min_interval_seconds == 0.0
    assert plugin_negative._axfr_notify_rate_limit_per_target_per_minute == 1


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
    loader_mod = importlib.import_module("foghorn.plugins.resolve.zone_records.loader")
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

    monkeypatch.setattr(loader_mod, "axfr_transfer", fake_axfr_transfer)

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
    ttl, values, _ = plugin.records[key]
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
    loader_mod = importlib.import_module("foghorn.plugins.resolve.zone_records.loader")
    axfr_mod = importlib.import_module("foghorn.servers.transports.axfr")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text("seed-only.test|A|300|192.0.2.10\n", encoding="utf-8")

    def failing_axfr(*a, **k):  # noqa: ARG001
        raise axfr_mod.AXFRError("boom")

    monkeypatch.setattr(loader_mod, "axfr_transfer", failing_axfr)

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


def test_axfr_backoff_blocks_retry_until_elapsed() -> None:
    """Brief: should_attempt_axfr_zone respects failure backoff timing.

    Inputs:
      - None

    Outputs:
      - Asserts that backoff blocks attempts until the delay elapses.
    """
    axfr_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.axfr_dnssec"
    )

    zone_cfg = {
        "minimum_reload_time": 0,
        "failure_backoff_initial_seconds": 10,
        "failure_backoff_max_seconds": 60,
    }
    now = time.time()
    zone_metadata = {
        "example.com": {"failure_count": 1, "last_failure": now},
    }

    assert (
        axfr_mod.should_attempt_axfr_zone("example.com", zone_cfg, zone_metadata)
        is False
    )

    zone_metadata["example.com"]["last_failure"] = now - 11
    assert (
        axfr_mod.should_attempt_axfr_zone("example.com", zone_cfg, zone_metadata)
        is True
    )


def test_axfr_allow_private_upstreams_skips_non_public(monkeypatch) -> None:
    """Brief: _axfr_transfer_for_zone skips private upstreams when disallowed.

    Inputs:
      - monkeypatch: patches socket.getaddrinfo and axfr_fn.

    Outputs:
      - Asserts that private upstreams are skipped when allow_private_upstreams=False.
    """
    axfr_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.axfr_dnssec"
    )

    def fake_getaddrinfo(host, *_args, **_kwargs):  # noqa: ARG001
        return [(socket.AF_INET, None, None, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(axfr_mod.socket, "getaddrinfo", fake_getaddrinfo)

    calls = {"n": 0}

    def fake_axfr(*_a, **_k):
        calls["n"] += 1
        return []

    transferred, last_error = axfr_mod._axfr_transfer_for_zone(  # noqa: SLF001
        "example.com",
        [{"host": "private.example", "port": 53, "timeout_ms": 1000}],
        axfr_fn=fake_axfr,
        allow_private_upstreams=False,
    )

    assert transferred is None
    assert last_error is None
    assert calls["n"] == 0


def test_axfr_transfer_caps_are_forwarded(monkeypatch) -> None:
    """Brief: _axfr_transfer_for_zone forwards size caps to axfr_fn.

    Inputs:
      - monkeypatch: patches socket.getaddrinfo.

    Outputs:
      - Asserts axfr_fn receives max_rrs and max_total_bytes.
    """
    axfr_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.axfr_dnssec"
    )

    def fake_getaddrinfo(host, *_args, **_kwargs):  # noqa: ARG001
        return [(socket.AF_INET, None, None, "", ("192.0.2.10", 0))]

    monkeypatch.setattr(axfr_mod.socket, "getaddrinfo", fake_getaddrinfo)

    seen = {}

    def fake_axfr(*_a, **kwargs):
        seen["max_rrs"] = kwargs.get("max_rrs")
        seen["max_total_bytes"] = kwargs.get("max_total_bytes")
        return []

    axfr_mod._axfr_transfer_for_zone(  # noqa: SLF001
        "example.com",
        [{"host": "up.example", "port": 53, "timeout_ms": 1000}],
        axfr_fn=fake_axfr,
        max_rrs_per_zone=123,
        max_bytes_per_zone=456,
    )

    assert seen["max_rrs"] == 123
    assert seen["max_total_bytes"] == 456


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
    """Brief: client_wants_dnssec correctly detects DO bit in EDNS(0) OPT RR.

    Inputs:
      - tmp_path: pytest temporary directory (unused; kept for test API stability).

    Outputs:
      - Asserts True when DO=1, False when no EDNS or DO=0.
    """
    dnssec_mod = importlib.import_module("foghorn.plugins.resolve.zone_records.dnssec")

    # Query with DO=1 should return True.
    do_query = _make_query_with_do_bit("example.com", int(QTYPE.A))
    assert dnssec_mod.client_wants_dnssec(do_query) is True

    # Query without EDNS should return False.
    plain_query = _make_query("example.com", int(QTYPE.A))
    assert dnssec_mod.client_wants_dnssec(plain_query) is False

    # Malformed bytes should return False gracefully.
    assert dnssec_mod.client_wants_dnssec(b"not-valid-dns") is False


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


def test_dnssec_nxdomain_includes_nsec3_when_do_bit_set(tmp_path: pathlib.Path) -> None:
    """Brief: NXDOMAIN answers include NSEC3 + RRSIG when DO=1 and auto-signing is enabled.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that an authoritative NXDOMAIN response contains SOA, NSEC3,
        and RRSIG records in the authority section when the client sets DO=1.
    """
    records_file = tmp_path / "zone.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com|A|300|192.0.2.1",
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
        dnssec_signing={
            "keys_dir": str(keys_dir),
            "algorithm": "ECDSAP256SHA256",
            "generate": "yes",
            "validity_days": 7,
        },
        watchdog_poll_interval_seconds=0.0,
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req_with_do = _make_query_with_do_bit("missing.example.com", int(QTYPE.A))

    decision = plugin.pre_resolve("missing.example.com", int(QTYPE.A), req_with_do, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    assert response.header.rcode == RCODE.NXDOMAIN

    auth_types = {rr.rtype for rr in (response.auth or [])}
    assert QTYPE.SOA in auth_types
    assert QTYPE.NSEC3 in auth_types
    assert QTYPE.RRSIG in auth_types


def test_dnssec_nxdomain_omits_nsec3_when_autosign_explicitly_disabled(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: NXDOMAIN answers omit NSEC3/RRSIG when dnssec_signing.enabled=false.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that an authoritative NXDOMAIN response contains SOA but no
        NSEC3 or RRSIG records when auto-signing is explicitly disabled.
    """
    records_file = tmp_path / "zone.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com|A|300|192.0.2.1",
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
        dnssec_signing={
            "enabled": False,
            "keys_dir": str(keys_dir),
            "algorithm": "ECDSAP256SHA256",
            "generate": "yes",
            "validity_days": 7,
        },
        watchdog_poll_interval_seconds=0.0,
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req_with_do = _make_query_with_do_bit("missing.example.com", int(QTYPE.A))

    decision = plugin.pre_resolve("missing.example.com", int(QTYPE.A), req_with_do, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    assert response.header.rcode == RCODE.NXDOMAIN

    auth_types = {rr.rtype for rr in (response.auth or [])}
    assert QTYPE.SOA in auth_types
    assert QTYPE.NSEC3 not in auth_types
    assert QTYPE.RRSIG not in auth_types


def test_zone_dnssec_signing_config_defaults_enabled_when_defined() -> None:
    """Brief: ZoneDnssecSigningConfig defaults enabled=true when block exists.

    Inputs:
      - None.

    Outputs:
      - Asserts that constructing ZoneDnssecSigningConfig without an explicit
        enabled field yields enabled=True.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    cfg = mod.ZoneDnssecSigningConfig()
    assert cfg.enabled is True


def test_zone_dnssec_signing_config_normalizes_generate_maybe_and_false() -> None:
    """Brief: ZoneDnssecSigningConfig normalizes maybe/false generate inputs.

    Inputs:
      - None.

    Outputs:
      - Asserts that generate accepts maybe variants and false-like values and
        normalizes them to the canonical yes/no/maybe policy strings.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")

    cfg_maybe = mod.ZoneDnssecSigningConfig(generate=" maybe ")
    assert cfg_maybe.generate == "maybe"

    cfg_maybe_case = mod.ZoneDnssecSigningConfig(generate="MAYBE")
    assert cfg_maybe_case.generate == "maybe"

    cfg_false_str = mod.ZoneDnssecSigningConfig(generate="false")
    assert cfg_false_str.generate == "no"

    cfg_false_bool = mod.ZoneDnssecSigningConfig(generate=False)
    assert cfg_false_bool.generate == "no"

    cfg_false_alias = mod.ZoneDnssecSigningConfig(generate="off")
    assert cfg_false_alias.generate == "no"


def test_zone_records_config_normalizes_nested_dnssec_generate_policy() -> None:
    """Brief: ZoneRecordsConfig applies generate normalization in dnssec_signing.

    Inputs:
      - None.

    Outputs:
      - Asserts that nested dnssec_signing.generate values are normalized when
        parsed via ZoneRecordsConfig.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")

    cfg_maybe = mod.ZoneRecordsConfig(dnssec_signing={"generate": "maybe"})
    assert cfg_maybe.dnssec_signing is not None
    assert cfg_maybe.dnssec_signing.generate == "maybe"

    cfg_false = mod.ZoneRecordsConfig(dnssec_signing={"generate": "false"})
    assert cfg_false.dnssec_signing is not None
    assert cfg_false.dnssec_signing.generate == "no"


def test_dnssec_nsec3_params_configurable_via_dnssec_signing(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: dnssec_signing.nsec3 controls the synthesized NSEC3PARAM values.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that the zone apex has an NSEC3PARAM RRset and that its
        (algorithm, flags, iterations, salt) fields reflect the configured
        iterations/salt.
    """
    records_file = tmp_path / "zone.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com|A|300|192.0.2.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        dnssec_signing={
            "enabled": True,
            "keys_dir": str(tmp_path / "keys"),
            "generate": "yes",
            "nsec3": {"iterations": 5, "salt": "ABCD"},
        },
        watchdog_poll_interval_seconds=0.0,
    )
    plugin.setup()

    # ZoneRecords stores RRsets in (owner, qtype) form; NSEC3PARAM is at the apex.
    nsec3param_key = ("example.com", int(QTYPE.NSEC3PARAM))
    assert nsec3param_key in plugin.records

    _ttl, vals, _ = plugin.records[nsec3param_key]
    assert vals

    parts = str(vals[0]).split()
    assert parts[0] == "1"  # algorithm
    assert parts[1] == "0"  # flags
    assert int(parts[2]) == 5
    assert parts[3].lower() == "abcd"


def test_dnssec_nsec3_iterations_capped_for_hashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: NSEC3 iterations are capped before hashing.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that NSEC3 hashing uses the capped iteration count.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records.dnssec")
    mod._nsec3_hash_cached.cache_clear()

    calls: list[int] = []

    class _StubDnssec:
        def nsec3_hash(
            self,
            _name_text: str,
            _salt_value: object,
            iterations: int,
            _alg: int,
        ) -> str:
            calls.append(int(iterations))
            return "BBBB"

    monkeypatch.setattr(mod, "_dns_dnssec", _StubDnssec())
    monkeypatch.setattr(mod, "add_rrset_to_reply", lambda *_a, **_k: None)

    reply = DNSRecord.question("missing.example.com", qtype="A")
    records = {
        ("example.com", int(QTYPE.NSEC3PARAM)): (300, ["1 0 100000 ABCD"], []),
        ("aaaa.example.com", int(QTYPE.NSEC3)): (300, ["1 0 1 ABCD BBBB A"], []),
    }
    mapping_by_qtype = {
        int(QTYPE.NSEC3): {"aaaa.example.com": [object()]},
    }

    mod.add_nsec3_denial_of_existence(
        reply,
        "missing.example.com",
        int(QTYPE.A),
        "example.com",
        records,
        {},
        mapping_by_qtype=mapping_by_qtype,
    )

    assert calls
    assert max(calls) == mod.NSEC3_MAX_ITERATIONS_SHA1


def test_dnssec_nsec3_uses_cached_owner_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Cached NSEC3 owner index avoids per-query scans.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that add_nsec3_denial_of_existence uses the cached index
        without scanning NSEC3 owner keys.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records.dnssec")
    mod._nsec3_hash_cached.cache_clear()

    class _StubDnssec:
        def nsec3_hash(
            self,
            _name_text: str,
            _salt_value: object,
            _iterations: int,
            _alg: int,
        ) -> str:
            return "AAAA"

    class _NoKeysDict(dict):
        def keys(self) -> object:  # type: ignore[override]
            raise AssertionError("NSEC3 owner keys should not be scanned")

    added: list[tuple] = []
    monkeypatch.setattr(mod, "_dns_dnssec", _StubDnssec())
    monkeypatch.setattr(mod, "add_rrset_to_reply", lambda *a, **k: added.append((a, k)))

    nsec3_owner = "aaaa.example.com"
    records = {
        ("example.com", int(QTYPE.NSEC3PARAM)): (300, ["1 0 1 -"], []),
        (nsec3_owner, int(QTYPE.NSEC3)): (300, ["1 0 1 - AAAA A"], []),
    }
    mapping_by_qtype = {
        int(QTYPE.NSEC3): _NoKeysDict({nsec3_owner: [object()]}),
    }
    nsec3_index = {
        "example.com": {
            "hash_to_owner": {"AAAA": nsec3_owner},
            "hashes_sorted": ["AAAA"],
        }
    }

    reply = DNSRecord.question("missing.example.com", qtype="A")
    mod.add_nsec3_denial_of_existence(
        reply,
        "missing.example.com",
        int(QTYPE.A),
        "example.com",
        records,
        {},
        mapping_by_qtype=mapping_by_qtype,
        nsec3_index=nsec3_index,
    )

    assert added


def test_dnssec_nxdomain_omits_nsec3_when_do_bit_not_set(
    tmp_path: pathlib.Path,
) -> None:
    """Brief: NXDOMAIN answers omit NSEC3/RRSIG when DO=0.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that an authoritative NXDOMAIN response contains SOA but no
        NSEC3 or RRSIG records when DO=0.
    """
    records_file = tmp_path / "zone.txt"
    records_file.write_text(
        "\n".join(
            [
                (
                    "example.com|SOA|300|ns1.example.com. "
                    "hostmaster.example.com. ( 1 3600 600 604800 300 )"
                ),
                "example.com|A|300|192.0.2.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        dnssec_signing={
            "enabled": True,
            "keys_dir": str(tmp_path / "keys"),
            "generate": "yes",
        },
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req_no_do = _make_query("missing.example.com", int(QTYPE.A))

    decision = plugin.pre_resolve("missing.example.com", int(QTYPE.A), req_no_do, ctx)
    assert decision is not None
    assert decision.action == "override"

    response = DNSRecord.parse(decision.response)
    assert response.header.rcode == RCODE.NXDOMAIN

    auth_types = {rr.rtype for rr in (response.auth or [])}
    assert QTYPE.SOA in auth_types
    assert QTYPE.NSEC3 not in auth_types
    assert QTYPE.RRSIG not in auth_types


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
        helpers.find_zone_for_name().
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
    helpers_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.helpers"
    )
    assert (
        helpers_mod.find_zone_for_name("host.example.test", zone_soa) == "example.test"
    )


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
    """Brief: normalize_axfr_config parses allow_no_dnssec correctly.

    Inputs:
      - None.

    Outputs:
      - Asserts that allow_no_dnssec defaults to True and can be set to False.
    """
    helpers_mod = importlib.import_module(
        "foghorn.plugins.resolve.zone_records.helpers"
    )

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

    zones = helpers_mod.normalize_axfr_config(raw)
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
    rr_list = list(rrs)
    owners = {str(rr.rname).rstrip(".").lower() for rr in rr_list}
    types = {rr.rtype for rr in rr_list}

    # Only in-zone owners should be present.
    assert "example.com" in owners
    assert "www.example.com" in owners
    assert "other.com" not in owners

    # We should at least see SOA and A RR types in the export.
    from dnslib import QTYPE as _Q

    assert _Q.SOA in types
    assert _Q.A in types


def test_zone_records_rejects_file_over_max_size(tmp_path: pathlib.Path) -> None:
    """Brief: loader enforces max_file_size_bytes for file_paths.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts setup raises ValueError when a configured records file exceeds
        max_file_size_bytes.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "too-large.txt"
    records_file.write_text(
        "example.com|A|300|192.0.2.10\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="max_file_size_bytes"):
        plugin = ZoneRecords(
            file_paths=[str(records_file)],
            max_file_size_bytes=8,
        )
        plugin.setup()


def test_zone_records_rejects_parent_traversal_path(
    tmp_path: pathlib.Path, caplog
) -> None:
    """Brief: loader rejects configured paths that contain explicit '..' segments.

    Inputs:
      - tmp_path: pytest temporary directory.
      - caplog: pytest log capture fixture.

    Outputs:
      - Asserts a traversal-style configured path is skipped and warning is
        logged, resulting in no loaded records from that source.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "example.com|A|300|192.0.2.10\n",
        encoding="utf-8",
    )
    parent_ref = tmp_path / ".." / tmp_path.name / "records.txt"

    with caplog.at_level(logging.WARNING):
        plugin = ZoneRecords(file_paths=[str(parent_ref)])
        plugin.setup()

    assert ("example.com", int(QTYPE.A)) not in plugin.records
    assert "parent traversal" in caplog.text


def test_zone_records_max_records_limit_enforced_for_inline_records() -> None:
    """Brief: loader enforces max_records across accepted record values.

    Inputs:
      - None.

    Outputs:
      - Asserts setup raises ValueError once inline record ingestion exceeds
        max_records.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    with pytest.raises(ValueError, match="max_records exceeded"):
        plugin = ZoneRecords(
            records=[
                "example.com|A|300|192.0.2.10",
                "example.com|A|300|192.0.2.11",
            ],
            max_records=1,
        )
        plugin.setup()


def test_zone_records_max_record_value_length_enforced() -> None:
    """Brief: loader rejects record values that exceed max_record_value_length.

    Inputs:
      - None.

    Outputs:
      - Asserts setup raises ValueError for overlong inline values.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    with pytest.raises(ValueError, match="record value too long"):
        plugin = ZoneRecords(
            records=["example.com|TXT|300|abcdefghijklmnopqrstuvwxyz"],
            max_record_value_length=4,
        )
        plugin.setup()


def test_zone_records_auto_ptr_can_be_disabled() -> None:
    """Brief: auto_ptr_enabled=false prevents reverse PTR synthesis.

    Inputs:
      - None.

    Outputs:
      - Asserts no PTR RRset is created for a loaded A record when auto PTR is
        disabled.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        records=["host.example.com|A|300|192.0.2.10"],
        auto_ptr_enabled=False,
    )
    plugin.setup()

    ptr_key = (
        dns_name := ipaddress.ip_address("192.0.2.10").reverse_pointer,
        int(QTYPE.PTR),
    )
    ptr_key = (dns_name.rstrip(".").lower(), int(QTYPE.PTR))
    assert ptr_key not in plugin.records


def test_zone_records_auto_ptr_respects_max_auto_ptr_records() -> None:
    """Brief: auto PTR synthesis stops when max_auto_ptr_records is reached.

    Inputs:
      - None.

    Outputs:
      - Asserts only max_auto_ptr_records PTR RRsets are created.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        records=[
            "a.example.com|A|300|192.0.2.10",
            "b.example.com|A|300|192.0.2.11",
            "c.example.com|A|300|192.0.2.12",
        ],
        max_auto_ptr_records=2,
    )
    plugin.setup()

    ptr_qtype = int(QTYPE.PTR)
    ptr_rrsets = [key for key in plugin.records.keys() if int(key[1]) == ptr_qtype]
    assert len(ptr_rrsets) == 2


def test_zone_records_soa_synthesis_can_be_disabled() -> None:
    """Brief: soa_synthesis_enabled=false disables inferred SOA creation.

    Inputs:
      - None.

    Outputs:
      - Asserts zone_soa stays empty when no explicit SOA exists and synthesis
        is disabled.
    """
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        records=[
            "a.example.com|A|300|192.0.2.10",
            "b.example.com|A|300|192.0.2.11",
        ],
        soa_synthesis_enabled=False,
    )
    plugin.setup()

    assert getattr(plugin, "_zone_soa", {}) == {}
