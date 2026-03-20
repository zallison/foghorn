from __future__ import annotations

import pathlib
from types import SimpleNamespace

import pytest

from foghorn.plugins.resolve.zone_records import helpers as zone_helpers


class _BadStr:
    def __str__(self) -> str:
        raise ValueError("nope")


class _PathObj:
    def __init__(self, path: str, origin: object = None, ttl: object = None) -> None:
        self.path = path
        self.origin = origin
        self.ttl = ttl


def test_normalize_path_allowlist_handles_invalid_entries(
    monkeypatch, tmp_path
) -> None:
    """Brief: normalize_path_allowlist skips invalid entries and de-duplicates.

    Inputs:
      - monkeypatch: pytest fixture for patching Path.resolve.
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts invalid entries are ignored and valid paths are de-duplicated.
    """
    p1 = tmp_path / "one"
    p2 = tmp_path / "two"

    def _raise_resolve(self):  # noqa: ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr(pathlib.Path, "resolve", _raise_resolve)

    raw = [None, "", "  ", p1, str(p1), _BadStr(), p2]
    out = zone_helpers.normalize_path_allowlist(raw)

    # resolve() fails, so absolute() is used; we still de-duplicate by string.
    assert len(out) == 2
    assert str(out[0]).endswith("one")
    assert str(out[1]).endswith("two")


def test_path_is_within_allowlist_accepts_only_prefixes(tmp_path) -> None:
    """Brief: _path_is_within_allowlist only returns True for allowed prefixes.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts inside paths pass and outside paths fail.
    """
    allow = [tmp_path.resolve()]
    inside = tmp_path / "sub" / "file.txt"
    outside = tmp_path.parent / "other.txt"

    assert zone_helpers._path_is_within_allowlist(str(inside), allow) is True
    assert zone_helpers._path_is_within_allowlist(str(outside), allow) is False
    assert zone_helpers._path_is_within_allowlist(_BadStr(), allow) is False


def test_normalize_paths_enforces_allowlist_and_deduplicates(tmp_path) -> None:
    """Brief: normalize_paths applies allowlist and handles legacy inputs.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts allowlist filters paths and legacy path is de-duplicated.
    """
    allowed = tmp_path / "allowed"
    allowlist = [allowed.resolve()]
    fp1 = allowed / "one"
    fp2 = tmp_path / "blocked"

    out = zone_helpers.normalize_paths(
        [str(fp1), str(fp2), str(fp1)],
        legacy=str(fp1),
        path_allowlist=allowlist,
    )
    assert out == [str(fp1)]


def test_normalize_paths_raises_when_all_filtered(tmp_path) -> None:
    """Brief: normalize_paths raises when allowlist filters everything.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts ValueError when no usable paths remain.
    """
    allowlist = [tmp_path.resolve()]
    with pytest.raises(ValueError):
        zone_helpers.normalize_paths(
            [str(tmp_path.parent / "nope")],
            legacy=None,
            path_allowlist=allowlist,
        )


def test_normalize_zone_suffixes_dedupes_and_sorts() -> None:
    """Brief: normalize_zone_suffixes de-duplicates and sorts longest-first.

    Inputs:
      - None.

    Outputs:
      - Asserts normalized values are sorted by length descending.
    """
    raw = ["Example.COM.", "sub.example.com", "example.com", None, 123]
    out = zone_helpers.normalize_zone_suffixes(raw)
    assert out == ["sub.example.com", "example.com"]


def test_normalize_bind_paths_accepts_objects_and_filters(tmp_path) -> None:
    """Brief: normalize_bind_paths handles objects, ttl/origin and allowlist.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts invalid entries are dropped and valid entry is normalized.
    """
    allowed = tmp_path / "allowed"
    allowlist = [allowed.resolve()]
    ok_path = allowed / "zone.txt"

    raw = [
        {"origin": "example.com"},  # missing path
        _PathObj(path=str(ok_path), origin="  ", ttl="300"),
        _PathObj(path=str(ok_path), origin="x", ttl="-1"),
        _PathObj(path=str(tmp_path / "blocked"), origin="x", ttl=60),
    ]

    out = zone_helpers.normalize_bind_paths(raw, path_allowlist=allowlist)
    assert len(out) == 1
    assert out[0]["path"] == str(ok_path)
    assert out[0]["origin"] is None
    assert out[0]["ttl"] == 300


def test_normalize_axfr_notify_targets_valid_and_invalid() -> None:
    """Brief: normalize_axfr_notify_targets keeps valid targets only.

    Inputs:
      - None.

    Outputs:
      - Asserts invalid targets are dropped and defaults applied.
    """
    raw = [
        {"host": "192.0.2.1"},
        {"host": "bad.example", "transport": "udp"},
        {"port": 53},
        {"host": "192.0.2.2", "port": "not-int"},
        SimpleNamespace(host="192.0.2.3", port=853, transport="dot"),
    ]

    out = zone_helpers.normalize_axfr_notify_targets(raw)
    assert len(out) == 2
    assert out[0]["host"] == "192.0.2.1"
    assert out[0]["port"] == 53
    assert out[0]["transport"] == "tcp"
    assert out[1]["host"] == "192.0.2.3"
    assert out[1]["port"] == 853
    assert out[1]["transport"] == "dot"


def test_normalize_axfr_config_handles_legacy_and_poll_interval() -> None:
    """Brief: normalize_axfr_config accepts legacy masters and poll intervals.

    Inputs:
      - None.

    Outputs:
      - Asserts legacy masters are used and poll interval <=0 is omitted.
    """
    raw = [
        {
            "zone": "example.com.",
            "masters": [{"host": "192.0.2.1"}],
            "poll_interval_seconds": 0,
        }
    ]
    out = zone_helpers.normalize_axfr_config(raw)
    assert len(out) == 1
    assert out[0]["zone"] == "example.com"
    assert out[0]["upstreams"][0]["host"] == "192.0.2.1"
    assert "poll_interval_seconds" not in out[0]


def test_find_zone_for_name_with_and_without_index() -> None:
    """Brief: find_zone_for_name chooses the longest matching apex.

    Inputs:
      - None.

    Outputs:
      - Asserts both indexed and non-indexed lookups return the longest match.
    """
    zone_soa = {
        "example.com": (300, ["soa"]),
        "sub.example.com": (300, ["soa"]),
    }
    assert (
        zone_helpers.find_zone_for_name("a.sub.example.com", zone_soa)
        == "sub.example.com"
    )
    index = zone_helpers.build_zone_suffix_index(zone_soa)
    assert (
        zone_helpers.find_zone_for_name("a.sub.example.com", zone_soa, index)
        == "sub.example.com"
    )


def test_normalize_dns_name_for_cache_fallback(monkeypatch) -> None:
    """Brief: _normalize_dns_name_for_cache falls back on normalize failures.

    Inputs:
      - monkeypatch: pytest fixture for forcing normalize_name to raise.

    Outputs:
      - Asserts fallback lowercases and strips trailing dot.
    """
    monkeypatch.setattr(zone_helpers.dns_names, "normalize_name", lambda _: 1 / 0)
    assert zone_helpers._normalize_dns_name_for_cache("ExAmple.COM.") == "example.com"


def test_split_dns_labels_rejects_invalid_labels() -> None:
    """Brief: _split_dns_labels returns empty tuple on invalid labels.

    Inputs:
      - None.

    Outputs:
      - Asserts invalid label characters are rejected.
    """
    assert zone_helpers._split_dns_labels("bad$.example") == ()
    assert zone_helpers._split_dns_labels("..example") == ()


def test_wildcard_helpers_match_and_costs() -> None:
    """Brief: Wildcard helpers enforce label rules and cost calculations.

    Inputs:
      - None.

    Outputs:
      - Asserts wildcard matching and cost behavior.
    """
    assert zone_helpers.is_wildcard_domain_pattern("*.example.com") is True
    assert zone_helpers.is_wildcard_domain_pattern("foo*.example.com") is False

    assert (
        zone_helpers.match_wildcard_domain("a.b.example.com", "*.example.com") is True
    )
    assert zone_helpers.match_wildcard_domain("a.b.example.com", "a.*.com") is True
    assert zone_helpers.match_wildcard_domain("a.b.example.com", "a.*") is False
    assert zone_helpers.match_wildcard_domain("a.b.example.com", "*") is True
    assert zone_helpers.match_wildcard_domain("", "*") is False

    assert zone_helpers.wildcard_matched_character_count(
        "a.b.example.com", "*.example.com"
    ) == len("a.b")
    assert (
        zone_helpers.wildcard_matched_character_count("a.b.example.com", "a.*.com") == 0
    )
    assert (
        zone_helpers.wildcard_matched_character_count("a.b.example.com", "*.nope")
        is None
    )


def test_sort_and_cache_wildcard_patterns() -> None:
    """Brief: sort_wildcard_patterns orders by specificity; cache respects size.

    Inputs:
      - None.

    Outputs:
      - Asserts sorting and cache update on size change.
    """
    patterns = ["*", "*.example.com", "a.*.com"]
    sorted_patterns = zone_helpers.sort_wildcard_patterns(patterns)
    assert sorted_patterns[0] == "*.example.com"
    assert sorted_patterns[-1] == "*"

    name_index = {"*.example.com": {}, "a.*.com": {}}
    first = zone_helpers.get_cached_wildcard_patterns(name_index)
    name_index["*.sub.example.com"] = {}
    second = zone_helpers.get_cached_wildcard_patterns(name_index)
    assert "*.sub.example.com" in second
    assert first != second


def test_find_best_rrsets_for_name_prefers_exact_and_low_cost() -> None:
    """Brief: find_best_rrsets_for_name prefers exact and lowest-cost wildcard.

    Inputs:
      - None.

    Outputs:
      - Asserts exact owner wins and lowest cost wildcard is chosen.
    """
    name_index = {
        "host.example.com": {1: (300, ["1.1.1.1"])},
        "*.example.com": {1: (300, ["2.2.2.2"])},
        "*.c.example.com": {1: (300, ["3.3.3.3"])},
    }
    owner, rrsets = zone_helpers.find_best_rrsets_for_name(
        "host.example.com", name_index
    )
    assert owner == "host.example.com"
    assert rrsets[1][1] == ["1.1.1.1"]

    owner2, rrsets2 = zone_helpers.find_best_rrsets_for_name(
        "a.b.c.example.com", name_index
    )
    assert owner2 == "*.c.example.com"
    assert rrsets2[1][1] == ["3.3.3.3"]


def test_snapshot_zone_state_and_compute_changed_zones() -> None:
    """Brief: snapshot_zone_state includes only apex owners and coerces ttl.

    Inputs:
      - None.

    Outputs:
      - Asserts snapshot contents and changed zones detection.
    """
    old_name_index = {
        "example.com": {1: ("bad", ["1.1.1.1"], ["src"])},
        "other.com": {1: (300, ["9.9.9.9"], ["src"])},
    }
    new_name_index = {
        "example.com": {1: (300, ["1.1.1.1"], ["src"])},
    }
    snap = zone_helpers.snapshot_zone_state("example.com", old_name_index)
    assert ("example.com", 1, 0, ("1.1.1.1",)) in snap
    assert all(owner.endswith("example.com") for owner, *_ in snap)

    old_zone_soa = {"example.com": (300, ["soa"])}
    new_zone_soa = {"example.com": (300, ["soa"]), "added.com": (300, ["soa"])}
    changed = zone_helpers.compute_changed_zones(
        old_name_index, old_zone_soa, new_name_index, new_zone_soa
    )
    assert "example.com" in changed
    assert "added.com" in changed
