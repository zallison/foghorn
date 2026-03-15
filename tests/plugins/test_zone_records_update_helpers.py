"""Brief: Tests for update_helpers (DNS UPDATE filter and parsing helpers).

Inputs/Outputs:
  - Temporary list files and raw wire-format domain name bytes.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import threading
import time
from types import SimpleNamespace

import pytest

from foghorn.plugins.resolve.zone_records import update_helpers as uh
from foghorn.plugins.resolve.zone_records import UpdateZoneApexConfig


def test_load_list_helpers_strip_comments_and_normalize(tmp_path) -> None:
    names_file = tmp_path / "names.txt"
    names_file.write_text(
        "\n".join(
            [
                "# comment",
                "",
                "Example.COM.",
                "sub.example.com",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    cidr_file = tmp_path / "cidrs.txt"
    cidr_file.write_text(
        "\n".join(
            [
                "# comment",
                "",
                "192.0.2.0/24",
                "2001:db8::/32",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert uh.load_names_list_from_file(str(names_file)) == [
        "example.com",
        "sub.example.com",
    ]
    assert uh.load_cidr_list_from_file(str(cidr_file)) == [
        "192.0.2.0/24",
        "2001:db8::/32",
    ]


def test_load_helpers_missing_files_return_empty_and_do_not_raise(
    tmp_path, caplog
) -> None:
    missing = tmp_path / "missing.txt"
    assert uh.load_names_list_from_file(str(missing)) == []
    assert uh.load_cidr_list_from_file(str(missing)) == []


def test_combine_lists_is_ordered_concatenation(tmp_path) -> None:
    f = tmp_path / "names.txt"
    f.write_text("b.example\n", encoding="utf-8")

    combined = uh.combine_lists(["a.example"], [str(f)], uh.load_names_list_from_file)
    assert combined == ["a.example", "b.example"]


@pytest.mark.parametrize(
    ("cidr", "ok_prefix"),
    [
        ("192.0.2.0/24", 24),
        ("192.0.2.10", 32),
        ("2001:db8::/32", 32),
        ("2001:db8::1", 128),
    ],
)
def test_normalize_cidr_accepts_network_or_host(cidr: str, ok_prefix: int) -> None:
    net = uh.normalize_cidr(cidr)
    assert net is not None
    assert int(net.prefixlen) == ok_prefix


def test_normalize_cidr_rejects_invalid() -> None:
    assert uh.normalize_cidr("not-a-cidr") is None


def test_is_ip_in_cidr_list_handles_invalid_ip_and_invalid_cidr() -> None:
    assert uh.is_ip_in_cidr_list("not-an-ip", ["192.0.2.0/24"]) is False
    assert uh.is_ip_in_cidr_list("192.0.2.5", ["not-a-cidr", "192.0.2.0/24"]) is True


def test_matches_name_pattern_normalizes_case_and_trailing_dot() -> None:
    assert uh.matches_name_pattern("WWW.Example.COM.", ["www.example.com"]) is True
    assert uh.matches_name_pattern("a.example.com", ["*.example.com"]) is True
    assert uh.matches_name_pattern("a.example.com", ["b.example.com"]) is False


def test_update_zone_apex_config_normalize_removes_leading_dots() -> None:
    """Verify that zone names with leading dots are normalized correctly."""
    # Test that leading dots are stripped
    cfg1 = UpdateZoneApexConfig(zone=".zaa")
    assert cfg1.zone == "zaa"

    cfg2 = UpdateZoneApexConfig(zone=".example.com")
    assert cfg2.zone == "example.com"

    # Test that normal zone names work as expected
    cfg3 = UpdateZoneApexConfig(zone="example.com")
    assert cfg3.zone == "example.com"


def test_collect_update_file_paths_skips_non_zone_dicts_and_dedups(tmp_path) -> None:
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"

    cfg = {
        "zones": [
            "not-a-dict",
            {
                "zone": "example.com.",
                "allow_names_files": [str(a)],
                "block_names_files": [str(a)],
                "allow_clients_files": [str(b)],
                "allow_update_ips_files": [str(a)],
                "block_update_ips_files": [str(b)],
            },
        ]
    }

    paths = set(uh.collect_update_file_paths(cfg))
    assert paths == {str(a), str(b)}


def test_collect_update_file_paths_includes_tsig_file_sources(
    tmp_path,
) -> None:
    source_file = tmp_path / "tsig-source.yaml"
    source_file.write_text(
        "keys:\n"
        "  - name: key2.example.\n"
        "    algorithm: hmac-sha256\n"
        "    secret: dGVzdDI=\n",
        encoding="utf-8",
    )

    cfg = {
        "zones": [
            {
                "zone": "example.com",
                "tsig": {
                    "key_sources": [{"type": "file", "path": str(source_file)}],
                },
            }
        ]
    }

    paths = set(uh.collect_update_file_paths(cfg))
    assert str(source_file) in paths


def test_load_tsig_keys_from_file_supports_list_and_mapping(tmp_path) -> None:
    list_file = tmp_path / "keys-list.yaml"
    list_file.write_text(
        "- name: list.example.\n" "  algorithm: hmac-sha256\n" "  secret: dGVzdA==\n",
        encoding="utf-8",
    )
    map_file = tmp_path / "keys-map.yaml"
    map_file.write_text(
        "keys:\n"
        "  - name: map.example.\n"
        "    algorithm: hmac-sha256\n"
        "    secret: Zm9v\n",
        encoding="utf-8",
    )

    list_keys = uh.load_tsig_keys_from_file(str(list_file))
    map_keys = uh.load_tsig_keys_from_file(str(map_file))

    assert list_keys == [
        {"name": "list.example.", "algorithm": "hmac-sha256", "secret": "dGVzdA=="}
    ]
    assert map_keys == [
        {"name": "map.example.", "algorithm": "hmac-sha256", "secret": "Zm9v"}
    ]


def test_resolve_tsig_key_configs_combines_inline_and_custom_source(
    tmp_path,
) -> None:

    def _api_loader(source: dict) -> list[dict]:
        _ = source
        return [
            {
                "name": "api.example.",
                "algorithm": "hmac-sha256",
                "secret": "YXBp",
            }
        ]

    zone_cfg = {
        "tsig": {
            "keys": [
                {
                    "name": "inline.example.",
                    "algorithm": "hmac-sha256",
                    "secret": "aW5saW5l",
                }
            ],
            "key_sources": [{"type": "api", "endpoint": "https://example.invalid"}],
        }
    }

    keys = uh.resolve_tsig_key_configs(zone_cfg, source_loaders={"api": _api_loader})
    key_names = [k.get("name") for k in keys]
    assert key_names == ["inline.example.", "api.example."]


def test_reload_update_lists_loads_when_mtime_changes_and_caches(
    tmp_path, monkeypatch
) -> None:
    names_path = tmp_path / "allow_names.txt"
    cidrs_path = tmp_path / "allow_clients.txt"
    names_path.write_text("a.example.com\n", encoding="utf-8")
    cidrs_path.write_text("192.0.2.0/24\n", encoding="utf-8")

    plugin = SimpleNamespace(
        _dns_update_config={
            "zones": [
                {
                    "zone": "example.com.",
                    "allow_names_files": [str(names_path)],
                    "allow_clients_files": [str(cidrs_path)],
                }
            ]
        },
        _dns_update_cache_lock=threading.RLock(),
        _dns_update_timestamps={},
        _dns_update_lists_cache={},
    )

    uh.reload_update_lists(plugin)

    assert plugin._dns_update_lists_cache["example.com_allow_names"] == [
        "a.example.com"
    ]
    assert plugin._dns_update_lists_cache["example.com_allow_clients"] == [
        "192.0.2.0/24"
    ]
    assert str(names_path) in plugin._dns_update_timestamps

    # Second call without changes should not reload; enforce by making loaders fail.
    orig_load_names = uh.load_names_list_from_file
    orig_load_cidrs = uh.load_cidr_list_from_file

    monkeypatch.setattr(
        uh,
        "load_names_list_from_file",
        lambda _: (_ for _ in ()).throw(RuntimeError("should not reload")),
    )
    monkeypatch.setattr(
        uh,
        "load_cidr_list_from_file",
        lambda _: (_ for _ in ()).throw(RuntimeError("should not reload")),
    )
    uh.reload_update_lists(plugin)

    # Restore loaders for the next reload.
    monkeypatch.setattr(uh, "load_names_list_from_file", orig_load_names)
    monkeypatch.setattr(uh, "load_cidr_list_from_file", orig_load_cidrs)

    # If a file disappears after having been loaded, the cache should refresh to empty.
    names_path.unlink()
    uh.reload_update_lists(plugin)
    assert plugin._dns_update_lists_cache["example.com_allow_names"] == []


def test_reload_update_lists_no_config_or_no_lock_is_noop(tmp_path) -> None:
    plugin_no_cfg = SimpleNamespace(_dns_update_config=None)
    uh.reload_update_lists(plugin_no_cfg)

    plugin_no_lock = SimpleNamespace(
        _dns_update_config={"zones": [{"zone": "example.com."}]},
        _dns_update_cache_lock=None,
    )
    uh.reload_update_lists(plugin_no_lock)


def test_parse_domain_name_wire_parses_root_and_labels_and_rejects_pointers() -> None:
    root, off = uh.parse_domain_name_wire(b"\x00", 0)
    assert root == "."
    assert off == 1

    data = b"\x03www\x07example\x03com\x00"
    name, off2 = uh.parse_domain_name_wire(data, 0)
    assert name == "www.example.com"
    assert off2 == len(data)

    # Compression pointer is rejected in this helper.
    bad, off3 = uh.parse_domain_name_wire(b"\xc0\x0c", 0)
    assert bad is None
    assert off3 == 0

    # Overrun is rejected.
    bad2, off4 = uh.parse_domain_name_wire(b"\x03ww", 0)
    assert bad2 is None
    assert off4 == 0


def test_tsig_hmac_verify_validates_fudge_and_mac() -> None:
    secret_b64 = base64.b64encode(b"secret").decode("ascii")
    msg = b"hello"
    now = int(time.time())

    expected = hmac.new(b"secret", msg, hashlib.sha256).digest()

    assert (
        uh.tsig_hmac_verify(
            "key.example.",
            secret_b64,
            "hmac-sha256",
            msg,
            now,
            30,
            expected,
            1,
        )
        is True
    )

    assert (
        uh.tsig_hmac_verify(
            "key.example.",
            secret_b64,
            "hmac-sha256",
            msg,
            now - 100,
            1,
            expected,
            1,
        )
        is False
    )

    assert (
        uh.tsig_hmac_verify(
            "key.example.",
            "not-base64!!!",
            "hmac-sha256",
            msg,
            now,
            30,
            expected,
            1,
        )
        is False
    )

    assert (
        uh.tsig_hmac_verify(
            "key.example.",
            secret_b64,
            "unknown-alg",
            msg,
            now,
            30,
            expected,
            1,
        )
        is False
    )

    # Defensive: non-bytes msg should return False.
    assert (
        uh.tsig_hmac_verify(
            "key.example.",
            secret_b64,
            "hmac-sha256",
            None,  # type: ignore[arg-type]
            now,
            30,
            expected,
            1,
        )
        is False
    )
