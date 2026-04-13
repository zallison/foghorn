"""Brief: Tests for foghorn.plugins.resolve.admin_ui helper functions.

Inputs:
  - Various config-like mappings and values.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

import threading

from foghorn.plugins.resolve import admin_ui


def test_make_deepcopy_safe_covers_non_trivial_branches() -> None:
    """Brief: _make_deepcopy_safe normalizes common config shapes.

    Inputs:
      - Primitive types, bytes, dict/list/tuple/set, and custom objects.

    Outputs:
      - None; asserts returned structures are copy/deepcopy safe.
    """

    assert admin_ui._make_deepcopy_safe(None) is None
    assert admin_ui._make_deepcopy_safe("x") == "x"
    assert admin_ui._make_deepcopy_safe(123) == 123
    assert admin_ui._make_deepcopy_safe(1.25) == 1.25
    assert admin_ui._make_deepcopy_safe(True) is True

    # bytes -> utf-8 string
    assert admin_ui._make_deepcopy_safe(b"hello") == "hello"

    class BadBytes(bytes):
        def decode(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            raise UnicodeError("boom")

    # bytes decode failure -> str(value)
    assert admin_ui._make_deepcopy_safe(BadBytes(b"hello")) == "b'hello'"

    # dict recursion + stringified keys
    out = admin_ui._make_deepcopy_safe({1: {b"k": b"v"}})
    assert isinstance(out, dict)
    assert out["1"]["b'k'"] == "v"

    # tuple/set -> list
    assert admin_ui._make_deepcopy_safe((1, 2)) == [1, 2]
    set_out = admin_ui._make_deepcopy_safe({1, 2})
    assert isinstance(set_out, list)
    assert set(set_out) == {1, 2}

    # generic objects -> fixed placeholder
    class Foo:
        pass

    assert admin_ui._make_deepcopy_safe(Foo()) == "<object>"


def test_truncate_handles_small_and_disabled_limits() -> None:
    """Brief: _truncate truncates when max_len > 0 and disables truncation otherwise.

    Inputs:
      - A long string and different max_len settings.

    Outputs:
      - None; asserts resulting strings match the helper behavior.
    """

    assert admin_ui._truncate("abcdef", max_len=4) == "a..."
    assert admin_ui._truncate("abcdef", max_len=0) == "abcdef"


def test_stringify_value_covers_non_trivial_branches() -> None:
    """Brief: _stringify_value produces compact strings for common value shapes.

    Inputs:
      - None/bool/number/string/sequence/dict values.

    Outputs:
      - None; asserts formatting/truncation and fallback cases.
    """

    assert admin_ui._stringify_value(None) == ""
    assert admin_ui._stringify_value(True) == "true"
    assert admin_ui._stringify_value(False) == "false"
    assert admin_ui._stringify_value(12) == "12"
    assert admin_ui._stringify_value(1.5) == "1.5"

    assert admin_ui._stringify_value("aaaaaaaaaa", max_len=6) == "aaa..."

    seq = [1, True, None, "x" * 500]
    text = admin_ui._stringify_value(seq, max_len=120)
    assert "1" in text
    assert "true" in text

    long_seq = list(range(60))
    text2 = admin_ui._stringify_value(long_seq, max_len=400)
    assert "(+10 more)" in text2

    d = {"b": 2, "a": 1}
    text3 = admin_ui._stringify_value(d, max_len=200)
    assert '"a": 1' in text3
    assert '"b": 2' in text3

    class Stable:
        def __repr__(self) -> str:
            return "Stable()"

        def __str__(self) -> str:
            return "Stable()"

    # json.dumps should fail; fallback to str(dict) should keep Stable() visible.
    d2 = {"x": Stable()}
    text4 = admin_ui._stringify_value(d2, max_len=200)
    assert "Stable()" in text4


def test_config_to_items_handles_redaction_and_deepcopy_unsafe_values() -> None:
    """Brief: config_to_items redacts nested keys and stringifies values.

    Inputs:
      - Config mapping containing secret keys, nested mappings, and lock objects.

    Outputs:
      - None; asserts output rows contain redacted values and safe representations.
    """

    assert admin_ui.config_to_items(None) == []
    assert admin_ui.config_to_items("not-a-dict") == []  # type: ignore[arg-type]

    lock = threading.RLock()
    cfg = {
        "password": "pw",
        "nested": {"token": "t"},
        "cache": lock,
    }

    items = admin_ui.config_to_items(cfg)
    by_key = {row["key"]: row["value"] for row in items}

    assert by_key["password"] == "***"
    assert "***" in by_key["nested"]
    assert '"token": "t"' not in by_key["nested"]
    assert by_key["cache"] == "<object>"

    # Custom redact_keys: only redact password, leave nested.token visible.
    items2 = admin_ui.config_to_items(cfg, redact_keys=["password"])
    by_key2 = {row["key"]: row["value"] for row in items2}
    assert by_key2["password"] == "***"
    assert '"token": "t"' in by_key2["nested"]

    # max_value_len: enforce truncation.
    items3 = admin_ui.config_to_items({"k": "a" * 50}, redact_keys=[], max_value_len=10)
    assert items3 == [{"key": "k", "value": "aaaaaaa..."}]


def test_config_to_items_defensive_safe_cfg_non_dict(monkeypatch) -> None:
    """Brief: config_to_items tolerates unexpected non-dict safe_cfg values.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts function returns an empty list when safe_cfg is forced non-dict.
    """

    monkeypatch.setattr(admin_ui, "_make_deepcopy_safe", lambda _cfg: "boom")
    assert admin_ui.config_to_items({"a": 1}, redact_keys=[]) == []


def test_limit_rows_enforces_limits_and_stops_iteration() -> None:
    """Brief: limit_rows slices iterables and respects non-positive limits.

    Inputs:
      - Generator producing dict rows.

    Outputs:
      - None; asserts correct row counts and early stop.
    """

    assert admin_ui.limit_rows([], limit=0) == []
    assert admin_ui.limit_rows([{"x": 1}], limit=-1) == []

    produced = {"n": 0}

    def gen():
        for i in range(10):
            produced["n"] += 1
            yield {"x": i}

    rows = admin_ui.limit_rows(gen(), limit=3)
    assert rows == [{"x": 0}, {"x": 1}, {"x": 2}]
    # Ensure the generator was not exhausted.
    assert produced["n"] == 3

    # When the iterable is shorter than the limit, all rows are returned.
    assert admin_ui.limit_rows([{"x": 1}, {"x": 2}], limit=10) == [{"x": 1}, {"x": 2}]


def test_fallback_sanitize_config_supports_substring_key_matches() -> None:
    """Brief: Fallback sanitizer redacts keys matching any configured substring.

    Inputs:
      - Config with exact and substring-sensitive key names.

    Outputs:
      - None; asserts values are redacted in both matching styles.
    """

    cfg = {
        "api_key": "a",
        "dns_api_key": "b",
        "nested": {"auth_token": "c", "safe": "ok"},
    }

    clean = admin_ui._fallback_sanitize_config(cfg, redact_keys=["api_key", "token"])
    assert clean["api_key"] == "***"
    assert clean["dns_api_key"] == "***"
    assert clean["nested"]["auth_token"] == "***"
    assert clean["nested"]["safe"] == "ok"


def test_config_to_items_masks_url_userinfo_for_url_and_endpoint_keys() -> None:
    """Brief: URL userinfo is masked for url/endpoint-like key names.

    Inputs:
      - Config values containing credentials in URL userinfo segments.

    Outputs:
      - None; asserts userinfo is replaced while preserving host/path.
    """

    cfg = {
        "url": "https://user:secret@example.com/dns-query",
        "endpoint": "http://token@internal.local/v1",
        "nested": {"proxy_url": "socks5://alice:pw@proxy.local:1080"},
    }
    items = admin_ui.config_to_items(cfg, redact_keys=[])
    by_key = {row["key"]: row["value"] for row in items}

    assert by_key["url"] == "https://***@example.com/dns-query"
    assert by_key["endpoint"] == "http://***@internal.local/v1"
    assert "socks5://***@proxy.local:1080" in by_key["nested"]
