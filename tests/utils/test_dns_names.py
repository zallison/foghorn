"""Brief: Tests for foghorn.utils.dns_names helpers.

Inputs:
  - pytest fixtures (none)

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import pytest

from foghorn.utils import dns_names


def test_normalize_name_defaults() -> None:
    """Brief: normalize_name applies default lower/strip behaviors.

    Inputs:
      - None

    Outputs:
      - None
    """

    assert dns_names.normalize_name("Example.COM. ") == "example.com"


def test_normalize_name_custom_flags() -> None:
    """Brief: normalize_name respects per-flag options.

    Inputs:
      - None

    Outputs:
      - None
    """

    assert (
        dns_names.normalize_name(
            " Example.COM. ",
            lower=False,
            strip_trailing_dot=False,
            strip_whitespace=False,
        )
        == " Example.COM. "
    )
    assert dns_names.normalize_name("Example.COM.", lower=False) == "Example.COM"
    assert (
        dns_names.normalize_name(" Example.COM ", strip_whitespace=False)
        == " example.com "
    )


def test_normalize_name_list_filters_empty_and_none() -> None:
    """Brief: normalize_name_list skips empty normalized entries and handles None.

    Inputs:
      - None

    Outputs:
      - None
    """

    assert dns_names.normalize_name_list(None) == []
    values = ["Example.COM.", "   ", ".", "TeSt"]
    assert dns_names.normalize_name_list(values) == ["example.com", "test"]


@pytest.mark.parametrize(
    ("name", "suffix", "expected"),
    [
        ("example.com", "example.com", True),
        ("a.b.Example.COM.", "example.com.", True),
        ("example.net", "example.com", False),
        ("", "example.com", False),
        ("example.com", "", False),
    ],
)
def test_is_suffix_match(name: str, suffix: str, expected: bool) -> None:
    """Brief: is_suffix_match handles exact, subdomain, and empty cases.

    Inputs:
      - name: candidate name
      - suffix: suffix to check
      - expected: expected boolean result

    Outputs:
      - None
    """

    assert dns_names.is_suffix_match(name, suffix) is expected


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("example.com", True),
        ("example.com.", True),
        ("foo_bar.example", True),
        ("foo bar.example", False),
        ("foo/bar.example", False),
        ("-bad.example", False),
        ("bad-.example", False),
        ("a" * 64 + ".com", False),
        ("bad@name.example", False),
        (".example.com", False),
    ],
)
def test_is_plain_domain_token(token: str, expected: bool) -> None:
    """Brief: is_plain_domain_token enforces label and character rules.

    Inputs:
      - token: candidate token
      - expected: expected boolean result

    Outputs:
      - None
    """

    assert dns_names.is_plain_domain_token(token) is expected


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("example.com", True),
        ("example.com.", True),
        ("foo_bar.example.com", True),
        ("example", False),
        ("example .com", False),
        ("example.com\x7f", False),
        ("-bad.example.com", False),
        ("bad-.example.com", False),
        ("a" * 64 + ".com", False),
        ("a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63, False),
    ],
)
def test_is_list_domain_token(token: str, expected: bool) -> None:
    """Brief: is_list_domain_token enforces list-file semantics.

    Inputs:
      - token: candidate token
      - expected: expected boolean result

    Outputs:
      - None
    """

    assert dns_names.is_list_domain_token(token) is expected


# ---- Qualification helpers ----


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("lemur", True),
        ("LEMUR", True),
        ("lemur.zaa", False),
        ("lemur.com", False),
        ("", False),
        (".", False),
    ],
)
def test_is_single_label(name: str, expected: bool) -> None:
    """Brief: is_single_label returns True for exactly one label names.

    Inputs:
      - name: candidate name
      - expected: expected bool

    Outputs:
      - None
    """
    assert dns_names.is_single_label(name) is expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("lemur.com", True),
        ("foo.example.io", True),
        ("foo.example.co.uk", True),  # 2-char ccTLD
        ("foo.lab", False),  # 'lab' not in _KNOWN_GTLDS -> local label
        ("foo.corp", False),  # 'corp' not in _KNOWN_GTLDS -> local label
        ("foo.net", True),  # 'net' is a known gTLD
        ("lemur", False),  # single label
        ("lemur.local", False),  # 'local' explicitly excluded
        ("example.12", False),  # numeric TLD rejected
        ("", False),
    ],
)
def test_has_proper_tld(name: str, expected: bool) -> None:
    """Brief: has_proper_tld heuristic classifies names with proper TLDs.

    Inputs:
      - name: candidate name
      - expected: expected bool

    Outputs:
      - None
    """
    assert dns_names.has_proper_tld(name) is expected


@pytest.mark.parametrize(
    ("name", "suffix", "expected"),
    [
        ("lemur", "zaa", "lemur.zaa"),
        ("lemur", "example.com", "lemur.example.com"),
        ("foo.lab", "mycorp.com", "foo.lab.mycorp.com"),
        # Oversize: should return None
        ("a" * 63, "b" * 63 + "." + "c" * 63 + "." + "d" * 63, None),
        ("", "zaa", None),
        ("lemur", "", None),
    ],
)
def test_qualify_name(name: str, suffix: str, expected) -> None:
    """Brief: qualify_name appends suffix when result fits DNS limits.

    Inputs:
      - name: base name
      - suffix: search suffix
      - expected: expected qualified name or None

    Outputs:
      - None
    """
    assert dns_names.qualify_name(name, suffix) == expected


@pytest.mark.parametrize(
    ("name", "single_label", "non_proper_tld", "mode", "expected"),
    [
        # Single-label gate
        ("lemur", True, False, "suffix", True),
        ("lemur", False, False, "suffix", False),
        # Absolute names (trailing dot in raw) are never qualified
        ("lemur.", True, False, "suffix", False),
        # Multi-label with proper TLD: not qualified
        ("lemur.com", True, False, "suffix", False),
        # Multi-label without proper TLD: qualify_non_proper_tld=True
        ("lemur.lab", True, True, "suffix", True),
        ("lemur.lab", True, False, "suffix", False),
        # List mode suffix: name ends with listed label
        ("foo.lab", True, ["lab", "prod"], "suffix", True),
        ("foo.bar", True, ["lab", "prod"], "suffix", False),
        ("www.prod", True, ["lab", "prod"], "suffix", True),
        # List mode exact: only the last label must match
        ("server1", True, ["server1", "server2"], "exact", True),
        ("foo.server1", True, ["server1", "server2"], "exact", False),
        ("server3", True, ["server1", "server2"], "exact", False),
        # Empty name
        ("", True, True, "suffix", False),
    ],
)
def test_should_qualify(
    name: str,
    single_label: bool,
    non_proper_tld,
    mode: str,
    expected: bool,
) -> None:
    """Brief: should_qualify respects single-label and non-proper-TLD gates.

    Inputs:
      - name/single_label/non_proper_tld/mode/expected: parametrized test inputs.

    Outputs:
      - None
    """
    result = dns_names.should_qualify(
        name,
        qualify_single_label=single_label,
        qualify_non_proper_tld=non_proper_tld,
        non_proper_tld_mode=mode,
    )
    assert result is expected
