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
