"""Brief: Shared DNS name and token helpers.

Inputs/Outputs:
  - Normalization helpers for DNS/QNAME strings.
  - Token validation helpers used by multiple list parsers.
"""

from __future__ import annotations

from typing import Iterable, List

from foghorn.utils.register_caches import registered_lru_cached


@registered_lru_cached(maxsize=65_536)
def _normalize_name_text(
    text: str,
    *,
    lower: bool = True,
    strip_trailing_dot: bool = True,
    strip_whitespace: bool = True,
) -> str:
    """Brief: Cached core normalizer for DNS name-like strings.

    Inputs:
      - text: Input string to normalize.
      - lower: When True, lower-case the result (default True).
      - strip_trailing_dot: When True, remove a trailing '.' (default True).
      - strip_whitespace: When True, strip surrounding whitespace (default True).

    Outputs:
      - str: Normalized name string.
    """
    if strip_whitespace:
        text = text.strip()
    if strip_trailing_dot:
        text = text.rstrip(".")
    if lower:
        text = text.lower()
    return text


def normalize_name(
    value: object,
    *,
    lower: bool = True,
    strip_trailing_dot: bool = True,
    strip_whitespace: bool = True,
) -> str:
    """Brief: Normalize a DNS name-like value to a consistent string.

    Inputs:
      - value: Domain/QNAME-like object (string or label-like).
      - lower: When True, lower-case the result (default True).
      - strip_trailing_dot: When True, remove a trailing '.' (default True).
      - strip_whitespace: When True, strip surrounding whitespace (default True).

    Outputs:
      - str: Normalized name string (may be empty).

    Example:
      >>> normalize_name("Example.COM. ")
      'example.com'
    """
    try:
        text = str(value)
    except Exception:  # pragma: no cover - defensive
        text = ""
    return _normalize_name_text(
        text,
        lower=lower,
        strip_trailing_dot=strip_trailing_dot,
        strip_whitespace=strip_whitespace,
    )


def normalize_name_list(values: Iterable[object]) -> List[str]:
    """Brief: Normalize a list of DNS names.

    Inputs:
      - values: Iterable of name-like objects.

    Outputs:
      - list[str]: Normalized names with empties removed.
    """
    out: List[str] = []
    for item in values or []:
        norm = normalize_name(item)
        if norm:
            out.append(norm)
    return out


@registered_lru_cached(maxsize=32768)
def is_suffix_match(name: str, suffix: str) -> bool:
    """Brief: Check whether name matches suffix (exact or subdomain).

    Inputs:
      - name: Candidate name (may include trailing dot).
      - suffix: Suffix to match (may include trailing dot).

    Outputs:
      - bool: True when name == suffix or ends with ".suffix".
    """
    name_norm = normalize_name(name)
    suffix_norm = normalize_name(suffix)
    if not name_norm or not suffix_norm:
        return False
    return name_norm == suffix_norm or name_norm.endswith("." + suffix_norm)


@registered_lru_cached(maxsize=655_360)
def is_plain_domain_token(token: str) -> bool:
    """Brief: Validate a plain domain token (Filter list semantics).

    Inputs:
      - token: Candidate token string.

    Outputs:
      - bool: True when token is a plain DNS-style name.

    Notes:
      - Mirrors Filter._is_plain_domain_token behavior (no wildcard/AdGuard chars).
      - Underscores are accepted in labels to support list entries that include
        service-style or vendor-specific DNS labels.
    """
    text = str(token).strip().rstrip(".")
    if not text or any(ch.isspace() for ch in text):
        return False
    if any(ch in text for ch in ("/", "=", "@", "|", "^", "$", "\\")):
        return False
    labels = text.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        for ch in label:
            if not (ch.isalnum() or ch in {"-", "_"}):
                return False
    return True


def is_list_domain_token(token: str) -> bool:
    """Brief: Validate a domain token from list files (FileDownloader semantics).

    Inputs:
      - token: Raw token string after comment stripping.

    Outputs:
      - bool: True when token is a valid DNS-style domain name.

    Notes:
      - Mirrors FileDownloader._is_valid_domain_token behavior.
      - Underscores are accepted in labels to support common blocklist formats.
    """
    if any(ch.isspace() for ch in token):
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in token):
        return False
    name = str(token).rstrip(".")
    if not name or len(name) > 253 or "." not in name:
        return False
    labels = name.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        for ch in label:
            if not (ch.isalnum() or ch in {"-", "_"}):
                return False
    return True
