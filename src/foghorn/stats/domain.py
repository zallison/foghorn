from __future__ import annotations

from foghorn.utils.register_caches import registered_lru_cached

# Heuristic support for common ccTLD + second-level public suffix patterns.
#
# This is intentionally a lightweight approximation (not a full Public Suffix List).
# It aims to correctly handle common forms such as:
#   - example.co.uk
#   - example.com.au
#   - example.co.jp
#
# Rules:
#   - When the TLD is a 2-letter ccTLD and the second-level label is in this set,
#     treat the registrable base as the last 3 labels.
#   - Otherwise treat the registrable base as the last 2 labels.
_CCTLD_SECOND_LEVEL_PUBLIC_SUFFIXES = {
    "ac",
    "com",
    "co",
    "edu",
    "gov",
    "net",
    "org",
}


@registered_lru_cached(maxsize=(16 * 1024))
def _normalize_domain(domain: str) -> str:
    """
    Normalize domain name for statistics tracking.

    Inputs:
        domain: Raw domain name string (may have trailing dot, mixed case)

    Outputs:
        Normalized lowercase domain without trailing dot

    Example:
        >>> _normalize_domain('Example.COM.')
        'example.com'
    """
    return domain.rstrip(".").lower()


@registered_lru_cached(maxsize=(16 * 1024))
def _base_domain(domain: str) -> str:
    """Return the registrable base domain for a name.

    Brief:
        Returns the base domain used for domain-oriented statistics (for example,
        the keys stored under the ``domains`` scope and the values tracked in
        ``top_domains``).

    Inputs:
        domain: Raw or normalized domain name string.

    Outputs:
        Normalized base domain string.

    Notes:
        This uses a lightweight heuristic (not a full Public Suffix List). It
        correctly handles common ccTLD patterns like ``example.co.uk`` by using
        the last three labels when the TLD is a 2-letter ccTLD and the second-
        level label is in ``_CCTLD_SECOND_LEVEL_PUBLIC_SUFFIXES``.

    Example:
        >>> _base_domain('www.example.com')
        'example.com'
        >>> _base_domain('www.example.co.uk')
        'example.co.uk'
    """
    norm = _normalize_domain(domain or "")
    if not norm:
        return ""

    parts = norm.split(".")
    if len(parts) < 2:
        return norm

    # ccTLD heuristic: example.co.uk, example.com.au, example.co.jp, ...
    if (
        len(parts) >= 3
        and len(parts[-1]) == 2
        and parts[-2] in _CCTLD_SECOND_LEVEL_PUBLIC_SUFFIXES
    ):
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


@registered_lru_cached(maxsize=(16 * 1024))
def _is_subdomain(domain: str) -> bool:
    """Return True if the name should be treated as a subdomain.

    Inputs:
        domain: Raw or normalized domain name string.

    Outputs:
        Boolean indicating whether the normalized name should be counted as a
        subdomain for statistics.

    Rules:
        - For most domains, at least three labels (e.g., 'www.example.com').
        - For common ccTLD + second-level public suffix patterns such as
          '*.co.uk' and '*.com.au', at least four labels (e.g.,
          'www.example.co.uk'), so that 'example.co.uk' itself is treated as a
          base domain, not a subdomain.

    Example:
        >>> _is_subdomain('www.example.com')
        True
        >>> _is_subdomain('example.com')
        False
        >>> _is_subdomain('www.example.co.uk')
        True
        >>> _is_subdomain('example.co.uk')
        False
    """
    norm = _normalize_domain(domain or "")
    if not norm:
        return False

    parts = norm.split(".")
    if len(parts) < 3:
        return False

    # ccTLD public-suffix heuristic: under e.g. *.co.uk the base is 3 labels, so
    # subdomains require at least one additional label.
    if (
        len(parts) >= 3
        and len(parts[-1]) == 2
        and parts[-2] in _CCTLD_SECOND_LEVEL_PUBLIC_SUFFIXES
    ):
        return len(parts) >= 4

    # Default: any name with at least three labels is a subdomain.
    return True
