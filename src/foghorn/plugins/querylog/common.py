from __future__ import annotations

"""Common helpers shared by querylog backend implementations.

Inputs:
  - Utility functions consume raw domain-name text.

Outputs:
  - Normalized domain-name strings and subdomain classification booleans used by
    rebuild and query filtering logic across multiple backends.
"""


def normalize_domain(domain: str) -> str:
    """Normalize domain name for statistics tracking.

    Inputs:
        domain: Raw domain name string (may have trailing dot, mixed case).

    Outputs:
        Normalized lowercase domain without trailing dot.
    """

    from foghorn.utils import dns_names

    return dns_names.normalize_name(domain)


def is_subdomain(domain: str) -> bool:
    """Return True if the name should be treated as a subdomain.

    Inputs:
        domain: Raw or normalized domain name string.

    Outputs:
        Boolean indicating whether the normalized name should be counted as a
        subdomain for statistics aggregation.
    """

    norm = normalize_domain(domain or "")
    if not norm:
        return False

    parts = norm.split(".")
    if len(parts) < 3:
        return False

    if len(parts) >= 3 and parts[-2:] == ["co", "uk"]:
        return len(parts) >= 4

    return True
