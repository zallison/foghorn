"""Brief: Shared DNS name and token helpers.

Inputs/Outputs:
  - Normalization helpers for DNS/QNAME strings.
  - Token validation helpers used by multiple list parsers.
  - Qname search-domain qualification helpers.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Set, Union, Final

from foghorn.utils.register_caches import registered_lru_cached

# DNS limits per RFC 1035
_DNS_MAX_NAME_LEN: Final[int] = 253
_DNS_MAX_LABEL_LEN: Final[int] = 63


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


def is_single_label(name: str) -> bool:
    """Brief: Return True when the normalized name has exactly one label (no dots).

    Inputs:
      - name: Domain name string (trailing dot stripped automatically).

    Outputs:
      - bool: True for e.g. 'lemur', False for 'lemur.example'.

    Example:
      >>> is_single_label('lemur')
      True
      >>> is_single_label('lemur.zaa')
      False
    """
    norm = normalize_name(name)
    if not norm:
        return False
    return "." not in norm


# Common gTLDs that clearly look like public TLDs (non-exhaustive).
_KNOWN_GTLDS: frozenset[str] = frozenset(
    {
        "com",
        "net",
        "org",
        "gov",
        "edu",
        "mil",
        "int",
        "info",
        "biz",
        "pro",
        "name",
        "mobi",
        "aero",
        "coop",
        "museum",
        "travel",
        "jobs",
        "tel",
        "cat",
        "post",
        "xxx",
        "xxx",
        "io",
        "co",
        "ai",
        "app",
        "dev",
        "cloud",
        "tech",
        "online",
        "site",
        "shop",
        "store",
        "club",
        "wiki",
        "news",
        "media",
        "film",
        "blog",
        "host",
        "agency",
        "group",
        "team",
    }
)


def has_proper_tld(name: str) -> bool:
    """Brief: Heuristic: does name end with a label that looks like a real/public TLD.

    Inputs:
      - name: Domain name string (trailing dot stripped automatically).

    Outputs:
      - bool: True when the right-most label is likely a delegated public TLD,
        False for purely local/search labels like 'lab', 'prod', 'corp', 'lan' etc.

    Notes:
      - This is a lightweight heuristic; it does not consult the full PSL.
      - Single-label names always return False (no TLD at all).
      - Numeric-only TLDs (e.g. IPv4-like right-labels) return False.
      - 'local' and known local-only labels return False (mDNS pseudo-TLD).
      - 2-char labels are treated as country-code TLDs (ccTLDs), except 'co' which
        is always listed in _KNOWN_GTLDS.
      - 3+ char labels must be in _KNOWN_GTLDS or >= 7 chars (new gTLD range).
    """
    norm = normalize_name(name)
    if not norm or "." not in norm:
        return False
    labels = norm.split(".")
    tld = labels[-1]
    if not tld:
        return False
    # Must be purely alphabetic; reject numeric or hyphenated right-labels.
    if not tld.isalpha():
        return False
    # Excluded local pseudo-TLDs.
    if tld in {"local", "localhost", "internal", "invalid", "example", "test"}:
        return False
    # 2-char labels are ccTLDs (uk, de, fr, jp, au, ...).
    if len(tld) == 2:
        return True
    # 3-6 char labels must be in the known gTLD set; otherwise treat as local.
    if 3 <= len(tld) <= 6:
        return tld in _KNOWN_GTLDS
    # 7+ char labels (new gTLD space, e.g. .academy, .network) are treated as proper.
    return True


def qualify_name(
    name: str,
    suffix: str,
) -> Optional[str]:
    """Brief: Append suffix to name and return the result if within DNS length limits.

    Inputs:
      - name: Normalized domain name string (no trailing dot).
      - suffix: Normalized search suffix to append (no trailing dot).

    Outputs:
      - str: Qualified name (e.g. 'lemur.zaa') when within limits.
      - None: When the resulting name would violate RFC 1035 length limits.

    Example:
      >>> qualify_name('lemur', 'zaa')
      'lemur.zaa'
      >>> qualify_name('lemur', 'example.com')
      'lemur.example.com'
    """
    if not name or not suffix:
        return None
    candidate = f"{name}.{suffix}"
    # Full wire-encoded length: each label gets a length octet plus the root "."
    # The RFC 1035 limit of 255 octets for the full wire encoding corresponds to
    # 253 printable characters (excluding the two length octets for the first and
    # last labels). We use the conservative 253-char limit on the printable form.
    if len(candidate) > _DNS_MAX_NAME_LEN:
        return None
    # Validate each label of the resulting name.
    for label in candidate.split("."):
        if not label or len(label) > _DNS_MAX_LABEL_LEN:
            return None
    return candidate


def should_qualify(
    name: str,
    *,
    qualify_single_label: bool = True,
    qualify_non_proper_tld: Union[bool, List[str], Set[str]] = False,
    non_proper_tld_mode: str = "suffix",
) -> bool:
    """Brief: Decide whether name should be search-qualified.

    Inputs:
      - name: Normalized domain name string (no trailing dot).
      - qualify_single_label: When True, single-label names always qualify (default True).
        In list-based exact mode this flag is bypassed so the list exclusively controls
        which names are qualified (including single-label names not in the list).
      - qualify_non_proper_tld: Controls qualification for names without a proper TLD:
          * True  - qualify any name that lacks a proper TLD.
          * False - never qualify based on TLD heuristic (default).
          * list/set of strings - qualify only when the name matches one of these entries
            according to non_proper_tld_mode.
      - non_proper_tld_mode: When qualify_non_proper_tld is a list, controls matching:
          * 'suffix' (default) - name equals or ends with an entry (label-wise).
          * 'exact' - the entire normalized name must equal one of the entries.
            In this mode the single-label gate is bypassed so the list can also
            restrict single-label names that are not in the list.

    Outputs:
      - bool: True when the name should be qualified by appending the search suffix.

    Notes:
      - A name ending with a trailing dot (absolute) is never qualified.
      - A name that already has a proper TLD is not qualified.
      - In list/exact mode, the list acts as an allowlist: only names that exactly
        match a list entry are qualified, regardless of qualify_single_label.

    Example:
      >>> should_qualify('lemur', qualify_single_label=True)
      True
      >>> should_qualify('foo.lab', qualify_non_proper_tld=['lab'])
      True
      >>> should_qualify('foo.com', qualify_non_proper_tld=['lab'])
      False
      >>> should_qualify('server3', qualify_single_label=True,
      ...                qualify_non_proper_tld=['server1'], non_proper_tld_mode='exact')
      False
    """
    if not name:
        return False

    norm = normalize_name(name)
    if not norm:
        return False

    # Absolute names (user explicitly terminated with dot) are never qualified.
    # By the time we see them, the trailing dot has been stripped by normalize_name,
    # but the original passed by the resolver pipeline still carries it if it was
    # an FQDN. We check the raw name here.
    raw = str(name).strip()
    if raw.endswith("."):
        return False

    # In list-based exact mode, the list acts as a full allowlist and bypasses
    # the single-label gate so non-matching single-label names are NOT qualified.
    _mode = str(non_proper_tld_mode or "suffix").strip().lower()
    _is_exact_list = _mode == "exact" and not isinstance(qualify_non_proper_tld, bool)

    # Single-label names (skip this gate in list-exact mode).
    if is_single_label(norm) and not _is_exact_list:
        return bool(qualify_single_label)

    # Names with a proper TLD: not qualified (they look like real FQDNs).
    if has_proper_tld(norm):
        return False

    # Names without a proper TLD:
    if qualify_non_proper_tld is True:
        return True

    if qualify_non_proper_tld is False:
        return False

    # List/set of strings to match against.
    try:
        entries: List[str] = [
            normalize_name(e) for e in qualify_non_proper_tld if normalize_name(e)
        ]
    except Exception:
        return False
    if not entries:
        return False

    for entry in entries:
        if _mode == "exact":
            # Entire normalized name must equal the entry exactly.
            if norm == entry:
                return True
        else:
            # suffix mode: name equals or ends with entry label-wise.
            if norm == entry or norm.endswith("." + entry):
                return True

    return False
