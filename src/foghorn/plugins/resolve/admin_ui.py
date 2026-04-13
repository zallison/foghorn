"""Brief: Helper utilities for resolve plugin admin UI snapshots.

Inputs/Outputs:
  - Provide small helpers to build JSON-safe admin snapshots for plugins.
  - Provide conservative redaction for common secret-like config keys.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional


def _fallback_sanitize_config(
    cfg: Dict[str, Any], redact_keys: List[str] | None = None
) -> Dict[str, Any]:
    """Fallback sanitize_config when webserver helpers are unavailable.

    Inputs:
      - cfg: Original config dictionary.
      - redact_keys: Optional list of key names to redact.

    Outputs:
      - Deep-ish sanitized dict (best-effort). Values for matching keys are
        replaced by '***'.
    """

    if not isinstance(cfg, dict):
        return {}
    if not redact_keys:
        return dict(cfg)
    targets = {str(k).lower() for k in redact_keys}

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            out: Dict[str, Any] = {}
            for k, v in node.items():
                key_str = str(k).lower()
                if any(target in key_str for target in targets):
                    out[str(k)] = "***"
                else:
                    out[str(k)] = _walk(v)
            return out
        if isinstance(node, list):
            return [_walk(x) for x in node]
        return node

    return _walk(cfg)


try:
    # Prefer the canonical redaction logic used by the admin webserver.
    from foghorn.servers.webserver.config_helpers import sanitize_config
except Exception:  # pragma: no cover - defensive fallback
    sanitize_config = _fallback_sanitize_config


DEFAULT_REDACT_KEYS = [
    # NOTE: These entries are key-name patterns only. Embedded credentials
    # inside values (for example URL userinfo) are handled separately.
    "token",
    "password",
    "secret",
    "key",
    "api_key",
    "apikey",
    "psk",
    "hmac_key",
    "signing_key",
    "key_file",
    "cert",
    "tls_cert",
    "dsn",
    "connection_string",
    "proxy",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "ssh_private_key",
    "authorization",
    "bearer",
]
_URL_USERINFO_RE = re.compile(r"://[^@]+@")


def _make_deepcopy_safe(value: Any) -> Any:
    """Brief: Convert arbitrary values into a deepcopy-safe structure.

    Inputs:
      - value: Any Python object.

    Outputs:
      - A structure composed only of JSON-like primitives (dict/list/str/int/float/bool/None)
        so that downstream helpers (notably foghorn.servers.webserver.config_helpers.sanitize_config)
        can safely copy/redact it.

    Notes:
      - Tuples/sets are converted into lists.
      - Unknown object types are converted to a fixed non-sensitive placeholder.
      - This primarily exists because config_parser injects a live cache instance into
        every plugin config under the key "cache". Some cache implementations contain
        non-pickleable locks (e.g. RLock), which breaks copy.deepcopy().
    """

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return str(value)

    if isinstance(value, dict):
        return {str(k): _make_deepcopy_safe(v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_make_deepcopy_safe(v) for v in value]

    # For any other object (cache instances, regex objects, sockets, etc.), use a
    # fixed non-sensitive placeholder.
    return "<object>"


def _redact_url_userinfo(value: str) -> str:
    """Brief: Redact URL userinfo while preserving scheme and host.

    Inputs:
      - value: Potential URL-like string.

    Outputs:
      - String where URL userinfo segments are replaced with '***'.
    """

    return _URL_USERINFO_RE.sub("://***@", str(value))


def _mask_url_userinfo_for_keys(node: Any) -> Any:
    """Brief: Recursively mask URL userinfo for url/endpoint-like keys.

    Inputs:
      - node: Arbitrary JSON-like structure.

    Outputs:
      - Structure with URL credentials masked for url/endpoint keys.
    """

    if isinstance(node, dict):
        out: Dict[str, Any] = {}
        for k, v in node.items():
            key_str = str(k).lower()
            if isinstance(v, str) and ("url" in key_str or "endpoint" in key_str):
                out[str(k)] = _redact_url_userinfo(v)
            else:
                out[str(k)] = _mask_url_userinfo_for_keys(v)
        return out
    if isinstance(node, list):
        return [_mask_url_userinfo_for_keys(v) for v in node]
    return node


def _truncate(text: str, max_len: int = 200) -> str:
    """Brief: Truncate long strings for table display.

    Inputs:
      - text: Original string.
      - max_len: Maximum allowed length. When <= 0, truncation is disabled.

    Outputs:
      - Possibly truncated string.
    """

    s = str(text)
    if max_len > 0 and len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def _stringify_value(value: Any, *, max_len: int = 200) -> str:
    """Brief: Convert arbitrary values into a short, JSON-safe string.

    Inputs:
      - value: Any object.
      - max_len: Maximum length of the resulting string.

    Outputs:
      - str: A display-friendly representation.

    Notes:
      - Sequences show at most the first 50 items.
      - Dicts attempt json.dumps(...); when that fails, they fall back to str(value).
    """

    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return _truncate(value, max_len=max_len)
    if isinstance(value, (list, tuple, set)):
        parts = []
        for v in list(value)[:50]:
            parts.append(_stringify_value(v, max_len=80))
        suffix = ""
        if len(value) > 50:
            suffix = f" (+{len(value) - 50} more)"
        return _truncate(", ".join(parts) + suffix, max_len=max_len)
    if isinstance(value, dict):
        try:
            return _truncate(json.dumps(value, sort_keys=True), max_len=max_len)
        except Exception:
            return _truncate(str(value), max_len=max_len)

    return _truncate(str(value), max_len=max_len)


def config_to_items(
    cfg: Dict[str, Any] | None,
    *,
    redact_keys: Optional[List[str]] = None,
    max_value_len: int = 200,
) -> List[Dict[str, str]]:
    """Brief: Convert a config mapping to a list of key/value rows.

    Inputs:
      - cfg: Raw config mapping.
      - redact_keys: Key names to redact at any nesting level.
      - max_value_len: Max string length for values.

    Outputs:
      - list[dict]: Rows with keys: key, value.

    Notes:
      - The output is one row per *top-level* key in cfg (the mapping is not
        flattened).
      - Values are stringified so the frontend table renderer displays them
        predictably.
    """

    if not isinstance(cfg, dict):
        return []

    keys = redact_keys if redact_keys is not None else DEFAULT_REDACT_KEYS

    # Ensure cfg is safe to deepcopy (sanitize_config currently uses copy.deepcopy).
    safe_cfg = _make_deepcopy_safe(cfg)
    if not isinstance(safe_cfg, dict):
        safe_cfg = {}

    clean = sanitize_config(safe_cfg, redact_keys=list(keys or []))
    clean = _mask_url_userinfo_for_keys(clean)

    out: List[Dict[str, str]] = []
    for k in sorted(clean.keys()):
        out.append(
            {
                "key": str(k),
                "value": _stringify_value(clean.get(k), max_len=max_value_len),
            }
        )
    return out


def limit_rows(
    rows: Iterable[Dict[str, Any]], limit: int = 200
) -> List[Dict[str, Any]]:
    """Brief: Return at most N rows from an iterable.

    Inputs:
      - rows: Iterable of row dicts.
      - limit: Maximum row count to return.

    Outputs:
      - list[dict]: First N rows.
    """

    out: List[Dict[str, Any]] = []
    if limit <= 0:
        return out
    for row in rows:
        out.append(row)
        if len(out) >= limit:
            break
    return out
