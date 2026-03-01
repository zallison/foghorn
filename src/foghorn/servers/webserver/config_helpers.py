"""Configuration and YAML redaction helpers for the admin webserver.

This module contains helpers for working with the Foghorn configuration
mapping, including extracting the webserver subsection, computing redact-keys,
performing layout-preserving YAML redaction, and basic time/serialization
utilities.

The functions here were originally implemented in
:mod:`foghorn.servers.webserver.core` and are re-exported from there so that
existing imports via :mod:`foghorn.servers.webserver` continue to work.
"""

from __future__ import annotations

import copy
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import yaml

from foghorn.utils.register_caches import registered_lru_cached

# Short-lived cache for sanitized YAML configuration text returned by /config.
# The underlying on-disk config rarely changes, so a small TTL avoids repeated
# disk I/O and redaction work under frequent polling.
_CONFIG_TEXT_CACHE_TTL_SECONDS = 2.0
_CONFIG_TEXT_CACHE_LOCK = threading.Lock()
_last_config_text_key: tuple[str, tuple[str, ...]] | None = None
_last_config_text: str | None = None
_last_config_text_ts: float = 0.0


def _get_web_cfg(config: Dict[str, Any] | None) -> Dict[str, Any]:
    """Return the admin HTTP/webserver config subsection from a full config mapping.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - dict: Effective web configuration mapping.

    Notes:
      - Preferred v2 location: ``config['server']['http']``.
      - Legacy fallback (tests/older configs): ``config['webserver']``.
      - Centralising this avoids drift between FastAPI and threaded HTTP paths.
    """

    if not isinstance(config, dict):
        return {}

    server_cfg = config.get("server") or {}
    legacy = config.get("webserver")

    if isinstance(server_cfg, dict):
        http_cfg = server_cfg.get("http")
        if isinstance(http_cfg, dict):
            # Backwards-compatibility: some older configs/tests still place
            # fields such as auth under the legacy webserver block. Merge those
            # keys as defaults when they are not present in server.http.
            out: Dict[str, Any] = dict(http_cfg)
            if isinstance(legacy, dict):
                for k, v in legacy.items():
                    if k not in out:
                        out[k] = v
            return out

    return legacy if isinstance(legacy, dict) else {}


def _get_redact_keys(config: Dict[str, Any] | None) -> List[str]:
    """Determine which config keys should be redacted for /config endpoints.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - List of key names that should have their values redacted.

    Notes:
      - Preferred: ``webserver.redact_keys``.
      - Compatibility: also accepts ``server.http.redact_keys`` (v2-style config).
      - If neither is configured, falls back to a small default list of sensitive
        names ("token", "password", "secret").
    """

    web_cfg = _get_web_cfg(config)
    keys = web_cfg.get("redact_keys")

    if keys is None and isinstance(config, dict):
        server_cfg = config.get("server") or {}
        http_cfg = server_cfg.get("http") or {}
        if isinstance(http_cfg, dict):
            keys = http_cfg.get("redact_keys")

    if not keys:
        keys = ["token", "password", "secret"]

    if isinstance(keys, (list, tuple)):
        return [str(k) for k in keys]
    return [str(keys)]


def sanitize_config(
    cfg: Dict[str, Any], redact_keys: List[str] | None = None
) -> Dict[str, Any]:
    """Return a deep-copied, sanitized configuration with sensitive values redacted.

    Inputs:
      - cfg: Original configuration dictionary.
      - redact_keys: Optional list of key names to redact at any nesting level.

    Outputs:
      - New dict with sensitive values replaced by ``"***"``.

    Notes:
      - This implementation intentionally stays simple and conservative: if a
        top-level key or nested key name matches an entry in ``redact_keys``, its
        value is replaced with the placeholder.

    Example::

      cfg = {"webserver": {"auth": {"token": "secret"}}}
      clean = sanitize_config(cfg, ["token"])
      assert clean["webserver"]["auth"]["token"] == "***"
    """

    if not isinstance(cfg, dict):
        return {}
    redacted = copy.deepcopy(cfg)
    if not redact_keys:
        return redacted

    targets = set(str(k) for k in redact_keys)

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in list(node.items()):
                if str(key) in targets:
                    node[key] = "***"
                else:
                    _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(redacted)
    return redacted


def _get_sanitized_config_yaml_cached(
    cfg: Dict[str, Any], cfg_path: str | None, redact_keys: List[str] | None
) -> str:
    """Return sanitized configuration YAML text with a short-lived cache.

    Inputs:
      - cfg: In-memory configuration mapping.
      - cfg_path: Optional filesystem path to the active YAML config file.
      - redact_keys: List of key names whose values should be redacted.

    Outputs:
      - YAML string with sensitive values redacted.
    """

    global _last_config_text_key, _last_config_text, _last_config_text_ts

    key = (str(cfg_path or ""), tuple(sorted(str(k) for k in (redact_keys or []))))
    now = time.time()
    with _CONFIG_TEXT_CACHE_LOCK:
        if (
            _last_config_text is not None
            and _last_config_text_key == key
            and now - _last_config_text_ts < _CONFIG_TEXT_CACHE_TTL_SECONDS
        ):
            return _last_config_text

    # Cache miss: compute sanitized YAML text.
    if cfg_path:
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                raw_text = f.read()
            body = _redact_yaml_text_preserving_layout(raw_text, redact_keys or [])
        except Exception:  # pragma: no cover - I/O specific
            clean = sanitize_config(cfg, redact_keys=redact_keys or [])
            try:
                body = yaml.safe_dump(clean, sort_keys=False)  # type: ignore[arg-type]
            except Exception:
                body = ""
    else:
        clean = sanitize_config(cfg, redact_keys=redact_keys or [])
        try:
            body = yaml.safe_dump(clean, sort_keys=False)  # type: ignore[arg-type]
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            body = ""

    with _CONFIG_TEXT_CACHE_LOCK:
        _last_config_text_key = key
        _last_config_text = body
        _last_config_text_ts = time.time()
    return body


# Precompiled regexes for lightweight YAML redaction that preserves layout/comments.
_YAML_KEY_LINE_RE = re.compile(r"^(\s*)([^:\s][^:]*)\s*:(.*)$")
# List item that is itself a mapping entry, e.g. "  - suffix: example.com".
_YAML_LIST_KEY_LINE_RE = re.compile(r"^(\s*)-\s*([^:\s][^:]*)\s*:(.*)$")
_YAML_LIST_LINE_RE = re.compile(r"^(\s*)-\s*(.*)$")


def _split_yaml_value_and_comment(rest: str) -> Tuple[str, str]:
    """Split the portion of a YAML line after ':' or '-' into value and comment.

    Inputs:
      - rest: Substring after the ':' or '-' token, including any value and
        comment.

    Outputs:
      - Tuple ``(value, comment_suffix)`` where ``comment_suffix`` includes
        leading ``" #"`` when a comment is present, otherwise an empty string.
    """

    if "#" not in rest:
        return rest.rstrip(), ""
    before, comment = rest.split("#", 1)
    return before.rstrip(), " #" + comment


def _redact_yaml_text_preserving_layout(
    raw_yaml: str, redact_keys: List[str] | None
) -> str:
    """Redact sensitive keys in raw YAML text while preserving comments/spacing.

    Inputs:
      - raw_yaml: Original YAML document text as read from disk.
      - redact_keys: List of key names whose values and all nested subkeys
        should be redacted.

    Outputs:
      - New YAML text with the same overall layout and comments, but with
        matching keys and any keys/subkeys within their block replaced by
        ``"***"`` for scalar values only. Mapping (dict) and sequence (list)
        values are left intact at the key line, with nested scalars redacted
        within their block where possible.

    Notes:
      - This is a best-effort textual transformation intended for human-facing
        display (e.g., the admin UI). It is not a full YAML parser and may not
        handle all edge cases, but it preserves common constructs well.
      - Some callers may accidentally pass in YAML text that has been
        "double-escaped" such that literal ``"\\n"`` sequences appear in the
        content instead of real newlines (for example, when YAML is embedded
        inside JSON or logs). To keep the behavior predictable for these
        callers, we heuristically treat ``"\\n"`` sequences as real newlines
        before applying layout-preserving redaction.
    """

    if not raw_yaml or not redact_keys:
        return raw_yaml

    # Heuristic: collapse literal "\\n" sequences into real newlines so that
    # YAML constructed via double-escaping (e.g. "line1\\nline2") is treated
    # like on-disk multi-line YAML. This is a best-effort transformation for
    # admin display only and does not affect the underlying configuration.
    text = raw_yaml.replace("\\n", "\n") if "\\n" in raw_yaml else raw_yaml

    targets = {str(k) for k in redact_keys}
    lines = text.splitlines(keepends=False)
    out_lines: List[str] = []

    def _is_container_like(val: str) -> bool:
        """Best-effort check if an inline YAML value denotes a list or dict."""

        v = (val or "").lstrip()
        return v.startswith("[") or v.startswith("{")

    # Track a single active redaction block keyed by its indentation level.
    in_block = False
    block_indent: int | None = None

    for line in lines:
        stripped = line.lstrip(" ")
        indent_len = len(line) - len(stripped)

        # Empty or whitespace-only lines are passed through unchanged.
        if not stripped:
            out_lines.append(line)
            continue

        # If we are currently inside a redaction block and encounter a line that
        # is not more indented than the block, treat it as leaving the block
        # *before* processing the line below.
        if in_block and block_indent is not None and indent_len <= block_indent:
            in_block = False
            block_indent = None

        # Handle standard mapping key lines ("key: value").
        m_key = _YAML_KEY_LINE_RE.match(line)
        if m_key:
            indent, key, rest = m_key.groups()
            key_clean = key.strip()

            # Starting a new redaction block when the key itself is in targets.
            if key_clean in targets:
                # Determine the inline value (if any), excluding any trailing comment
                value_part, comment_part = _split_yaml_value_and_comment(rest)
                value_trim = value_part.strip()

                # Enter a block only when the key introduces a nested block
                # (i.e., nothing after ':' once comments are stripped).
                if not value_trim:
                    in_block = True
                    block_indent = indent_len
                    # Nothing to replace on this line; leave it as-is (no '***').
                    out_lines.append(line)
                    continue

                # If the inline value is a list/dict, do not replace with '***'.
                if _is_container_like(value_trim):
                    out_lines.append(line)
                    continue

                # Scalar inline value -> redact. Quote the placeholder so the
                # resulting YAML remains parseable (unquoted "***" is treated
                # as an alias token by YAML parsers).
                new_line = f"{indent}{key_clean}: '***'{comment_part}"
                out_lines.append(new_line)
                continue

            # Redact any keys nested under an active redaction block.
            if in_block:
                value_part, comment_part = _split_yaml_value_and_comment(rest)
                value_trim = value_part.strip()
                # Only redact scalars; when no inline value or container, keep as-is.
                if value_trim and not _is_container_like(value_trim):
                    new_line = f"{indent}{key_clean}: '***'{comment_part}"
                    out_lines.append(new_line)
                    continue
                # Keep original line if not a scalar inline value.
                out_lines.append(line)
                continue

        # Handle list items; a list item can be either "- value" or
        # "- key: value" (mapping entry inside a list).
        m_list_key = _YAML_LIST_KEY_LINE_RE.match(line)
        if m_list_key:
            indent, key, rest = m_list_key.groups()
            key_clean = key.strip()

            # If the key for this list-mapping entry is sensitive, redact it and
            # treat it as part of any active block.
            if key_clean in targets or in_block:
                value_part, comment_part = _split_yaml_value_and_comment(rest)
                value_trim = value_part.strip()

                # Enter block only when this list item starts a nested block.
                if key_clean in targets and not in_block and not value_trim:
                    in_block = True
                    block_indent = indent_len
                    out_lines.append(line)  # nothing to replace on this header line
                    continue

                # If inline value is a list/dict or absent, keep the line.
                if not value_trim or _is_container_like(value_trim):
                    out_lines.append(line)
                    continue

                # Scalar inline value -> redact.
                new_line = f"{indent}- {key_clean}: '***'{comment_part}"
                out_lines.append(new_line)
                continue

        # Redact simple list items nested under any redacted block ("- value").
        # This handles the case where a list of scalars lives under a previously
        # redacted mapping key; in practice this is a rare layout and the
        # mapping/list-key redaction above already covers the common cases.
        if in_block:  # pragma: no cover - low-value edge case for scalar-only lists
            m_list = _YAML_LIST_LINE_RE.match(line)
            if m_list:
                indent, rest = m_list.groups()
                value_part, comment_part = _split_yaml_value_and_comment(rest)
                value_trim = value_part.strip()
                # Only redact scalars; keep container or empty-as-header lines.
                if value_trim and not _is_container_like(value_trim):
                    new_line = f"{indent}- '***'{comment_part}"
                    out_lines.append(new_line)
                    continue
                out_lines.append(line)
                continue

        # Default: emit the original line unchanged.
        out_lines.append(line)

    redacted = "\n".join(out_lines)
    # Preserve a trailing newline if the original had one.
    if raw_yaml.endswith("\n") and not redacted.endswith("\n"):
        redacted += "\n"
    return redacted


def _get_config_raw_text(cfg_path: str) -> str:
    """Read and return the raw config YAML text from disk.

    Inputs:
      - cfg_path: Filesystem path to the YAML configuration file.

    Outputs:
      - Raw YAML text.
    """

    with open(cfg_path, "r", encoding="utf-8") as f:
        return f.read()


def _get_config_raw_json(cfg_path: str) -> Dict[str, Any]:
    """Read the on-disk YAML config and return both parsed mapping and raw text.

    Inputs:
      - cfg_path: Filesystem path to the YAML configuration file.

    Outputs:
      - Dict with keys: ``config`` (parsed mapping) and ``raw_yaml`` (exact
        text).
    """

    raw_text = _get_config_raw_text(cfg_path)
    raw_cfg = yaml.safe_load(raw_text) or {}
    return {"config": raw_cfg, "raw_yaml": raw_text}


def _ts_to_utc_iso(ts: float) -> str:
    """Convert a Unix timestamp (seconds) to an ISO8601 UTC string.

    Inputs:
      - ts: Unix timestamp in seconds.

    Outputs:
      - ISO8601 string in UTC (``"...Z"`` suffix).
    """

    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        dt = datetime.fromtimestamp(0.0, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


@registered_lru_cached(maxsize=1024)
def _parse_utc_datetime_cached(value: str, datetime_token: int) -> datetime:
    """Brief: Cached helper for _parse_utc_datetime.

    Inputs:
      - value: Datetime string.
      - datetime_token: Integer token included in the cache key so that tests
        which monkeypatch the module-level ``datetime`` do not accidentally hit
        a stale cached parse.

    Outputs:
      - timezone-aware :class:`datetime` in UTC.
    """
    # datetime_token is intentionally unused except as part of the cache key.
    _ = int(datetime_token)

    raw = str(value or "").strip()
    if not raw:
        raise ValueError("empty datetime")

    # ISO8601 (support trailing Z)
    iso = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
    except Exception:
        dt = None  # type: ignore[assignment]

    if dt is None:
        # Common non-ISO format used in config/UI
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                dt = datetime.strptime(raw, fmt)
                break
            except Exception:
                dt = None  # type: ignore[assignment]

    if dt is None:
        raise ValueError(f"invalid datetime: {raw}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def _parse_utc_datetime(value: str) -> datetime:
    """Parse a datetime string into an aware UTC :class:`datetime`.

    Brief:
      Accepts either ISO-8601-like strings (including a trailing ``"Z"``) or
      a simple space-separated format ``"YYYY-MM-DD HH:MM:SS"`` (optionally with
      fractional seconds).

    Inputs:
      - value: Datetime string.

    Outputs:
      - timezone-aware :class:`datetime` in UTC.

    Raises:
      - ValueError when parsing fails.
    """

    # Include the identity of the module-level datetime binding in the cache key
    # so that tests which monkeypatch `datetime` do not observe stale cache hits.
    return _parse_utc_datetime_cached(value, id(datetime))
