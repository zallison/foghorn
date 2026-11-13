"""Safe path resolution under an optional configured data_root.

Brief:
  Resolve relative filesystem paths against server.data_root and reject any
  path that escapes that root. Used by DNSSEC trust-anchor storage, EtcHosts
  file loaders, and JSON query-log backends to prevent config-supplied paths
  from reading or writing sensitive system files (for example /etc/shadow).

Inputs:
  - Configured data_root (or None for legacy unconstrained mode).
  - Caller-supplied path strings from YAML.

Outputs:
  - Absolute resolved path strings, or ValueError when containment fails.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

_LOCK = threading.Lock()
_DATA_ROOT: str | None = None


def get_data_root() -> str | None:
    """Brief: Return the active data_root path when configured.

    Inputs:
      - None.

    Outputs:
      - str | None: Absolute data_root set by set_data_root(), else None.
    """

    return _DATA_ROOT


def set_data_root(data_root: str | None) -> None:
    """Brief: Record the active data_root for path containment checks.

    Inputs:
      - data_root: Directory path, or None to disable containment enforcement.

    Outputs:
      - None. Updates the module-global root under lock.
    """

    global _DATA_ROOT
    with _LOCK:
        if data_root is None or not str(data_root).strip():
            _DATA_ROOT = None
            return
        _DATA_ROOT = str(
            Path(str(data_root).strip()).expanduser().resolve(strict=False)
        )


def resolve_data_root(
    raw: object | None,
    *,
    config_path: str | None = None,
) -> str | None:
    """Brief: Normalize a configured data_root value to an absolute directory.

    Inputs:
      - raw: server.data_root value (str path) or None/empty.
      - config_path: Optional active config file path (unused when raw is set;
        reserved for future defaulting).

    Outputs:
      - str | None: Absolute directory path, or None when data_root is unset
        (legacy mode: no containment enforcement).

    Notes:
      - When raw is set, the directory need not exist yet; resolve(strict=False).
      - config_path is accepted for API symmetry with TLS helpers but is not
        currently used as an implicit default (operators must set data_root).
    """

    del config_path  # reserved
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    return str(Path(text).expanduser().resolve(strict=False))


def _is_within(path: Path, base: Path) -> bool:
    """Brief: Return True when path is base or a descendant of base.

    Inputs:
      - path: Candidate filesystem path.
      - base: Allowed root directory.

    Outputs:
      - bool
    """

    try:
        path_r = path.expanduser().resolve(strict=False)
        base_r = base.expanduser().resolve(strict=False)
        path_r.relative_to(base_r)
        return True
    except Exception:
        return False


def enforce_data_root_path(
    path: object,
    *,
    data_root: str | None = None,
    kind: str = "path",
    must_exist: bool = False,
) -> str:
    """Brief: Expand, resolve, and optionally contain a configurable file path.

    Inputs:
      - path: Raw path from configuration (str-like).
      - data_root: Optional root directory. When None, uses get_data_root().
        When still None after that, only expanduser/abspath (no containment).
      - kind: Short label for error messages (e.g. "EtcHosts file", "JSON log").
      - must_exist: When True, raise if the resolved path is not an existing file.

    Outputs:
      - str: Absolute resolved path.

    Raises:
      - ValueError: When path is empty, escapes data_root, or must_exist fails.

    Example:
      >>> enforce_data_root_path("logs/q.json", data_root="/var/foghorn")  # doctest: +SKIP
      '/var/foghorn/logs/q.json'
    """

    raw = str(path or "").strip()
    if not raw:
        raise ValueError(f"{kind} path must be a non-empty string")

    root = data_root if data_root is not None else get_data_root()
    candidate = Path(raw).expanduser()

    if root:
        base = Path(str(root)).expanduser().resolve(strict=False)
        if candidate.is_absolute():
            resolved = candidate.resolve(strict=False)
        else:
            resolved = (base / candidate).resolve(strict=False)
        if not _is_within(resolved, base):
            raise ValueError(
                f"{kind} path {str(resolved)!r} must be under data_root {str(base)!r} "
                f"(server.data_root)"
            )
    else:
        # Legacy unconstrained mode: preserve expanduser + absolute resolution.
        resolved = Path(os.path.abspath(str(candidate)))

    if must_exist and not resolved.is_file():
        raise ValueError(
            f"{kind} path {str(resolved)!r} does not exist or is not a file"
        )

    return str(resolved)


def enforce_data_root_paths(
    paths: list[object] | tuple[object, ...] | None,
    *,
    data_root: str | None = None,
    kind: str = "path",
) -> list[str]:
    """Brief: Enforce data_root containment for a list of paths.

    Inputs:
      - paths: Iterable of raw path values.
      - data_root: Optional root override (see enforce_data_root_path).
      - kind: Label for error messages.

    Outputs:
      - list[str]: Resolved absolute paths in input order.

    Raises:
      - ValueError: When any path is invalid or escapes data_root.
    """

    out: list[str] = []
    for idx, item in enumerate(paths or []):
        label = f"{kind}[{idx}]"
        out.append(enforce_data_root_path(item, data_root=data_root, kind=label))
    return out
