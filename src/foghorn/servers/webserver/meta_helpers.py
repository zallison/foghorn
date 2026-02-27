from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import os
from typing import Any, Dict

from .stats_helpers import _utc_now_iso

_GITHUB_URL = "https://github.com/zallison/foghorn"

try:  # pragma: no cover - defensive fallback matches _core behaviour
    FOGHORN_VERSION = importlib_metadata.version("foghorn")
except Exception:  # pragma: no cover - best effort
    FOGHORN_VERSION = "unknown"


def _get_package_build_info() -> Dict[str, Any]:
    """Brief: Best-effort build metadata (commit, VCS url, etc.) from packaging.

    Inputs: none

    Outputs:
      - dict with keys:
          * git_sha: str|None
          * vcs_url: str|None
          * requested_revision: str|None
          * build_time: str|None
          * build_id: str|None

    Notes:
      - Prefers environment variables so container builds can inject stable build
        identifiers.
      - Falls back to PEP 610 direct_url.json metadata when available.
    """

    info: Dict[str, Any] = {
        "git_sha": None,
        "vcs_url": None,
        "requested_revision": None,
        "build_time": None,
        "build_id": None,
    }

    # Environment variable overrides (common in CI/container builds).
    for key, out_key in (
        ("FOGHORN_GIT_SHA", "git_sha"),
        ("GIT_SHA", "git_sha"),
        ("FOGHORN_BUILD_TIME", "build_time"),
        ("BUILD_TIME", "build_time"),
        ("FOGHORN_BUILD_ID", "build_id"),
        ("BUILD_ID", "build_id"),
    ):
        val = os.environ.get(key)
        if val and not info.get(out_key):
            info[out_key] = str(val)

    # PEP 610 direct_url.json (useful for editable installs from VCS).
    try:
        dist = importlib_metadata.distribution("foghorn")
        direct = dist.read_text("direct_url.json")
        if direct:
            payload = json.loads(direct)
            vcs_info = payload.get("vcs_info") if isinstance(payload, dict) else None
            if isinstance(vcs_info, dict):
                if not info.get("git_sha") and vcs_info.get("commit_id"):
                    info["git_sha"] = str(vcs_info.get("commit_id"))
                if vcs_info.get("requested_revision") and not info.get(
                    "requested_revision"
                ):
                    info["requested_revision"] = str(vcs_info.get("requested_revision"))
            if payload.get("url") and not info.get("vcs_url"):
                info["vcs_url"] = str(payload.get("url"))
    except Exception:  # pragma: no cover - best effort
        pass

    return info


def _get_about_payload() -> Dict[str, Any]:
    """Brief: Build the lightweight /about payload.

    Inputs: none

    Outputs:
      - dict containing version, build info, and the project GitHub URL.
    """

    build = _get_package_build_info()
    # Only include non-empty build fields to keep the payload compact.
    build_clean = {k: v for k, v in build.items() if v}
    return {
        "server_time": _utc_now_iso(),
        "version": FOGHORN_VERSION,
        "github_url": _GITHUB_URL,
        "build": build_clean,
    }
