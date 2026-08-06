"""Shared helpers for admin webserver tests.

These helpers keep production defaults secure (feature gates off) while
preserving the historically open surface that most webserver tests expect.
"""

from __future__ import annotations

from typing import Any


_DEFAULT_FEATURE_GATES = {
    "enable_api": True,
    "enable_admin": True,
    "enable_schema": True,
    "enable_docs": True,
}


def normalize_web_cfg_layout(
    config: dict[str, Any] | None,
    *,
    enable_default_feature_gates: bool = True,
    default_auth_mode: str | None = "none",
) -> dict[str, Any] | None:
    """Brief: Normalize legacy webserver config and optional test defaults.

    Inputs:
      - config: Optional application config mapping used by webserver tests.
      - enable_default_feature_gates: When true, fill missing enable_* keys with
        True so existing tests keep the historical open surface.
      - default_auth_mode: When not None, set auth.mode if unset. Pass None to
        leave production auth defaults alone.

    Outputs:
      - dict | None: Config mapping with server.http populated from legacy
        webserver when server.http is absent, plus optional test defaults.
    """

    if not isinstance(config, dict):
        return config

    normalized = dict(config)
    legacy_web_cfg = normalized.get("webserver")
    server_cfg = normalized.get("server")
    if isinstance(legacy_web_cfg, dict):
        if not isinstance(server_cfg, dict):
            server_cfg = {}
            normalized["server"] = server_cfg
        if not isinstance(server_cfg.get("http"), dict):
            server_cfg["http"] = dict(legacy_web_cfg)

    if enable_default_feature_gates or default_auth_mode is not None:
        server_cfg = normalized.get("server")
        if not isinstance(server_cfg, dict):
            server_cfg = {}
            normalized["server"] = server_cfg
        http_cfg = server_cfg.get("http")
        if not isinstance(http_cfg, dict):
            http_cfg = {}
            server_cfg["http"] = http_cfg
        if enable_default_feature_gates:
            for key, value in _DEFAULT_FEATURE_GATES.items():
                http_cfg.setdefault(key, value)
        if default_auth_mode is not None:
            auth_cfg = http_cfg.get("auth")
            if not isinstance(auth_cfg, dict):
                auth_cfg = {}
                http_cfg["auth"] = auth_cfg
            auth_cfg.setdefault("mode", default_auth_mode)

    return normalized
