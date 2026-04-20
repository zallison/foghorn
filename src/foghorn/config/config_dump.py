"""Config expansion and dumping helpers.

Brief:
  This module provides a small utility for rendering a Foghorn YAML config as an
  "effective" config for debugging and tooling:
    - variables are expected to already be expanded by config_schema.validate_config
    - core runtime defaults (listener enable flags, ports, webserver defaults, etc.)
      are filled in so the output is explicit.

Inputs:
  - A parsed configuration mapping (typically from parse_config_file).

Outputs:
  - A deep-copied configuration mapping with best-effort defaults applied.
  - Serialized YAML/JSON output.

Notes:
  - This is intentionally best-effort and focuses on the defaults/normalization
    performed by foghorn.main.
  - The JSON Schema in assets/config-schema.json does not currently encode all
    runtime defaults; this module exists to make runtime behavior explicit.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Dict

import yaml

from foghorn.config.config_parser import (
    normalize_upstream_backup_config,
    normalize_upstream_config,
)
from foghorn.servers.overload_response import normalize_overload_response


def build_effective_config_for_display(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Brief: Build a display-friendly config with runtime defaults made explicit.

    Inputs:
      - cfg: Parsed configuration mapping (usually from parse_config_file). This
        mapping is not mutated.

    Outputs:
      - dict: Deep-copied configuration mapping with core runtime defaults
        inserted. Only keys already used by foghorn.main / admin webserver are
        filled; unknown keys are preserved.
      - When cfg is not a mapping, returns an empty dict.

    Example:
      >>> out = build_effective_config_for_display({'server': {'resolver': {'mode': 'forward'}}})
      >>> isinstance(out, dict)
      True
    """

    if not isinstance(cfg, dict):
        return {}

    out: Dict[str, Any] = copy.deepcopy(cfg)

    server_cfg = out.get("server")
    if not isinstance(server_cfg, dict):
        server_cfg = {}
        out["server"] = server_cfg

    _expand_server_listen_defaults(server_cfg)
    _expand_server_resolver_defaults(server_cfg)
    _expand_server_dnssec_defaults(server_cfg)
    _expand_server_limits_defaults(server_cfg)
    _expand_server_http_defaults(server_cfg)
    _expand_server_feature_flags(server_cfg)

    # Top-level blocks used by foghorn.main.
    if "plugins" not in out or not isinstance(out.get("plugins"), list):
        out["plugins"] = []

    _expand_upstreams_defaults(out)
    _expand_logging_defaults(out)

    return out


def dump_config_text(cfg: Dict[str, Any], *, fmt: str = "yaml") -> str:
    """Brief: Serialize a config mapping to YAML or JSON.

    Inputs:
      - cfg: Configuration mapping to dump.
      - fmt: 'yaml' (default) or 'json'.

    Outputs:
      - str: Serialized text.
    """

    f = str(fmt or "yaml").strip().lower()
    if f == "json":
        return json.dumps(cfg, indent=2, sort_keys=False) + "\n"

    # YAML output.
    return yaml.safe_dump(cfg, sort_keys=False)  # type: ignore[arg-type]


def _expand_server_listen_defaults(server_cfg: Dict[str, Any]) -> None:
    """Brief: Fill in server.listen defaults (udp/tcp/dot/doh).

    Inputs:
      - server_cfg: server config mapping (mutated in-place).

    Outputs:
      - None.

    Notes:
      - Mirrors the logic in foghorn.main for listener default enablement.
      - Adds explicit udp/tcp/dot/doh blocks even when the config omitted them,
        so the effective config is fully explicit.
    """

    listen_cfg = server_cfg.get("listen")
    if not isinstance(listen_cfg, dict):
        listen_cfg = {}
        server_cfg["listen"] = listen_cfg

    dns_cfg = listen_cfg.get("dns")
    if not isinstance(dns_cfg, dict):
        dns_cfg = {}

    # Listener defaults are sourced from listen.dns when present; otherwise
    # they fall back to hard-coded defaults.
    raw_host = dns_cfg.get("host", "127.0.0.1")
    raw_port = dns_cfg.get("port", 5335)

    default_host = str(raw_host)
    try:
        default_port = int(raw_port)
    except (TypeError, ValueError):
        default_port = 5335

    global_overload_configured = "overload_response" in listen_cfg
    global_overload_response = normalize_overload_response(
        listen_cfg.get("overload_response"),
        default="servfail",
    )
    listen_cfg["overload_response"] = global_overload_response
    if global_overload_configured:
        udp_overload_default = global_overload_response
        tcp_overload_default = global_overload_response
        dot_overload_default = global_overload_response
        doh_overload_default = global_overload_response
    else:
        # Backward-compatible transport defaults when no global override is set.
        udp_overload_default = "servfail"
        tcp_overload_default = "drop"
        dot_overload_default = "drop"
        doh_overload_default = "drop"

    def _sub(key: str, defaults: Dict[str, Any]) -> Dict[str, Any]:
        block = listen_cfg.get(key, {}) or {}
        if not isinstance(block, dict):
            return dict(defaults)
        return {**defaults, **block}

    udp_section = listen_cfg.get("udp")
    if isinstance(udp_section, dict):
        udp_default_enabled = bool(udp_section.get("enabled", True))
    else:
        udp_default_enabled = True

    tcp_section = listen_cfg.get("tcp")
    if isinstance(tcp_section, dict):
        tcp_default_enabled = bool(tcp_section.get("enabled", True))
    else:
        tcp_default_enabled = False

    dot_section = listen_cfg.get("dot")
    dot_default_enabled = True if isinstance(dot_section, dict) else False

    doh_section = listen_cfg.get("doh")
    doh_default_enabled = True if isinstance(doh_section, dict) else False

    udp_defaults: Dict[str, Any] = {
        "enabled": udp_default_enabled,
        "host": default_host,
        "port": default_port or 5335,
        "overload_response": udp_overload_default,
        # Runtime defaults (see foghorn.main).
        "use_asyncio": False,
        "allow_threaded_fallback": True,
        "exit_on_asyncio_failure": False,
        "max_inflight": 1024,
        "max_inflight_per_ip": 64,
        "max_inflight_by_cidr": None,
        "max_response_bytes": None,
    }
    listen_cfg["udp"] = _sub("udp", udp_defaults)
    listen_cfg["udp"]["overload_response"] = normalize_overload_response(
        listen_cfg["udp"].get("overload_response"),
        default=udp_overload_default,
    )

    tcp_defaults: Dict[str, Any] = {
        "enabled": tcp_default_enabled,
        "host": default_host,
        "port": default_port or 5335,
        "overload_response": tcp_overload_default,
        "max_connections": 1024,
        "max_connections_per_ip": 64,
        "max_queries_per_connection": 100,
        "idle_timeout_seconds": 15.0,
    }
    listen_cfg["tcp"] = _sub("tcp", tcp_defaults)
    listen_cfg["tcp"]["overload_response"] = normalize_overload_response(
        listen_cfg["tcp"].get("overload_response"),
        default=tcp_overload_default,
    )

    dot_defaults: Dict[str, Any] = {
        "enabled": dot_default_enabled,
        "host": default_host,
        "port": 853,
        "overload_response": dot_overload_default,
        "max_connections": 1024,
        "max_connections_per_ip": 64,
        "max_queries_per_connection": 100,
        "idle_timeout_seconds": 15.0,
        # TLS paths are required when enabled but have no global defaults.
        "cert_file": None,
        "key_file": None,
    }
    listen_cfg["dot"] = _sub("dot", dot_defaults)
    listen_cfg["dot"]["overload_response"] = normalize_overload_response(
        listen_cfg["dot"].get("overload_response"),
        default=dot_overload_default,
    )

    doh_defaults: Dict[str, Any] = {
        "enabled": doh_default_enabled,
        "host": default_host,
        "port": 1443,
        "overload_response": doh_overload_default,
        "cert_file": None,
        "key_file": None,
        "allow_threaded_fallback": True,
    }
    listen_cfg["doh"] = _sub("doh", doh_defaults)
    listen_cfg["doh"]["overload_response"] = normalize_overload_response(
        listen_cfg["doh"].get("overload_response"),
        default=doh_overload_default,
    )


def _expand_server_resolver_defaults(server_cfg: Dict[str, Any]) -> None:
    """Brief: Fill in server.resolver defaults used by foghorn.main.

    Inputs:
      - server_cfg: server config mapping (mutated in-place).

    Outputs:
      - None.

    Notes:
      - Values are normalized to the runtime representation used by foghorn.main
        (e.g. lowercased mode strings and integer timeout/max_depth fields).
    """

    resolver_cfg = server_cfg.get("resolver")
    if not isinstance(resolver_cfg, dict):
        resolver_cfg = {}
        server_cfg["resolver"] = resolver_cfg

    mode = str(resolver_cfg.get("mode", "forward") or "forward").lower()
    if mode == "none":
        mode = "master"
    # Overwrite so that legacy/invalid values (e.g. mode: NONE) are normalized.
    resolver_cfg["mode"] = mode

    # Defaults aligned with foghorn.main.
    try:
        timeout_ms = int(resolver_cfg.get("timeout_ms", 2000))
    except (TypeError, ValueError):
        timeout_ms = 2000
    resolver_cfg["timeout_ms"] = timeout_ms

    try:
        per_try = int(resolver_cfg.get("per_try_timeout_ms", timeout_ms))
    except (TypeError, ValueError):
        per_try = timeout_ms
    resolver_cfg["per_try_timeout_ms"] = per_try

    try:
        max_depth = int(resolver_cfg.get("max_depth", 12))
    except (TypeError, ValueError):
        max_depth = 12
    resolver_cfg["max_depth"] = max_depth

    resolver_cfg["use_asyncio"] = bool(resolver_cfg.get("use_asyncio", True))


def _expand_server_dnssec_defaults(server_cfg: Dict[str, Any]) -> None:
    """Brief: Fill in server.dnssec defaults.

    Inputs:
      - server_cfg: server config mapping (mutated in-place).

    Outputs:
      - None.

    Notes:
      - Values are normalized to the runtime representation used by foghorn.main
        (lowercased strings and integer udp_payload_size).
    """

    dnssec_cfg = server_cfg.get("dnssec")
    if not isinstance(dnssec_cfg, dict):
        dnssec_cfg = {}
        server_cfg["dnssec"] = dnssec_cfg

    dnssec_cfg["mode"] = str(dnssec_cfg.get("mode", "ignore") or "ignore").lower()
    dnssec_cfg["validation"] = str(
        dnssec_cfg.get("validation", "upstream_ad") or "upstream_ad"
    ).lower()

    try:
        payload = int(dnssec_cfg.get("udp_payload_size", 1232))
    except (TypeError, ValueError):
        payload = 1232
    dnssec_cfg["udp_payload_size"] = payload


def _expand_server_limits_defaults(server_cfg: Dict[str, Any]) -> None:
    """Brief: Fill in server.limits defaults.

    Inputs:
      - server_cfg: server config mapping (mutated in-place).

    Outputs:
      - None.
    """

    limits_cfg = server_cfg.get("limits")
    if not isinstance(limits_cfg, dict):
        limits_cfg = {}
        server_cfg["limits"] = limits_cfg

    limits_cfg.setdefault("resolver_executor_workers", None)
    limits_cfg.setdefault("bg_executor_workers", 4)
    limits_cfg.setdefault("bg_executor_max_pending", None)
    limits_cfg.setdefault("allow_unsafe_threaded_listeners", False)


def _expand_server_http_defaults(server_cfg: Dict[str, Any]) -> None:
    """Brief: Fill in server.http defaults.

    Inputs:
      - server_cfg: server config mapping (mutated in-place).

    Outputs:
      - None.

    Notes:
      - Enabled behavior matches foghorn.main/start_webserver: a non-empty
        server.http mapping implies enabled unless explicitly set.
    """

    http_cfg = server_cfg.get("http")
    if not isinstance(http_cfg, dict):
        http_cfg = {}
        server_cfg["http"] = http_cfg

    has_http_cfg = bool(http_cfg)
    raw_enabled = http_cfg.get("enabled")
    enabled = bool(raw_enabled) if raw_enabled is not None else has_http_cfg

    # Overwrite so that falsey values like 0 are normalized to a bool.
    http_cfg["enabled"] = enabled

    # Bind defaults used by the threaded fallback and typical uvicorn configs.
    http_cfg.setdefault("host", "127.0.0.1")
    http_cfg.setdefault("port", 5380)

    # Feature gates (defaults from foghorn.servers.webserver.core).
    http_cfg.setdefault("enable_api", True)
    http_cfg.setdefault("enable_schema", True)
    http_cfg.setdefault("enable_docs", True)

    http_cfg.setdefault("allow_threaded_fallback", True)
    http_cfg.setdefault("www_root", None)
    http_cfg.setdefault("index", True)

    logs_cfg = http_cfg.get("logs")
    if not isinstance(logs_cfg, dict):
        logs_cfg = {}
        http_cfg["logs"] = logs_cfg
    logs_cfg.setdefault("buffer_size", 500)

    # TTL tuning defaults mirrored from webserver internals.
    http_cfg.setdefault("system_info_ttl_seconds", 2.0)
    http_cfg.setdefault("stats_snapshot_ttl_seconds", 2.0)
    http_cfg.setdefault("config_cache_ttl_seconds", 2.0)

    http_cfg.setdefault("system_metrics_detail", "full")
    http_cfg.setdefault("debug_timings", False)

    cors_cfg = http_cfg.get("cors")
    if not isinstance(cors_cfg, dict):
        cors_cfg = {}
        http_cfg["cors"] = cors_cfg
    cors_cfg.setdefault("enabled", False)
    cors_cfg.setdefault("allowlist", [])

    auth_cfg = http_cfg.get("auth")
    if not isinstance(auth_cfg, dict):
        auth_cfg = {}
        http_cfg["auth"] = auth_cfg
    auth_cfg.setdefault("mode", "none")
    auth_cfg.setdefault("token", None)

    http_cfg.setdefault("redact_keys", ["token", "password", "secret"])


def _expand_server_feature_flags(server_cfg: Dict[str, Any]) -> None:
    """Brief: Fill in selected server feature-gate defaults.

    Inputs:
      - server_cfg: server config mapping (mutated in-place).

    Outputs:
      - None.
    """

    features_cfg = server_cfg.get("features")
    if not isinstance(features_cfg, dict):
        features_cfg = {}
        server_cfg["features"] = features_cfg

    legacy_enable_ede = bool(server_cfg.get("enable_ede", False))
    legacy_forward_local = bool(server_cfg.get("forward_local", False))

    features_cfg["enable_ede"] = bool(features_cfg.get("enable_ede", legacy_enable_ede))
    features_cfg["forward_local"] = bool(
        features_cfg.get("forward_local", legacy_forward_local)
    )

    ecs_cfg = features_cfg.get("ecs")
    if not isinstance(ecs_cfg, dict):
        ecs_cfg = {}
        features_cfg["ecs"] = ecs_cfg
    ecs_cfg["enabled"] = bool(ecs_cfg.get("enabled", False))
    ecs_cfg["forward_inbound"] = bool(ecs_cfg.get("forward_inbound", False))
    ecs_cfg["synthesize_from_client_ip"] = bool(
        ecs_cfg.get("synthesize_from_client_ip", False)
    )
    try:
        ecs_cfg["source_prefix_v4"] = max(
            0, min(32, int(ecs_cfg.get("source_prefix_v4", 24)))
        )
    except Exception:
        ecs_cfg["source_prefix_v4"] = 24
    try:
        ecs_cfg["source_prefix_v6"] = max(
            0,
            min(128, int(ecs_cfg.get("source_prefix_v6", 56))),
        )
    except Exception:
        ecs_cfg["source_prefix_v6"] = 56
    try:
        ecs_cfg["scope_prefix_v4"] = max(
            0, min(32, int(ecs_cfg.get("scope_prefix_v4", 0)))
        )
    except Exception:
        ecs_cfg["scope_prefix_v4"] = 0
    try:
        ecs_cfg["scope_prefix_v6"] = max(
            0,
            min(128, int(ecs_cfg.get("scope_prefix_v6", 0))),
        )
    except Exception:
        ecs_cfg["scope_prefix_v6"] = 0
    trusted_listeners = ecs_cfg.get("trusted_listeners")
    if not isinstance(trusted_listeners, list):
        trusted_listeners = []
    ecs_cfg["trusted_listeners"] = [str(v) for v in trusted_listeners if str(v).strip()]
    trusted_cidrs = ecs_cfg.get("trusted_client_cidrs")
    if not isinstance(trusted_cidrs, list):
        trusted_cidrs = []
    ecs_cfg["trusted_client_cidrs"] = [str(v) for v in trusted_cidrs if str(v).strip()]
    ecs_cfg["use_for_plugin_targeting"] = bool(
        ecs_cfg.get("use_for_plugin_targeting", False)
    )

    # Preserve legacy keys for backward compatibility in config-dump views.
    server_cfg["enable_ede"] = bool(features_cfg.get("enable_ede", False))
    server_cfg["forward_local"] = bool(features_cfg.get("forward_local", False))

    axfr_cfg = server_cfg.get("axfr")
    if not isinstance(axfr_cfg, dict):
        axfr_cfg = {}
        server_cfg["axfr"] = axfr_cfg
    axfr_cfg.setdefault("enabled", False)
    allow_clients = axfr_cfg.get("allow_clients")
    if not isinstance(allow_clients, list):
        allow_clients = []
        axfr_cfg["allow_clients"] = allow_clients
    axfr_cfg.setdefault("max_zone_rrs", None)
    try:
        max_concurrent = int(axfr_cfg.get("max_concurrent_transfers", 4))
    except Exception:
        max_concurrent = 4
    axfr_cfg["max_concurrent_transfers"] = max(1, int(max_concurrent))
    try:
        rate_per_sec = float(axfr_cfg.get("rate_limit_per_client_per_second", 0.0))
    except Exception:
        rate_per_sec = 0.0
    axfr_cfg["rate_limit_per_client_per_second"] = max(0.0, float(rate_per_sec))
    try:
        burst = float(axfr_cfg.get("rate_limit_burst", 2.0))
    except Exception:
        burst = 2.0
    axfr_cfg["rate_limit_burst"] = max(1.0, float(burst))
    axfr_cfg.setdefault("max_transfer_rate_bytes_per_second", None)
    try:
        message_max = int(axfr_cfg.get("message_max_bytes", 64000))
    except Exception:
        message_max = 64000
    axfr_cfg["message_max_bytes"] = max(512, min(65535, int(message_max)))
    axfr_cfg.setdefault("require_tsig", False)
    tsig_keys = axfr_cfg.get("tsig_keys")
    if not isinstance(tsig_keys, list):
        tsig_keys = []
    axfr_cfg["tsig_keys"] = tsig_keys


def _expand_upstreams_defaults(out: Dict[str, Any]) -> None:
    """Brief: Normalize upstream endpoints and fill in upstream strategy defaults.

    Inputs:
      - out: Full config mapping (mutated in-place).

    Outputs:
      - None.

    Notes:
      - Uses normalize_upstream_config() to fill in per-endpoint default ports.
    """

    upstream_cfg = out.get("upstreams")
    if upstream_cfg is None:
        upstream_cfg = {}
        out["upstreams"] = upstream_cfg

    if not isinstance(upstream_cfg, dict):
        return

    upstream_cfg["strategy"] = str(
        upstream_cfg.get("strategy", "failover") or "failover"
    ).lower()

    # Optional upstream health tuning defaults (used by server.py).
    health_cfg = upstream_cfg.get("health")
    if not isinstance(health_cfg, dict):
        health_cfg = {}
        upstream_cfg["health"] = health_cfg
    health_cfg.setdefault("max_serv_fail", 3)
    health_cfg.setdefault("unknown_after_seconds", 300)
    health_cfg.setdefault("probe_percent", 1.0)
    health_cfg.setdefault("probe_min_percent", 0.5)
    health_cfg.setdefault("probe_max_percent", 50.0)
    health_cfg.setdefault("probe_increase", 1.0)
    health_cfg.setdefault("probe_decrease", 1.0)

    # Optional backup upstream endpoints.
    backup_cfg = upstream_cfg.get("backup")
    if backup_cfg is None:
        backup_cfg = {"endpoints": []}
        upstream_cfg["backup"] = backup_cfg
    elif not isinstance(backup_cfg, dict):
        # Best-effort: keep invalid backup cfg unmodified.
        backup_cfg = None

    try:
        max_conc = int(upstream_cfg.get("max_concurrent", 1) or 1)
    except Exception:
        max_conc = 1
    if max_conc < 1:
        max_conc = 1
    upstream_cfg["max_concurrent"] = max_conc

    # Best-effort endpoint normalization; forward mode only.
    resolver_cfg = (out.get("server") or {}).get("resolver")
    resolver_mode = None
    if isinstance(resolver_cfg, dict):
        resolver_mode = str(resolver_cfg.get("mode", "forward") or "forward").lower()

    if resolver_mode == "none":
        resolver_mode = "master"

    if resolver_mode and resolver_mode != "forward":
        return

    try:
        normalized, _timeout_ms = normalize_upstream_config(out)
    except Exception:
        return

    # Preserve the v2 layout when present.
    if "endpoints" in upstream_cfg and isinstance(upstream_cfg.get("endpoints"), list):
        upstream_cfg["endpoints"] = normalized

    # Normalize backup endpoints when present.
    if isinstance(upstream_cfg.get("backup"), dict) and isinstance(
        upstream_cfg["backup"].get("endpoints"), list
    ):
        try:
            backup_normalized = normalize_upstream_backup_config(out)
            upstream_cfg["backup"]["endpoints"] = backup_normalized
        except Exception:
            # Best-effort: keep original backup endpoints on errors.
            return


def _expand_logging_defaults(out: Dict[str, Any]) -> None:
    """Brief: Fill in logging defaults for the new logging.python layout.

    Inputs:
      - out: Full config mapping (mutated in-place).

    Outputs:
      - None.
    """

    logging_cfg = out.get("logging")
    if not isinstance(logging_cfg, dict):
        logging_cfg = {}
        out["logging"] = logging_cfg

    python_cfg = logging_cfg.get("python")
    if not isinstance(python_cfg, dict):
        python_cfg = {}
        logging_cfg["python"] = python_cfg

    python_cfg.setdefault("level", "info")
    python_cfg.setdefault("stderr", True)
    python_cfg.setdefault("file", None)
    python_cfg.setdefault("syslog", False)
