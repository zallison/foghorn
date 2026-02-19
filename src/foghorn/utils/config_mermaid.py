"""Brief: Generate Mermaid diagrams (and optional PNG renders) for a Foghorn config.

This module is a reusable library version of `scripts/generate_config_mermaid.py`.
It is used both by:
  - the CLI script (for ad-hoc generation), and
  - the running server (to generate a config diagram PNG on startup).

Inputs:
  - Config path (YAML) or already-parsed config mapping.
  - Optional rendering knobs (direction, spacing, font size).

Outputs:
  - Mermaid flowchart text.
  - Optional PNG image written to disk when a renderer (mmdc or python_mermaid)
    is available.

Notes:
  - PNG generation is best-effort and should never prevent server startup.
  - `mmdc` (Mermaid CLI) is preferred. If unavailable, this module can
    optionally attempt to use `python_mermaid` when installed.
  - The PNG is regenerated when missing or when the config file mtime is newer
    than the PNG mtime.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Optional

import yaml

from foghorn.config.config_schema import get_default_schema_path, validate_config

logger = logging.getLogger("foghorn.utils.config_mermaid")


_ALLOWED_PIPELINE_ACTIONS = {"deny", "override", "drop", "allow"}

# Mermaid render defaults.
_DEFAULT_DIRECTION = "TB"  # Top-to-bottom.
_DEFAULT_FONT_SIZE_PX = 18
_DEFAULT_NODE_SPACING = 80
_DEFAULT_RANK_SPACING = 90


@dataclass(frozen=True)
class PluginInfo:
    """Brief: Normalized view of a config plugin entry for diagram rendering.

    Inputs:
      - idx: Position in the config's plugins list.
      - name: Instance identifier (id/name/type-derived).
      - type_key: Plugin type/alias/module identifier as written in config.
      - cls_path: Resolved Python class path (module.Class).
      - setup_priority: setup() order (lower runs first) when plugin is a setup plugin.
      - pre_priority: pre_resolve order (lower runs first) when enabled.
      - post_priority: post_resolve order (lower runs first) when enabled.
      - pre_actions/post_actions: Pipeline actions the plugin may emit.
      - sets_upstreams: Whether plugin may set ctx.upstream_candidates/override.

    Outputs:
      - PluginInfo instance.
    """

    idx: int
    name: str
    type_key: str
    cls_path: str

    setup_priority: Optional[int] = None
    pre_priority: Optional[int] = None
    post_priority: Optional[int] = None

    pre_actions: set[str] = field(default_factory=set)
    post_actions: set[str] = field(default_factory=set)

    sets_upstreams: bool = False


def _safe_int(value: object) -> Optional[int]:
    """Brief: Parse an integer priority value.

    Inputs:
      - value: Any object; typically int/str/None.

    Outputs:
      - int when value can be parsed; otherwise None.

    Example:
      - _safe_int('25') -> 25
      - _safe_int(None) -> None
    """

    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _get_dict(root: object, *keys: str) -> dict[str, Any]:
    """Brief: Get a nested mapping from a root mapping.

    Inputs:
      - root: Mapping-like object.
      - *keys: Path segments to descend.

    Outputs:
      - dict: Nested mapping when present; otherwise empty dict.

    Example:
      - _get_dict({'a': {'b': 1}}, 'a') -> {'b': 1}
      - _get_dict({'a': 1}, 'a') -> {}
    """

    cur: object = root
    for k in keys:
        if not isinstance(cur, dict):
            return {}
        cur = cur.get(k)
    return cur if isinstance(cur, dict) else {}


_ACTION_KW_RE = re.compile(r"PluginDecision\(\s*action\s*=\s*['\"]([a-zA-Z_]+)['\"]")
_ACTION_POS_RE = re.compile(r"PluginDecision\(\s*['\"]([a-zA-Z_]+)['\"]")


@dataclass(frozen=True)
class PluginSource:
    """Brief: Source-level plugin metadata derived from files under src/.

    Inputs:
      - alias: Normalized alias key (lowercase, '-' -> '_').
      - module: Python module path (e.g. 'foghorn.plugins.resolve.filter').
      - class_name: Class name implementing the plugin.
      - file_path: Filesystem path to the Python file.
      - has_setup: Whether the class appears to define a setup() method.
      - pre_actions/post_actions: Pipeline actions referenced in pre_resolve/post_resolve.
      - sets_upstreams: Whether pre/post code references ctx.upstream_candidates/override.

    Outputs:
      - PluginSource instance.
    """

    alias: str
    module: str
    class_name: str
    file_path: Path

    has_setup: bool = False
    pre_actions: set[str] = field(default_factory=set)
    post_actions: set[str] = field(default_factory=set)
    sets_upstreams: bool = False


_CAMEL_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")


def _camel_to_snake(name: str) -> str:
    """Brief: Convert CamelCase to snake_case.

    Inputs:
      - name: CamelCase identifier.

    Outputs:
      - str: snake_case identifier.

    Example:
      - _camel_to_snake('MdnsBridge') -> 'mdns_bridge'
    """

    s1 = _CAMEL_1.sub(r"\1_\2", name)
    s2 = _CAMEL_2.sub(r"\1_\2", s1)
    return s2.lower()


def _normalize_alias(alias: str) -> str:
    """Brief: Normalize an alias like the runtime registry (lower, '-' -> '_').

    Inputs:
      - alias: Alias string.

    Outputs:
      - str: Normalized alias.
    """

    return str(alias or "").strip().lower().replace("-", "_")


def _default_alias_for_class(class_name: str) -> str:
    """Brief: Reproduce registry default alias logic from a class name.

    Inputs:
      - class_name: Python class name.

    Outputs:
      - str: Default alias.

    Example:
      - _default_alias_for_class('DockerHosts') -> 'docker_hosts'
    """

    name = str(class_name)
    if name.endswith("Plugin"):
        name = name[:-6]
    return _camel_to_snake(name)


def _module_to_file(module: str) -> Optional[Path]:
    """Brief: Convert a Python module path into a source file path.

    Inputs:
      - module: Python module path (e.g. 'foghorn.plugins.resolve.filter').

    Outputs:
      - Optional[Path]: Path to a .py file when resolvable, else None.

    Notes:
      - Prefers <module>.py, then <module>/__init__.py.
    """

    mod = str(module or "").strip()
    if not mod:
        return None

    # Resolve relative to this installed source tree.
    src_dir = Path(__file__).resolve().parents[2]

    parts = mod.split(".")
    py_candidate = src_dir.joinpath(*parts).with_suffix(".py")
    if py_candidate.is_file():
        return py_candidate

    init_candidate = src_dir.joinpath(*parts) / "__init__.py"
    if init_candidate.is_file():
        return init_candidate

    return None


_CLASS_RE = re.compile(
    r"^(?P<indent>[ \t]*)class\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<bases>[^)]*)\)\s*:",
    re.MULTILINE,
)


def _extract_method_block(class_text: str, method_name: str) -> str:
    """Brief: Extract a best-effort method block from within a class body.

    Inputs:
      - class_text: Text spanning a single class definition.
      - method_name: Name of the method to extract.

    Outputs:
      - str: Method block text, or empty string when not found.

    Notes:
      - This is heuristic and assumes 4-space indentation for methods.
    """

    pat = re.compile(
        rf"(?ms)^    def\s+{re.escape(method_name)}\b.*?(?=^    def\s+|\Z)"
    )
    m = pat.search(class_text)
    return m.group(0) if m else ""


def _scan_actions_in_text(text: str) -> set[str]:
    """Brief: Scan text for constant PluginDecision actions.

    Inputs:
      - text: Source text to scan.

    Outputs:
      - set[str]: Action strings (filtered to those the core server handles).
    """

    actions = set(_ACTION_KW_RE.findall(text)) | set(_ACTION_POS_RE.findall(text))
    return {a for a in actions if a in _ALLOWED_PIPELINE_ACTIONS}


def _scan_sets_upstreams_in_text(text: str) -> bool:
    """Brief: Detect whether code references ctx.upstream_candidates/override.

    Inputs:
      - text: Source text.

    Outputs:
      - bool: True if upstream override fields are referenced.
    """

    return ("ctx.upstream_candidates" in text) or ("ctx.upstream_override" in text)


def _extract_class_text(text: str, class_name: str) -> str:
    """Brief: Extract the class definition block for a named class.

    Inputs:
      - text: Python source file text.
      - class_name: Class name to extract.

    Outputs:
      - str: Source text spanning the class definition, or empty string.
    """

    for m in _CLASS_RE.finditer(text):
        if m.group("name") != class_name:
            continue
        bases = m.group("bases")
        if "BasePlugin" not in bases:
            continue

        start = m.start()
        next_match = _CLASS_RE.search(text, m.end())
        end = next_match.start() if next_match else len(text)
        return text[start:end]

    return ""


def _build_plugin_source_from_module(
    *,
    alias: str,
    module: str,
    class_name: str,
    file_path: Path,
) -> Optional[PluginSource]:
    """Brief: Build PluginSource for a single plugin class.

    Inputs:
      - alias: Normalized alias.
      - module: Python module path (without class name).
      - class_name: Plugin class name.
      - file_path: Python file path.

    Outputs:
      - Optional[PluginSource]: Source metadata, or None when the class cannot be parsed.
    """

    try:
        text = file_path.read_text(encoding="utf-8")
    except Exception:
        return None

    class_text = _extract_class_text(text, class_name)
    if not class_text:
        return None

    pre_block = _extract_method_block(class_text, "pre_resolve")
    post_block = _extract_method_block(class_text, "post_resolve")
    setup_block = _extract_method_block(class_text, "setup")

    all_actions = _scan_actions_in_text(class_text)
    has_pre = bool(pre_block.strip())
    has_post = bool(post_block.strip())
    pre_actions = set(all_actions) if has_pre else set()
    post_actions = set(all_actions) if has_post else set()

    sets_upstreams = _scan_sets_upstreams_in_text(class_text)
    has_setup = bool(setup_block.strip())

    return PluginSource(
        alias=alias,
        module=module,
        class_name=class_name,
        file_path=file_path,
        has_setup=has_setup,
        pre_actions=pre_actions,
        post_actions=post_actions,
        sets_upstreams=sets_upstreams,
    )


_PLUGIN_SOURCE_INDEX: dict[str, PluginSource] | None = None


def _build_plugin_source_index_from_schema() -> dict[str, PluginSource]:
    """Brief: Build alias -> plugin source metadata from assets/config-schema.json.

    Inputs:
      - None.

    Outputs:
      - dict[str, PluginSource]: Mapping from normalized alias to plugin metadata.

    Notes:
      - Prefers the generated schema's plugin registry ("$defs.PluginConfigs").
      - Only resolve plugins are included (foghorn.plugins.resolve.*).
    """

    schema_path = get_default_schema_path()
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    defs = schema.get("$defs")
    if not isinstance(defs, dict):
        return {}

    plugin_cfgs = defs.get("PluginConfigs")
    if not isinstance(plugin_cfgs, dict):
        return {}

    index: dict[str, PluginSource] = {}

    for _key, meta in plugin_cfgs.items():
        if not isinstance(meta, dict):
            continue

        full = meta.get("module")
        if not isinstance(full, str) or not full.strip():
            continue

        full = full.strip()
        if not full.startswith("foghorn.plugins.resolve."):
            continue

        mod_path, _, cls_name = full.rpartition(".")
        if not mod_path or not cls_name:
            continue

        file_path = _module_to_file(mod_path)
        if file_path is None:
            continue

        aliases = meta.get("aliases")
        if not isinstance(aliases, list):
            aliases = []

        effective_aliases = set(str(a) for a in aliases if isinstance(a, str))
        effective_aliases.add(_default_alias_for_class(cls_name))

        for raw_alias in sorted(effective_aliases):
            alias = _normalize_alias(raw_alias)
            if not alias or alias in index:
                continue

            src = _build_plugin_source_from_module(
                alias=alias,
                module=mod_path,
                class_name=cls_name,
                file_path=file_path,
            )
            if src is None:
                continue
            index[alias] = src

    return index


def _get_plugin_source_index() -> dict[str, PluginSource]:
    """Brief: Lazily build (and cache) the plugin source index.

    Inputs:
      - None.

    Outputs:
      - dict[str, PluginSource]: Alias -> source metadata.
    """

    global _PLUGIN_SOURCE_INDEX
    if _PLUGIN_SOURCE_INDEX is None:
        _PLUGIN_SOURCE_INDEX = _build_plugin_source_index_from_schema()
    return _PLUGIN_SOURCE_INDEX or {}


def _lookup_plugin_source(type_key: str) -> Optional[PluginSource]:
    """Brief: Find plugin source metadata for a config 'type' / 'module' identifier.

    Inputs:
      - type_key: Plugin identifier from config (alias or full module.Class path).

    Outputs:
      - Optional[PluginSource]: Source metadata when resolvable; otherwise None.
    """

    idx = _get_plugin_source_index()
    raw = str(type_key or "").strip()
    if not raw:
        return None

    if "." in raw:
        tail = raw.split(".")[-1]
        alias = _normalize_alias(_default_alias_for_class(tail))
    else:
        alias = _normalize_alias(raw)

    return idx.get(alias)


def _derive_display_name(entry: dict[str, Any]) -> str:
    """Brief: Choose a human-facing identifier for a plugin config entry.

    Inputs:
      - entry: Plugin config entry mapping.

    Outputs:
      - str: Display name (prefers id/name, then type/module, else 'plugin').
    """

    for k in ("id", "name"):
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()

    for k in ("type", "module"):
        v2 = entry.get(k)
        if isinstance(v2, str) and v2.strip():
            return v2.strip()

    return "plugin"


def _extract_priorities(
    entry: dict[str, Any],
) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """Brief: Extract setup/pre/post priorities from a config plugin entry.

    Inputs:
      - entry: Plugin config entry mapping.

    Outputs:
      - (setup_priority, pre_priority, post_priority):
        Hook-specific values are preferred; legacy keys and generic priority
        are used as fallbacks.
    """

    setup_block = _get_dict(entry, "setup")
    hooks = _get_dict(entry, "hooks")
    pre_block = hooks.get("pre_resolve")
    post_block = hooks.get("post_resolve")

    setup_prio = _safe_int(setup_block.get("priority"))

    pre_prio = None
    if isinstance(pre_block, dict):
        pre_prio = _safe_int(pre_block.get("priority"))

    post_prio = None
    if isinstance(post_block, dict):
        post_prio = _safe_int(post_block.get("priority"))

    generic = _safe_int(entry.get("priority"))
    pre_legacy = _safe_int(entry.get("pre_priority"))
    post_legacy = _safe_int(entry.get("post_priority"))
    setup_legacy = _safe_int(entry.get("setup_priority"))

    if pre_prio is None:
        pre_prio = pre_legacy if pre_legacy is not None else generic
    if post_prio is None:
        post_prio = post_legacy if post_legacy is not None else generic
    if setup_prio is None:
        setup_prio = setup_legacy if setup_legacy is not None else generic

    return setup_prio, pre_prio, post_prio


def _has_nonempty_list(value: object) -> bool:
    """Brief: True when value is a non-empty list.

    Inputs:
      - value: Any object.

    Outputs:
      - bool: True if value is a list with at least one element.
    """

    return isinstance(value, list) and bool(value)


def _constrain_plugin_info_for_config(
    info: PluginInfo, *, entry_config: dict[str, Any]
) -> PluginInfo:
    """Brief: Adjust inferred plugin phases/actions using config-specific hints."""

    if info.cls_path == "foghorn.plugins.resolve.filter.Filter":
        deny_response = str(entry_config.get("deny_response", "nxdomain")).lower()

        pre_actions = set(info.pre_actions)
        post_actions = set(info.post_actions)

        if deny_response != "drop":
            pre_actions.discard("drop")
            post_actions.discard("drop")

        has_ip_rules = _has_nonempty_list(
            entry_config.get("blocked_ips")
        ) or _has_nonempty_list(entry_config.get("blocked_ips_files"))
        if not has_ip_rules:
            return replace(
                info,
                post_priority=None,
                post_actions=set(),
                pre_actions=pre_actions,
            )

        return replace(info, pre_actions=pre_actions, post_actions=post_actions)

    return info


def normalize_plugins(cfg: dict[str, Any]) -> list[PluginInfo]:
    """Brief: Parse config plugins and resolve metadata needed for diagram generation."""

    plugins_raw = cfg.get("plugins") or []
    if not isinstance(plugins_raw, list):
        return []

    out: list[PluginInfo] = []

    for idx, entry in enumerate(plugins_raw):
        if not isinstance(entry, dict):
            continue

        type_key = str(entry.get("type") or entry.get("module") or "").strip()
        if not type_key:
            continue

        src = _lookup_plugin_source(type_key)
        cls_path = f"{src.module}.{src.class_name}" if src else str(type_key)

        setup_prio, pre_prio, post_prio = _extract_priorities(entry)

        is_setup_plugin = bool(src and src.has_setup)
        if is_setup_plugin and setup_prio is None:
            setup_prio = pre_prio if pre_prio is not None else 100

        name = _derive_display_name(entry)

        pre_actions = set(src.pre_actions) if src else set()
        post_actions = set(src.post_actions) if src else set()
        sets_upstreams = bool(src and src.sets_upstreams)

        info = PluginInfo(
            idx=idx,
            name=name,
            type_key=type_key,
            cls_path=cls_path,
            setup_priority=setup_prio if is_setup_plugin else None,
            pre_priority=pre_prio,
            post_priority=post_prio,
            pre_actions=pre_actions,
            post_actions=post_actions,
            sets_upstreams=sets_upstreams,
        )

        entry_cfg = entry.get("config")
        if not isinstance(entry_cfg, dict):
            entry_cfg = {}
        info = _constrain_plugin_info_for_config(info, entry_config=entry_cfg)

        out.append(info)

    return out


def _node_id(prefix: str, name: str, idx: int) -> str:
    """Brief: Build a Mermaid-safe node identifier.

    Inputs:
      - prefix: Namespace prefix (e.g. 'pre', 'post', 'setup').
      - name: Human plugin name used for readability.
      - idx: Plugin index, included to ensure uniqueness.

    Outputs:
      - str: Mermaid node id (alphanumerics/underscores only).
    """

    safe = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    safe = re.sub(r"_+", "_", safe).strip("_")
    if not safe:
        safe = "plugin"
    return f"{prefix}_{idx}_{safe}"


def _escape_mermaid_label(text: str) -> str:
    """Brief: Escape a string for use inside a Mermaid double-quoted label.

    Inputs:
      - text: Label text.

    Outputs:
      - str: Escaped label text.

    Notes:
      - Mermaid node labels often use the syntax: Node["..."]
      - We only escape double quotes here to avoid prematurely terminating labels.
    """

    return str(text).replace('"', '\\"')


def extract_listener_lines(cfg: dict[str, Any]) -> list[str]:
    """Brief: Extract human-friendly listener lines from config."""

    server_cfg = cfg.get("server") or {}
    if not isinstance(server_cfg, dict):
        return []

    listen_cfg = server_cfg.get("listen") or {}
    if not isinstance(listen_cfg, dict):
        return []

    found: dict[str, str] = {}

    dns_section = listen_cfg.get("dns")
    if isinstance(dns_section, dict):
        host = str(dns_section.get("host", "0.0.0.0"))
        try:
            port = int(dns_section.get("port", 53) or 53)
        except Exception:
            port = 53
        if bool(dns_section.get("udp", True)):
            found.setdefault("udp", f"udp: {host}:{port}")
        if bool(dns_section.get("tcp", False)):
            found.setdefault("tcp", f"tcp: {host}:{port}")

    defaults = {"udp": 53, "tcp": 53, "dot": 853, "doh": 1443}
    for name in ("udp", "tcp", "dot", "doh"):
        section = listen_cfg.get(name)
        if not isinstance(section, dict):
            continue
        enabled = bool(section.get("enabled", True))
        if not enabled:
            continue
        host = str(section.get("host", "0.0.0.0"))
        try:
            port = int(section.get("port", defaults[name]) or defaults[name])
        except Exception:
            port = defaults[name]
        found[name] = f"{name}: {host}:{port}"

    out: list[str] = []
    for k in ("udp", "tcp", "dot", "doh"):
        if k in found:
            out.append(found[k])
    return out


def extract_upstream_lines(cfg: dict[str, Any], *, resolver_mode: str) -> list[str]:
    """Brief: Extract human-friendly upstream endpoint lines from config."""

    mode = str(resolver_mode or "forward").lower()
    if mode == "none":
        mode = "master"
    if mode != "forward":
        return []

    upstream_cfg = cfg.get("upstreams") or {}
    if not isinstance(upstream_cfg, dict):
        return []

    endpoints = upstream_cfg.get("endpoints") or []
    if not isinstance(endpoints, list):
        return []

    lines: list[str] = []

    strategy = str(upstream_cfg.get("strategy", "failover") or "failover")
    try:
        max_concurrent = int(upstream_cfg.get("max_concurrent", 1) or 1)
    except Exception:
        max_concurrent = 1
    lines.append(f"strategy={strategy}, max_concurrent={max_concurrent}")

    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        transport = str(ep.get("transport", "udp") or "udp")
        url = ep.get("url")
        if isinstance(url, str) and url.strip():
            lines.append(f"{transport}: {url.strip()}")
            continue

        host = ep.get("host")
        if not isinstance(host, str) or not host.strip():
            continue
        host = host.strip()
        port = ep.get("port")
        if port is None:
            lines.append(f"{transport}: {host}")
        else:
            try:
                p = int(port)
            except Exception:
                lines.append(f"{transport}: {host}")
            else:
                lines.append(f"{transport}: {host}:{p}")

    return lines


def render_mermaid(
    plugins: list[PluginInfo],
    *,
    config_path: str,
    resolver_mode: str,
    listener_lines: list[str],
    upstream_lines: list[str],
    direction: str = _DEFAULT_DIRECTION,
    font_size_px: int = _DEFAULT_FONT_SIZE_PX,
    node_spacing: int = _DEFAULT_NODE_SPACING,
    rank_spacing: int = _DEFAULT_RANK_SPACING,
    include_init: bool = True,
) -> str:
    """Brief: Render the full Mermaid diagram."""

    pre_chain = [p for p in plugins if p.pre_priority is not None]
    pre_chain.sort(key=lambda p: (int(p.pre_priority or 0), p.idx))

    post_chain = [p for p in plugins if p.post_priority is not None]
    post_chain.sort(key=lambda p: (int(p.post_priority or 0), p.idx))

    has_drop = any(("drop" in p.pre_actions) for p in pre_chain) or any(
        ("drop" in p.post_actions) for p in post_chain
    )

    setup_chain = [p for p in plugins if p.setup_priority is not None]
    setup_chain.sort(key=lambda p: (int(p.setup_priority or 0), p.idx))

    direction = str(direction or _DEFAULT_DIRECTION).strip().upper()
    if direction not in {"TB", "LR"}:
        direction = _DEFAULT_DIRECTION

    font_size_px = int(font_size_px or _DEFAULT_FONT_SIZE_PX)
    node_spacing = int(node_spacing or _DEFAULT_NODE_SPACING)
    rank_spacing = int(rank_spacing or _DEFAULT_RANK_SPACING)

    lines: list[str] = []

    if include_init:
        init_cfg = {
            "flowchart": {
                "nodeSpacing": node_spacing,
                "rankSpacing": rank_spacing,
            },
            "themeVariables": {
                "fontSize": f"{font_size_px}px",
            },
        }
        lines.append(f"%%{{init: {json.dumps(init_cfg)} }}%%")

    lines.append(f"%% Generated from: {config_path}")
    lines.append(f"flowchart {direction}")

    lines.append("  %% Styles")
    lines.append(
        "  classDef secure fill:#E3F2FD,stroke:#1E88E5,stroke-width:2px,color:#0D47A1;"
    )
    lines.append(
        "  classDef insecure fill:#FFEBEE,stroke:#E53935,stroke-width:2px,color:#B71C1C;"
    )

    lines.append("  %% Core nodes")

    lines.append("  Q([Query])")
    lines.append("  Cache{Cache hit?}")
    lines.append(
        f'  Resolver["Resolver mode: {_escape_mermaid_label(resolver_mode)}<br/>options: forward | recursive | master (none)"]'
    )

    mode = str(resolver_mode or "forward").lower()
    if mode == "none":
        mode = "master"
    if mode == "recursive":
        lines.append('  Upstream["Recursive resolver"]')
    elif mode == "master":
        # Use a quoted label to avoid Mermaid parsing issues with punctuation.
        lines.append('  Upstream["Master mode: no forwarding (REFUSED)"]')
    else:
        lines.append('  Upstream["Forward to upstreams"]')

    # Listener nodes (split by protocol).
    if listener_lines:
        lines.append('  Listeners["Listeners"]')
        for raw in listener_lines:
            raw = str(raw or "").strip()
            if not raw:
                continue
            proto = raw.split(":", 1)[0].strip().lower() if ":" in raw else ""
            nid = f'Listener_{re.sub(r"[^a-zA-Z0-9_]", "_", proto) or "unknown"}'
            label = _escape_mermaid_label(raw)
            lines.append(f'  {nid}["{label}"]')
            lines.append(f"  Listeners --> {nid}")
            lines.append(f"  {nid} --> Q")

            if proto in {"dot", "doh"}:
                lines.append(f"  class {nid} secure")
            elif proto in {"udp", "tcp"}:
                lines.append(f"  class {nid} insecure")

    # Upstream endpoint nodes (split by transport) when in forward mode.
    if upstream_lines and mode == "forward":
        meta_bits = [str(x).strip() for x in upstream_lines if x and ":" not in str(x)]
        meta_txt = "<br/>".join(_escape_mermaid_label(x) for x in meta_bits)
        if meta_txt:
            lines.append(f'  Upstreams["Upstreams<br/>{meta_txt}"]')
        else:
            lines.append('  Upstreams["Upstreams"]')

        for i, raw in enumerate([x for x in upstream_lines if x and ":" in str(x)]):
            raw_s = str(raw).strip()
            proto = raw_s.split(":", 1)[0].strip().lower()
            safe_proto = re.sub(r"[^a-zA-Z0-9_]", "_", proto) or "unknown"
            nid = f"UpstreamEp_{i}_{safe_proto}"
            label = _escape_mermaid_label(raw_s)
            lines.append(f'  {nid}["{label}"]')
            # Detail edge (selection depends on strategy); show endpoints as children.
            lines.append(f"  Upstreams --> {nid}")

            if proto in {"dot", "doh"}:
                lines.append(f"  class {nid} secure")
            elif proto in {"udp", "tcp"}:
                lines.append(f"  class {nid} insecure")

    lines.append("  Resp([Response])")
    if has_drop:
        lines.append('  Drop(["Drop (no reply)"])')
    lines.append("")

    lines.append("  subgraph QueryPath[DNS query path]")
    lines.append("    direction TB")

    has_pre_merge = any(
        (("deny" in p.pre_actions) or ("override" in p.pre_actions)) for p in pre_chain
    )
    has_post_merge = any(
        (("deny" in p.post_actions) or ("override" in p.post_actions))
        for p in post_chain
    )

    if has_pre_merge:
        lines.append('    PreMerge(["Pre short-circuit"])')
        lines.append("    PreMerge --> Resp")
    if has_post_merge:
        lines.append('    PostMerge(["Post short-circuit"])')
        lines.append("    PostMerge --> Resp")

    if setup_chain:
        lines.append("    subgraph SetupPlugins[Setup plugins]")
        lines.append("      direction TB")
        prev = None
        for p in setup_chain:
            nid = _node_id("setup", p.name, p.idx)
            label = f"{p.name}<br/>{p.type_key}<br/>setup={p.setup_priority}"
            lines.append(f'      {nid}["{label}"]')
            if prev is not None:
                lines.append(f"      {prev} --> {nid}")
            prev = nid
        lines.append("    end")

    if pre_chain:
        lines.append("    subgraph PrePlugins[Pre plugins]")
        lines.append("      direction TB")

        first_pre = None
        prev = None
        for p in pre_chain:
            nid = _node_id("pre", p.name, p.idx)
            label = f"{p.name}<br/>{p.type_key}<br/>pre={p.pre_priority}"
            if p.sets_upstreams:
                label += "<br/>routes upstream"
            lines.append(f'      {nid}["{label}"]')

            if first_pre is None:
                first_pre = nid
            if prev is not None:
                lines.append(f"      {prev} --> {nid}")
            prev = nid

            resp_bits: list[str] = []
            if "deny" in p.pre_actions:
                resp_bits.append("deny (NXDOMAIN)")
            if "override" in p.pre_actions:
                resp_bits.append("override (wire reply)")
            if resp_bits and has_pre_merge:
                label_txt = "; ".join(resp_bits)
                lines.append(f'      {nid} -->|"{label_txt}"| PreMerge')

            if "drop" in p.pre_actions:
                lines.append(f"      {nid} -->|drop| Drop")

        lines.append("    end")

        assert first_pre is not None
        assert prev is not None
        lines.append(f"    Q --> {first_pre}")
        lines.append(f"    {prev} --> Cache")
    else:
        lines.append("    Q --> Cache")

    lines.append("    Cache -->|hit| Resp")
    lines.append("    Cache -->|miss| Resolver")
    lines.append("    Resolver --> Upstream")

    upstream_tail = "Upstream"
    if upstream_lines and mode == "forward":
        lines.append("    Upstream --> Upstreams")
        upstream_tail = "Upstreams"

    if post_chain:
        lines.append("    subgraph PostPlugins[Post plugins]")
        lines.append("      direction TB")

        first_post = None
        prev_post = None
        for p in post_chain:
            nid = _node_id("post", p.name, p.idx)
            label = f"{p.name}<br/>{p.type_key}<br/>post={p.post_priority}"
            lines.append(f'      {nid}["{label}"]')

            if first_post is None:
                first_post = nid
            if prev_post is not None:
                lines.append(f"      {prev_post} --> {nid}")
            prev_post = nid

            resp_bits = []
            if "deny" in p.post_actions:
                resp_bits.append("deny (NXDOMAIN)")
            if "override" in p.post_actions:
                resp_bits.append("override (wire reply)")
            if resp_bits and has_post_merge:
                label_txt = "; ".join(resp_bits)
                lines.append(f'      {nid} -->|"{label_txt}"| PostMerge')

            if "drop" in p.post_actions:
                lines.append(f"      {nid} -->|drop| Drop")

        lines.append("    end")

        assert first_post is not None
        assert prev_post is not None
        lines.append(f"    {upstream_tail} --> {first_post}")
        lines.append(f"    {prev_post} --> Resp")
    else:
        lines.append(f"    {upstream_tail} --> Resp")

    lines.append("  end")

    return "\n".join(lines) + "\n"


def load_config(config_path: str) -> dict[str, Any]:
    """Brief: Load and normalize config for diagram generation.

    Inputs:
      - config_path: Path to YAML config.

    Outputs:
      - dict: Parsed config mapping.

    Notes:
      - Uses validate_config() to perform variable expansion and in-memory
        normalization.
    """

    with open(config_path, "r", encoding="utf-8") as f:
        obj = yaml.safe_load(f) or {}

    if not isinstance(obj, dict):
        return {}

    validate_config(obj, config_path=config_path, unknown_keys="ignore")

    return obj


def generate_mermaid_text_from_config_path(
    config_path: str,
    *,
    direction: str = _DEFAULT_DIRECTION,
    font_size_px: int = _DEFAULT_FONT_SIZE_PX,
    node_spacing: int = _DEFAULT_NODE_SPACING,
    rank_spacing: int = _DEFAULT_RANK_SPACING,
    include_init: bool = True,
) -> str:
    """Brief: Generate Mermaid diagram text for a config file.

    Inputs:
      - config_path: YAML config path.

    Outputs:
      - Mermaid diagram text.
    """

    cfg = load_config(config_path)
    plugins = normalize_plugins(cfg)

    server_cfg = cfg.get("server") or {}
    if not isinstance(server_cfg, dict):
        server_cfg = {}
    resolver_cfg = server_cfg.get("resolver") or {}
    if not isinstance(resolver_cfg, dict):
        resolver_cfg = {}
    resolver_mode = str(resolver_cfg.get("mode", "forward") or "forward").lower()

    listener_lines = extract_listener_lines(cfg)
    upstream_lines = extract_upstream_lines(cfg, resolver_mode=resolver_mode)

    return render_mermaid(
        plugins,
        config_path=str(config_path),
        resolver_mode=resolver_mode,
        listener_lines=listener_lines,
        upstream_lines=upstream_lines,
        direction=direction,
        font_size_px=font_size_px,
        node_spacing=node_spacing,
        rank_spacing=rank_spacing,
        include_init=include_init,
    )


def diagram_png_path_for_config(config_path: str) -> str:
    """Brief: Compute the diagram PNG path for a given config path.

    Inputs:
      - config_path: Path to the YAML config.

    Outputs:
      - str: PNG path used by ensure_config_diagram_png().
    """

    return f"{config_path}.mermaid.png"


def diagram_mmd_path_for_config(config_path: str) -> str:
    """Brief: Compute the diagram .mmd path for a given config path.

    Inputs:
      - config_path: Path to the YAML config.

    Outputs:
      - str: Mermaid source path used by ensure_config_diagram_png().
    """

    return f"{config_path}.mermaid.mmd"


def _is_stale(input_path: str, output_path: str) -> bool:
    """Brief: True when output_path is missing or older than input_path.

    Inputs:
      - input_path: Source file path.
      - output_path: Derived artifact path.

    Outputs:
      - bool: True when regeneration should occur.
    """

    try:
        out_stat = os.stat(output_path)
    except FileNotFoundError:
        return True
    except Exception:
        return True

    try:
        in_stat = os.stat(input_path)
    except Exception:
        return True

    return float(in_stat.st_mtime) > float(out_stat.st_mtime)


def _mmdc_fallback_paths() -> list[Path]:
    """Brief: Candidate filesystem locations for mmdc in containerized envs.

    Inputs:
      - None.

    Outputs:
      - list[Path]: Paths to check when `mmdc` is not available on PATH.

    Notes:
      - Some Docker images mount the repo at /foghorn and install node
        dependencies there.
    """

    return [
        Path("/foghorn/node_modules/mmdc"),
        Path("/foghorn/node_modules/.bin/mmdc"),
    ]


def _find_mmdc_cmd() -> list[str] | None:
    """Brief: Locate a runnable command for mmdc.

    Inputs:
      - None.

    Outputs:
      - list[str] | None: Command prefix to invoke mmdc, else None.

    Behaviour:
      - Prefer PATH (shutil.which('mmdc')).
      - If missing, check for /foghorn/node_modules/mmdc (and .bin/mmdc).
      - If a fallback file exists but is not executable, try running it via node
        (when node is available on PATH).
    """

    mmdc = shutil.which("mmdc")
    if mmdc:
        return [mmdc]

    node = shutil.which("node")

    for p in _mmdc_fallback_paths():
        try:
            if not p.is_file():
                continue
            if os.access(str(p), os.X_OK):
                return [str(p)]
            if node:
                return [node, str(p)]
        except Exception:
            continue

    return None


def _render_png_with_mmdc(*, mmd_text: str, output_png_path: str) -> tuple[bool, str]:
    """Brief: Render Mermaid text to a PNG using mmdc.

    Inputs:
      - mmd_text: Mermaid flowchart text.
      - output_png_path: Destination PNG path.

    Outputs:
      - (ok, detail)
    """

    mmdc_cmd = _find_mmdc_cmd()
    if not mmdc_cmd:
        return False, "mmdc not found"

    out_path = Path(output_png_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="foghorn-mermaid-") as td:
        in_path = Path(td) / "diagram.mmd"
        in_path.write_text(mmd_text, encoding="utf-8")

        cmd = [*mmdc_cmd, "-i", str(in_path), "-o", str(out_path)]
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as exc:
            return False, f"failed to run mmdc: {exc}"

        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            return False, f"mmdc failed: {err}" if err else "mmdc failed"

    return True, "ok"


def _render_png_with_python_mermaid(
    *, mmd_text: str, output_png_path: str
) -> tuple[bool, str]:
    """Brief: Best-effort PNG rendering via python_mermaid.

    Inputs:
      - mmd_text: Mermaid flowchart text.
      - output_png_path: Destination PNG path.

    Outputs:
      - (ok, detail)

    Notes:
      - The python_mermaid API differs across versions; this function is very
        defensive and should be treated as an optional fallback.
    """

    try:
        import python_mermaid  # type: ignore
    except Exception:
        return False, "python_mermaid not installed"

    # Try a few likely APIs.
    try:
        fn = getattr(python_mermaid, "render", None)
        if callable(fn):
            out = fn(mmd_text, output_format="png")
            if isinstance(out, (bytes, bytearray, memoryview)):
                Path(output_png_path).write_bytes(bytes(out))
                return True, "ok"
    except Exception as exc:
        return False, f"python_mermaid render() failed: {exc}"

    return False, "python_mermaid has no supported render API"


def ensure_config_diagram_png(
    *,
    config_path: str,
    output_png_path: str | None = None,
    output_mmd_path: str | None = None,
) -> tuple[bool, str, str | None]:
    """Brief: Ensure a PNG config diagram exists and is up-to-date.

    Inputs:
      - config_path: YAML config path.
      - output_png_path: Optional explicit output path for PNG.
      - output_mmd_path: Optional explicit output path for Mermaid source.

    Outputs:
      - (ok, detail, png_path)

    Behaviour:
      - If the PNG is missing or older than the config file, regenerate it.
      - If no renderer is available, returns ok=False with a helpful detail.
    """

    cfg_path = str(config_path)
    if not cfg_path:
        return False, "config_path is empty", None

    if output_png_path is None:
        output_png_path = diagram_png_path_for_config(cfg_path)
    if output_mmd_path is None:
        output_mmd_path = diagram_mmd_path_for_config(cfg_path)

    if not os.path.isfile(cfg_path):
        return False, f"config not found: {cfg_path}", None

    if not _is_stale(cfg_path, output_png_path):
        return True, "up-to-date", output_png_path

    try:
        mmd_text = generate_mermaid_text_from_config_path(cfg_path)
    except Exception as exc:
        return False, f"failed to generate mermaid text: {exc}", None

    # Best-effort: also write the .mmd next to the PNG for debugging.
    try:
        Path(output_mmd_path).write_text(mmd_text, encoding="utf-8")
    except Exception:
        pass

    ok, detail = _render_png_with_mmdc(
        mmd_text=mmd_text, output_png_path=output_png_path
    )
    if not ok:
        # Optional fallback.
        ok2, detail2 = _render_png_with_python_mermaid(
            mmd_text=mmd_text, output_png_path=output_png_path
        )
        if ok2:
            return True, "rendered with python_mermaid", output_png_path
        return False, detail, None

    return True, "rendered with mmdc", output_png_path
