#!/usr/bin/env python3
"""Brief: Generate a Mermaid diagram describing plugin ordering and potential overrides.

Inputs:
  - --config (str): Path to a Foghorn YAML config file. Default: ./config/config.yaml
  - --output (str, optional): Write the Mermaid text to this path. When omitted,
    output is written to stdout.
  - --direction (TB|LR): Mermaid flow direction. Default: TB (top-to-bottom).
  - --font-size (int): Diagram font size (px) applied via Mermaid init directive.
  - --node-spacing (int): Mermaid flowchart node spacing (init directive).
  - --rank-spacing (int): Mermaid flowchart rank spacing (init directive).
  - --no-init: Disable Mermaid init directive.

Outputs:
  - Mermaid flowchart text ("flowchart TB") showing:
      - listener configuration (UDP/TCP/DoT/DoH) from the config
      - upstream endpoint configuration (when resolver.mode == forward)
      - pre_resolve execution order (pre_priority)
      - cache hit/miss branching
      - resolver mode (forward/recursive/master)
      - post_resolve execution order (post_priority)
      - potential short-circuits (deny/override/drop) and upstream routing

Notes:
  - This script reads the config file but does not modify it.
  - Plugin alias/module resolution prefers the generated JSON schema registry
    under `assets/config-schema.json` ("$defs.PluginConfigs") so aliases match
    runtime discovery.
  - Priority extraction supports both legacy keys (pre_priority/post_priority/
    setup_priority/priority) and the v2-style blocks used in config files:
      - setup: {priority: <int>}
      - hooks:
          pre_resolve:  {priority: <int>}
          post_resolve: {priority: <int>}

Example:
  PYTHONPATH=src python3 scripts/generate_config_mermaid.py --config ./config/config.yaml > plugins.mmd
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Optional

import yaml

# Add the 'src' directory to sys.path to resolve 'foghorn' module imports.
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
src_dir = project_root / "src"
if src_dir.is_dir() and str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Keep the output clean when users redirect Mermaid text to a file.
logging.basicConfig(level=logging.ERROR)

# Import config normalization/variable expansion without pulling in optional
# runtime dependencies (e.g. cache backends).
from foghorn.config.config_schema import get_default_schema_path, validate_config


_ALLOWED_PIPELINE_ACTIONS = {"deny", "override", "drop", "allow"}

# Mermaid render defaults.
# These are intentionally a bit "large" so the generated SVGs/images remain readable
# when embedded in docs (GitHub tends to downscale wide diagrams aggressively).
_DEFAULT_DIRECTION = "TB"  # Top-to-bottom.
_DEFAULT_FONT_SIZE_PX = 18
_DEFAULT_NODE_SPACING = 80
_DEFAULT_RANK_SPACING = 90


@dataclass(frozen=True)
class _PluginInfo:
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
      - _PluginInfo instance.
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
class _PluginSource:
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
      - _PluginSource instance.
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


def _extract_plugin_aliases_from_decorators(prefix_text: str) -> list[str]:
    """Brief: Extract @plugin_aliases('a', 'b') strings from a nearby text prefix.

    Inputs:
      - prefix_text: Text immediately preceding a class definition.

    Outputs:
      - list[str]: Alias strings (not yet normalized).

    Notes:
      - This is best-effort and only handles string-literal aliases.
    """

    if "plugin_aliases" not in prefix_text:
        return []

    # Look at a small window; handle both one-line and short multi-line decorator usage.
    m = re.search(
        r"@plugin_aliases\((?P<body>.*?)\)\s*$", prefix_text, re.DOTALL | re.MULTILINE
    )
    if not m:
        return []

    body = m.group("body")
    return re.findall(r"['\"]([^'\"]+)['\"]", body)


def _module_from_path(py_path: Path) -> str:
    """Brief: Derive a Python module path from an on-disk plugin file.

    Inputs:
      - py_path: Path to a .py file under src/.

    Outputs:
      - str: Module path (e.g. foghorn.plugins.resolve.filter).
    """

    rel = py_path.relative_to(src_dir)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1][:-3]  # strip .py
    return ".".join(parts)


def _module_to_file(module: str) -> Optional[Path]:
    """Brief: Convert a Python module path into a source file path under src/.

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

    parts = mod.split(".")
    py_candidate = src_dir.joinpath(*parts).with_suffix(".py")
    if py_candidate.is_file():
        return py_candidate

    init_candidate = src_dir.joinpath(*parts) / "__init__.py"
    if init_candidate.is_file():
        return init_candidate

    return None


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
) -> Optional[_PluginSource]:
    """Brief: Build _PluginSource for a single plugin class.

    Inputs:
      - alias: Normalized alias.
      - module: Python module path (without class name).
      - class_name: Plugin class name.
      - file_path: Python file path.

    Outputs:
      - Optional[_PluginSource]: Source metadata, or None when the class cannot be parsed.
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

    # Action scan note:
    # Many plugins build PluginDecision objects in helper methods called by
    # pre_resolve/post_resolve. To avoid missing important edges (like
    # Filter deny/override), scan the full class body for constant
    # PluginDecision actions and attribute them to phases the class
    # participates in.
    all_actions = _scan_actions_in_text(class_text)
    has_pre = bool(pre_block.strip())
    has_post = bool(post_block.strip())
    pre_actions = set(all_actions) if has_pre else set()
    post_actions = set(all_actions) if has_post else set()

    sets_upstreams = _scan_sets_upstreams_in_text(class_text)
    has_setup = bool(setup_block.strip())

    return _PluginSource(
        alias=alias,
        module=module,
        class_name=class_name,
        file_path=file_path,
        has_setup=has_setup,
        pre_actions=pre_actions,
        post_actions=post_actions,
        sets_upstreams=sets_upstreams,
    )


def _build_plugin_source_index_from_schema() -> dict[str, _PluginSource]:
    """Brief: Build alias -> plugin source metadata from assets/config-schema.json.

    Inputs:
      - None.

    Outputs:
      - dict[str, _PluginSource]: Mapping from normalized alias to plugin metadata.

    Notes:
      - This prefers the generated schema's plugin registry ("$defs.PluginConfigs")
        so plugin alias/module resolution stays consistent with runtime discovery.
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

    plugin_cfgs = (
        defs.get("PluginConfigs")
        or defs.get("plugin_configs")
        or defs.get("pluginConfigs")
    )
    if not isinstance(plugin_cfgs, dict):
        return {}

    index: dict[str, _PluginSource] = {}

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

        # Ensure the default alias is always present.
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


def _build_plugin_source_index_from_scan() -> dict[str, _PluginSource]:
    """Brief: Build alias -> plugin source metadata by scanning src/ files.

    Inputs:
      - None.

    Outputs:
      - dict[str, _PluginSource]: Mapping from normalized alias to plugin metadata.

    Notes:
      - Scans only `src/foghorn/plugins/resolve/` because this script is intended
        to diagram the DNS query pipeline plugins.
      - This is a fallback when the generated schema registry cannot be read.
    """

    base = src_dir / "foghorn" / "plugins" / "resolve"
    index: dict[str, _PluginSource] = {}

    for py_path in sorted(base.rglob("*.py")):
        try:
            text = py_path.read_text(encoding="utf-8")
        except Exception:
            continue

        module = _module_from_path(py_path)

        # Identify classes that look like plugins.
        for m in _CLASS_RE.finditer(text):
            bases = m.group("bases")
            if "BasePlugin" not in bases:
                continue

            class_name = m.group("name")

            # Capture class body text by slicing until the next top-level class.
            start = m.start()
            next_match = _CLASS_RE.search(text, m.end())
            end = next_match.start() if next_match else len(text)
            class_text = text[start:end]

            # Decorator scan window: a small prefix before 'class'.
            prefix_start = max(0, start - 800)
            prefix = text[prefix_start:start]

            aliases = set(_extract_plugin_aliases_from_decorators(prefix))
            aliases.add(_default_alias_for_class(class_name))

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

            for raw_alias in aliases:
                alias = _normalize_alias(raw_alias)
                if not alias:
                    continue
                # Keep the first hit to avoid random overrides.
                if alias in index:
                    continue
                index[alias] = _PluginSource(
                    alias=alias,
                    module=module,
                    class_name=class_name,
                    file_path=py_path,
                    has_setup=has_setup,
                    pre_actions=pre_actions,
                    post_actions=post_actions,
                    sets_upstreams=sets_upstreams,
                )

    return index


def _build_plugin_source_index() -> dict[str, _PluginSource]:
    """Brief: Build alias -> plugin source metadata.

    Inputs:
      - None.

    Outputs:
      - dict[str, _PluginSource]: Mapping from normalized alias to plugin metadata.

    Notes:
      - Prefer the generated JSON schema plugin registry when available.
      - Fall back to scanning the source tree when schema metadata can't be read.
    """

    idx = _build_plugin_source_index_from_schema()
    if idx:
        return idx
    return _build_plugin_source_index_from_scan()


def _derive_display_name(entry: dict[str, Any]) -> str:
    """Brief: Choose a human-facing identifier for a plugin config entry.

    Inputs:
      - entry: Plugin entry mapping from config.

    Outputs:
      - str: Prefer 'id', then 'name', then 'type'/'module'.
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
      - entry: Plugin entry mapping (one item in cfg['plugins']).

    Outputs:
      - (setup_priority, pre_priority, post_priority)

    Notes:
      - Supports v2-style blocks:
          setup.priority
          hooks.pre_resolve.priority
          hooks.post_resolve.priority
      - Also supports legacy fields:
          setup_priority/pre_priority/post_priority/priority
    """

    # v2-style
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

    # legacy
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


_PLUGIN_SOURCE_INDEX: dict[str, _PluginSource] | None = None


def _get_plugin_source_index() -> dict[str, _PluginSource]:
    """Brief: Lazily build (and cache) the plugin source index.

    Inputs:
      - None.

    Outputs:
      - dict[str, _PluginSource]: Alias -> source metadata.
    """

    global _PLUGIN_SOURCE_INDEX
    if _PLUGIN_SOURCE_INDEX is None:
        _PLUGIN_SOURCE_INDEX = _build_plugin_source_index()
    return _PLUGIN_SOURCE_INDEX


def _lookup_plugin_source(type_key: str) -> Optional[_PluginSource]:
    """Brief: Find plugin source metadata for a config 'type' / 'module' identifier.

    Inputs:
      - type_key: Plugin type/alias or dotted path.

    Outputs:
      - Optional[_PluginSource]: Source metadata when resolvable.

    Notes:
      - For dotted identifiers, we heuristically treat the last path segment as a
        class name and compute the default alias.
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


def _has_nonempty_list(value: object) -> bool:
    """Brief: Return True when value is a non-empty list-like.

    Inputs:
      - value: Any object.

    Outputs:
      - bool: True when value is a list with at least one item.
    """

    return isinstance(value, list) and bool(value)


def _constrain_plugin_info_for_config(
    info: _PluginInfo,
    *,
    entry_config: dict[str, Any],
) -> _PluginInfo:
    """Brief: Adjust inferred plugin phases/actions using config-specific hints.

    Inputs:
      - info: Normalized plugin metadata derived from schema/source.
      - entry_config: The plugin instance's `config:` mapping from the YAML file.

    Outputs:
      - _PluginInfo: Updated plugin info, potentially with actions removed or
        a phase suppressed when it cannot have any effect for the provided config.

    Notes:
      - This is intentionally conservative and currently only adds special-casing
        for plugins where we can safely infer behavior from config.
    """

    # Filter plugin config-awareness:
    # - Only show the post_resolve phase when IP rules exist.
    # - Only show a drop edge when deny_response explicitly requests it.
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
            # Without any blocked IP rules, Filter's post_resolve path is a
            # no-op for diagram purposes.
            return replace(
                info,
                post_priority=None,
                post_actions=set(),
                pre_actions=pre_actions,
            )

        return replace(info, pre_actions=pre_actions, post_actions=post_actions)

    return info


def _normalize_plugins(cfg: dict[str, Any]) -> list[_PluginInfo]:
    """Brief: Parse config plugins and resolve metadata needed for diagram generation.

    Inputs:
      - cfg: Parsed config mapping.

    Outputs:
      - list[_PluginInfo]: One element per plugin entry.
    """

    plugins_raw = cfg.get("plugins") or []
    if not isinstance(plugins_raw, list):
        return []

    out: list[_PluginInfo] = []

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

        info = _PluginInfo(
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
      - prefix: String prefix to namespace node IDs.
      - name: Human name.
      - idx: Stable index.

    Outputs:
      - str: Mermaid node ID.
    """

    safe = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    safe = re.sub(r"_+", "_", safe).strip("_")
    if not safe:
        safe = "plugin"
    return f"{prefix}_{idx}_{safe}"


def _extract_listener_lines(cfg: dict[str, Any]) -> list[str]:
    """Brief: Extract human-friendly listener lines from config.

    Inputs:
      - cfg: Parsed config mapping.

    Outputs:
      - list[str]: Listener descriptions like "udp: 0.0.0.0:53".

    Notes:
      - Supports both server.listen.dns.{udp,tcp} and server.listen.{udp,tcp,dot,doh}
        blocks.
      - Only enabled listeners are included.
    """

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

    # Stable ordering.
    out: list[str] = []
    for k in ("udp", "tcp", "dot", "doh"):
        if k in found:
            out.append(found[k])
    return out


def _extract_upstream_lines(cfg: dict[str, Any], *, resolver_mode: str) -> list[str]:
    """Brief: Extract human-friendly upstream endpoint lines from config.

    Inputs:
      - cfg: Parsed config mapping.
      - resolver_mode: Effective resolver mode.

    Outputs:
      - list[str]: Upstream descriptions (empty unless resolver_mode == 'forward').
    """

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

    # Summary line first.
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


def _render_mermaid(
    plugins: list[_PluginInfo],
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
    """Brief: Render the full Mermaid diagram.

    Inputs:
      - plugins: Normalized plugin info list.
      - config_path: Path used for display in diagram header.
      - resolver_mode: Configured resolver mode string.
      - listener_lines: Listener descriptions derived from config.
      - upstream_lines: Upstream descriptions derived from config.
      - direction: Mermaid flow direction ("TB" or "LR").
      - font_size_px: Mermaid theme font size (in pixels).
      - node_spacing: Mermaid flowchart node spacing.
      - rank_spacing: Mermaid flowchart rank spacing.
      - include_init: When True, emits a Mermaid init directive to make the diagram
        render at a more readable size.

    Outputs:
      - str: Mermaid flowchart text.
    """

    # Pre chain: only include entries that declare a pre_resolve hook priority.
    pre_chain = [p for p in plugins if p.pre_priority is not None]
    pre_chain.sort(key=lambda p: (int(p.pre_priority or 0), p.idx))

    # Post chain: only include entries that declare a post_resolve hook priority.
    post_chain = [p for p in plugins if p.post_priority is not None]
    post_chain.sort(key=lambda p: (int(p.post_priority or 0), p.idx))

    has_drop = any(("drop" in p.pre_actions) for p in pre_chain) or any(
        ("drop" in p.post_actions) for p in post_chain
    )

    # Setup chain: include setup plugins (setup_priority filled only for setup plugins).
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
        # Mermaid requires this directive to appear before the diagram definition.
        lines.append(f"%%{{init: {json.dumps(init_cfg)} }}%%")

    lines.append(f"%% Generated from: {config_path}")
    lines.append(f"flowchart {direction}")
    lines.append("  %% Core nodes")

    if listener_lines:
        lst = "<br/>".join(listener_lines)
        lines.append(f'  Listeners["Listeners<br/>{lst}"]')

    lines.append("  Q([Query])")
    lines.append("  Cache{Cache hit?}")
    lines.append(
        f'  Resolver["Resolver mode: {resolver_mode}<br/>options: forward | recursive | master (none)"]'
    )

    mode = str(resolver_mode or "forward").lower()
    if mode == "none":
        mode = "master"
    if mode == "recursive":
        lines.append("  Upstream[Recursive resolver]")
    elif mode == "master":
        lines.append("  Upstream[Master/none: no forwarding (REFUSED)]")
    else:
        lines.append("  Upstream[Forward to upstreams]")

    if upstream_lines and mode == "forward":
        ups = "<br/>".join(upstream_lines)
        lines.append(f'  Upstreams["Upstreams<br/>{ups}"]')

    lines.append("  Resp([Response])")
    if has_drop:
        # Parentheses in labels can trip some Mermaid parsers unless quoted.
        lines.append('  Drop(["Drop (no reply)"])')
    lines.append("")

    if listener_lines:
        lines.append("  Listeners --> Q")

    # Query path
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

    # Pre chain (stacked vertically to keep the diagram narrow)
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

            # Merge short-circuit edges into a single sink so Response stays tidy.
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

    # Cache branching
    lines.append("    Cache -->|hit| Resp")
    lines.append("    Cache -->|miss| Resolver")
    lines.append("    Resolver --> Upstream")

    upstream_tail = "Upstream"
    if upstream_lines and mode == "forward":
        lines.append("    Upstream --> Upstreams")
        upstream_tail = "Upstreams"

    # Post chain (stacked vertically to keep the diagram narrow)
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

            resp_bits: list[str] = []
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


def _load_config(config_path: str) -> dict[str, Any]:
    """Brief: Load and normalize config for diagram generation.

    Inputs:
      - config_path: Path to YAML config.

    Outputs:
      - dict: Parsed config mapping.

    Notes:
      - Uses foghorn.config.config_schema.validate_config() to perform variable
        expansion and lightweight normalization in-memory.
      - This does not write back to the config file.
    """

    with open(config_path, "r", encoding="utf-8") as f:
        obj = yaml.safe_load(f) or {}

    if not isinstance(obj, dict):
        return {}

    # Normalize/expand in place. Treat unknown keys as non-fatal so the script
    # remains useful with local, non-schema config extensions.
    validate_config(obj, config_path=config_path, unknown_keys="ignore")

    return obj


def main(argv: Optional[list[str]] = None) -> int:
    """Brief: CLI entry point.

    Inputs:
      - argv: Optional CLI args (defaults to sys.argv).

    Outputs:
      - int: Exit code (0 on success).

    Example:
      PYTHONPATH=src python3 scripts/generate_config_mermaid.py --config ./config/config.yaml
    """

    parser = argparse.ArgumentParser(description="Generate config Mermaid diagram")
    parser.add_argument(
        "--config",
        default=str(project_root / "config" / "config.yaml"),
        help="Path to YAML config (default: ./config/config.yaml)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write Mermaid text output to this file (default: stdout)",
    )
    parser.add_argument(
        "--direction",
        choices=["TB", "LR"],
        default=_DEFAULT_DIRECTION,
        help="Mermaid flow direction (default: TB = top-to-bottom)",
    )
    parser.add_argument(
        "--font-size",
        type=int,
        default=_DEFAULT_FONT_SIZE_PX,
        help="Mermaid theme font size in pixels (default: 18)",
    )
    parser.add_argument(
        "--node-spacing",
        type=int,
        default=_DEFAULT_NODE_SPACING,
        help="Mermaid flowchart node spacing (default: 80)",
    )
    parser.add_argument(
        "--rank-spacing",
        type=int,
        default=_DEFAULT_RANK_SPACING,
        help="Mermaid flowchart rank spacing (default: 90)",
    )
    parser.add_argument(
        "--no-init",
        action="store_true",
        help="Disable Mermaid init directive (theme/spacing tweaks)",
    )

    args = parser.parse_args(argv)

    cfg = _load_config(str(args.config))
    plugins = _normalize_plugins(cfg)

    server_cfg = cfg.get("server") or {}
    if not isinstance(server_cfg, dict):
        server_cfg = {}
    resolver_cfg = server_cfg.get("resolver") or {}
    if not isinstance(resolver_cfg, dict):
        resolver_cfg = {}
    resolver_mode = str(resolver_cfg.get("mode", "forward") or "forward").lower()

    listener_lines = _extract_listener_lines(cfg)
    upstream_lines = _extract_upstream_lines(cfg, resolver_mode=resolver_mode)

    text = _render_mermaid(
        plugins,
        config_path=str(args.config),
        resolver_mode=resolver_mode,
        listener_lines=listener_lines,
        upstream_lines=upstream_lines,
        direction=str(args.direction),
        font_size_px=int(args.font_size),
        node_spacing=int(args.node_spacing),
        rank_spacing=int(args.rank_spacing),
        include_init=not bool(args.no_init),
    )

    if args.output:
        out_path = Path(str(args.output))
        out_path.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
