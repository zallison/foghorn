#!/usr/bin/env python3
"""Brief: Generate a Mermaid diagram describing plugin ordering and potential overrides.

Inputs:
  - --config (str): Path to a Foghorn YAML config file. Default: ./config/config.yaml
  - --output (str, optional): Write the Mermaid text to this path. When omitted,
    output is written to stdout.

Outputs:
  - Mermaid flowchart text ("flowchart LR") showing:
      - setup() execution order (setup_priority)
      - pre_resolve execution order (pre_priority)
      - cache hit/miss branching
      - upstream resolution
      - post_resolve execution order (post_priority)
      - potential short-circuits (deny/override/drop) and upstream routing

Notes:
  - This script reads the config file but does not modify it.
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
import logging
import re
import sys
from dataclasses import dataclass, field
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
from foghorn.config.config_schema import validate_config


_ALLOWED_PIPELINE_ACTIONS = {"deny", "override", "drop", "allow"}


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


def _build_plugin_source_index() -> dict[str, _PluginSource]:
    """Brief: Build alias -> plugin source metadata by scanning src/ files.

    Inputs:
      - None.

    Outputs:
      - dict[str, _PluginSource]: Mapping from normalized alias to plugin metadata.

    Notes:
      - Scans only `src/foghorn/plugins/resolve/` because this script is intended
        to diagram the DNS query pipeline plugins.
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

        out.append(
            _PluginInfo(
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
        )

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


def _render_mermaid(plugins: list[_PluginInfo], *, config_path: str) -> str:
    """Brief: Render the full Mermaid diagram.

    Inputs:
      - plugins: Normalized plugin info list.
      - config_path: Path used for display in diagram header.

    Outputs:
      - str: Mermaid flowchart text.
    """

    # Pre chain: only include entries that declare a pre_resolve hook priority.
    pre_chain = [p for p in plugins if p.pre_priority is not None]
    pre_chain.sort(key=lambda p: (int(p.pre_priority or 0), p.idx))

    # Post chain: only include entries that declare a post_resolve hook priority.
    post_chain = [p for p in plugins if p.post_priority is not None]
    post_chain.sort(key=lambda p: (int(p.post_priority or 0), p.idx))

    # Setup chain: include setup plugins (setup_priority filled only for setup plugins).
    setup_chain = [p for p in plugins if p.setup_priority is not None]
    setup_chain.sort(key=lambda p: (int(p.setup_priority or 0), p.idx))

    lines: list[str] = []
    lines.append(f"%% Generated from: {config_path}")
    lines.append("flowchart LR")
    lines.append("  %% Core nodes")
    lines.append("  Q([Query])")
    lines.append("  Cache{Cache hit?}")
    lines.append("  Upstream[Upstream / recursive resolver]")
    lines.append("  Resp([Response])")
    # Parentheses in labels can trip some Mermaid parsers unless quoted.
    lines.append('  Drop(["Drop (no reply)"])')
    lines.append("")

    # Startup / setup
    if setup_chain:
        # Parentheses in subgraph titles can also require quoting.
        lines.append('  subgraph Startup["Startup: setup() phase"]')
        lines.append("    direction TB")
        lines.append("    Start([Start])")
        prev = "Start"
        for p in setup_chain:
            nid = _node_id("setup", p.name, p.idx)
            label = f"{p.name}<br/>{p.type_key}<br/>setup={p.setup_priority}"
            lines.append(f'    {nid}["{label}"]')
            lines.append(f"    {prev} --> {nid}")
            prev = nid
        lines.append("    Ready([Ready])")
        lines.append(f"    {prev} --> Ready")
        lines.append("  end")
        lines.append("")

    # Query path
    lines.append("  subgraph QueryPath[DNS query path]")

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
    lines.append("    Cache -->|miss| Upstream")

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
        lines.append(f"    Upstream --> {first_post}")
        lines.append(f"    {prev_post} --> Resp")
    else:
        lines.append("    Upstream --> Resp")

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
      PYTHONPATH=src python3 scripts/generate_plugin_mermaid.py --config ./config/config.yaml
    """

    parser = argparse.ArgumentParser(description="Generate plugin Mermaid diagram")
    parser.add_argument(
        "--config",
        default=str(project_root / "config" / "config.yaml"),
        help="Path to YAML config (default: ./config/config.yaml)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write output to this file (default: stdout)",
    )

    args = parser.parse_args(argv)

    cfg = _load_config(str(args.config))
    plugins = _normalize_plugins(cfg)
    text = _render_mermaid(plugins, config_path=str(args.config))

    if args.output:
        out_path = Path(str(args.output))
        out_path.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
