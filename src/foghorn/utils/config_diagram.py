"""Brief: Generate Graphviz dot config diagrams (and optional PNG renders) for a Foghorn config.

This module is a reusable library version of `scripts/generate_config_diagram.py`.

Inputs:
  - Config path (YAML) or already-parsed config mapping.
  - Optional rendering knobs (direction, spacing, font size).

Outputs:
  - Graphviz dot text.
  - Optional PNG image written to disk when the `dot` binary is available.

Notes:
  - PNG generation is best-effort and should never prevent server startup.
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

logger = logging.getLogger("foghorn.utils.config_diagram")


_ALLOWED_PIPELINE_ACTIONS = {"deny", "override", "drop", "allow"}

# Diagram render defaults.
#
# Notes:
#   - direction uses GraphViz rankdir-style values: TB or LR.
#   - node/rank spacing are GraphViz-style floats (nodesep/ranksep).
_DEFAULT_DIRECTION = "TB"  # Top-to-bottom.
_DEFAULT_THEME = "light"  # "light" | "dark".

# Prefer a generic sans family. Graphviz will map this to a platform-available font
# (e.g. DejaVu Sans on Linux, Helvetica on macOS).
_DEFAULT_FONT_FAMILY = "sans"

# Use a Graphviz colorscheme so the light/dark diagrams can share palette logic.
# Paired has light+dark variants for each hue, which works well across backgrounds.
_DEFAULT_COLORSCHEME = "paired12"

# Listener transport highlight colors.
# - Secure: blue
# - Insecure: red
#
# Notes:
#   - For the dark-theme diagram we choose the *lighter* paired colors for contrast.
#   - For the light-theme diagram we choose the *darker* paired colors for contrast.
_LISTENER_SECURE_FILL_DARK = f"/{_DEFAULT_COLORSCHEME}/1"
_LISTENER_INSECURE_FILL_DARK = f"/{_DEFAULT_COLORSCHEME}/5"
_LISTENER_SECURE_FILL_LIGHT = f"/{_DEFAULT_COLORSCHEME}/2"
_LISTENER_INSECURE_FILL_LIGHT = f"/{_DEFAULT_COLORSCHEME}/6"

# Subgraph/cluster shading (subtle background tint).
_CLUSTER_FILL_DARK = "#0f172a"
_CLUSTER_FILL_LIGHT = "#f3f4f6"

# Dark-theme outlines should be bright for contrast.
_DARK_OUTLINE = "#ffffff"

_CLUSTER_BORDER_DARK = _DARK_OUTLINE
_CLUSTER_BORDER_LIGHT = "#94a3b8"

# Highlight the resolver-mode decision node with a subtle fill distinct from default nodes.
_RESOLVER_FILL_DARK = "#1f2937"
_RESOLVER_FILL_LIGHT = "#e5e7eb"

_DEFAULT_FONT_SIZE_PX = 18
_DEFAULT_NODE_SPACING = 0.8
_DEFAULT_RANK_SPACING = 0.9


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
      - pre_deny_rcode/post_deny_rcode: Optional hint used by the diagram renderer
        to label deny edges with the effective RCODE (e.g. REFUSED) instead of
        assuming NXDOMAIN.
      - sets_upstreams: Whether plugin may set ctx.upstream_candidates/override.
      - routed_upstream_lines: Human-friendly route upstream lines (for upstream_router).

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

    pre_deny_rcode: Optional[str] = None
    post_deny_rcode: Optional[str] = None

    sets_upstreams: bool = False
    routed_upstream_lines: list[str] = field(default_factory=list)


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
      - has_pre_resolve/has_post_resolve: Whether the class defines those hook methods.
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
    has_pre_resolve: bool = False
    has_post_resolve: bool = False

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
        has_pre_resolve=has_pre,
        has_post_resolve=has_post,
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

    hook_all = _safe_int(hooks.get("priority"))

    pre_block = hooks.get("pre_resolve")
    post_block = hooks.get("post_resolve")
    setup_hook_block = hooks.get("setup")

    # setup priority:
    # - Prefer entry.setup.priority when present.
    # - Else accept hooks.setup as <int> or {priority: <int>}.
    # - Else fall back to hooks.priority.
    setup_prio = _safe_int(setup_block.get("priority"))
    if setup_prio is None:
        if isinstance(setup_hook_block, dict):
            setup_prio = _safe_int(setup_hook_block.get("priority"))
        else:
            setup_prio = _safe_int(setup_hook_block)
    if setup_prio is None:
        setup_prio = hook_all

    # Hook-specific priority can be configured as either:
    # - hooks.pre_resolve: <int>
    # - hooks.pre_resolve: {priority: <int>}
    pre_prio = None
    if isinstance(pre_block, dict):
        pre_prio = _safe_int(pre_block.get("priority"))
    else:
        pre_prio = _safe_int(pre_block)
    if pre_prio is None:
        pre_prio = hook_all

    post_prio = None
    if isinstance(post_block, dict):
        post_prio = _safe_int(post_block.get("priority"))
    else:
        post_prio = _safe_int(post_block)
    if post_prio is None:
        post_prio = hook_all

    generic = _safe_int(entry.get("priority"))
    pre_legacy = _safe_int(entry.get("pre_priority"))
    post_legacy = _safe_int(entry.get("post_priority"))
    setup_legacy = _safe_int(entry.get("setup_priority"))

    # Deprecated legacy fallbacks (kept for backward compatibility).
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


def _extract_upstream_router_route_lines(entry_config: dict[str, Any]) -> list[str]:
    """Brief: Build route/upstream lines for upstream_router config.

    Inputs:
      - entry_config: Plugin config mapping (entry["config"]).

    Outputs:
      - list[str]: Human-friendly lines describing each route and its upstreams.

    Notes:
      - This is diagram-only metadata; it does not attempt full validation.
      - The output is designed to look similar to `extract_upstream_lines()`:
        `transport: host[:port]` and `transport: url`.
      - Some configs in the wild define a shared `upstreams:` list next to `routes:`
        (instead of `routes[].upstreams`). The runtime plugin currently only uses
        `routes[].upstreams`, but for diagram purposes we try to render shared
        upstreams as a fallback so users can spot the intended wiring.
    """

    routes = entry_config.get("routes")
    if not isinstance(routes, list):
        return []

    shared_upstreams = entry_config.get("upstreams")
    if not isinstance(shared_upstreams, list):
        shared_upstreams = []

    def _infer_transport_from_url(url: str) -> str:
        """Brief: Infer transport label from a URL-like string.

        Inputs:
          - url: Upstream URL.

        Outputs:
          - str: Transport label ('doh', 'dot', 'tcp', 'udp').
        """

        u = (url or "").strip().lower()
        if u.startswith("https://") or u.startswith("http://"):
            return "doh"
        if u.startswith("tls://"):
            return "dot"
        if u.startswith("tcp://"):
            return "tcp"
        return "udp"

    out: list[str] = []

    for r in routes:
        if not isinstance(r, dict):
            continue

        domain = r.get("domain")
        suffix = r.get("suffix")

        match_bits: list[str] = []
        if isinstance(domain, str) and domain.strip():
            match_bits.append(f"domain={domain.strip()}")
        if isinstance(suffix, str) and suffix.strip():
            match_bits.append(f"suffix={suffix.strip()}")
        if not match_bits:
            continue

        # Prefer per-route upstreams. If missing, fall back to a shared list.
        # Also tolerate a legacy singular 'upstream' mapping.
        shared = False
        ups = r.get("upstreams")
        if not isinstance(ups, list) or not ups:
            legacy_up = r.get("upstream")
            if isinstance(legacy_up, dict):
                ups = [legacy_up]
            elif shared_upstreams:
                ups = list(shared_upstreams)
                shared = True
            else:
                ups = []

        route_label = "route: " + ", ".join(match_bits)
        if shared:
            route_label += " (shared upstreams)"
        out.append(route_label)

        if not ups:
            out.append("upstreams: (none)")
            continue

        for u in ups:
            if not isinstance(u, dict):
                continue

            transport = str(u.get("transport", "") or "").strip().lower()
            url = u.get("url")
            if isinstance(url, str) and url.strip():
                t = transport or _infer_transport_from_url(url)
                out.append(f"{t}: {url.strip()}")
                continue

            host = u.get("host")
            port = u.get("port")
            # For diagram purposes, if we have transport and port but host is a template variable
            # we still want to show SOMETHING to indicate the endpoint exists
            is_template_host = isinstance(host, str) and "${" in host
            if is_template_host and transport and port is not None:
                try:
                    p = int(port)
                except Exception:
                    p = port
                out.append(f"{transport}: {{host}}:{p}")
                continue

            if not isinstance(host, str) or not host.strip():
                continue

            t = transport or "udp"
            if port is None:
                out.append(f"{t}: {host.strip()}")
                continue

            try:
                p = int(port)
            except Exception:
                # Best-effort: show host even if port is invalid.
                out.append(f"{t}: {host.strip()}")
                continue

            out.append(f"{t}: {host.strip()}:{p}")

    return out


def _deny_response_to_rcode_label(deny_response: str) -> Optional[str]:
    """Brief: Map a deny_response mode to a concise diagram label.

    Inputs:
      - deny_response: Config string like 'nxdomain', 'refused', or 'nodata'.

    Outputs:
      - Optional[str]: Diagram label (e.g. 'REFUSED'), or None when the mode is
        better represented via a separate 'drop' edge.
    """

    mode = str(deny_response or "").strip().lower()
    if mode == "nxdomain":
        return "NXDOMAIN"
    if mode == "refused":
        return "REFUSED"
    if mode == "servfail":
        return "SERVFAIL"
    if mode in {"noerror_empty", "nodata"}:
        return "NOERROR (empty)"
    if mode == "ip":
        return "IP"
    if mode == "drop":
        return None
    return None


def _constrain_plugin_info_for_config(
    info: PluginInfo, *, entry_config: dict[str, Any]
) -> PluginInfo:
    """Brief: Adjust inferred plugin phases/actions using config-specific hints."""

    if info.cls_path in {
        "foghorn.plugins.resolve.filter.Filter",
        "foghorn.plugins.resolve.rate_limit.RateLimit",
        "foghorn.plugins.resolve.access_control.AccessControl",
    }:
        # For AccessControl, default to REFUSED instead of NXDOMAIN
        default_deny = (
            "refused"
            if info.cls_path == "foghorn.plugins.resolve.access_control.AccessControl"
            else "nxdomain"
        )
        deny_response = str(entry_config.get("deny_response", default_deny)).lower()
        deny_label = _deny_response_to_rcode_label(deny_response)

        pre_actions = set(info.pre_actions)
        post_actions = set(info.post_actions)

        # Drop is only relevant when explicitly configured.
        if deny_response != "drop":
            pre_actions.discard("drop")
            post_actions.discard("drop")

        # The diagram should show the effective RCODE, not the implementation
        # detail (Filter may use override wire replies for some deny_response
        # modes).
        pre_deny_rcode = deny_label
        post_deny_rcode = deny_label

        # IP-based deny_response shows "deny\nIP" edge label
        if deny_response == "ip":
            pre_deny_rcode = "IP"
            post_deny_rcode = "IP"

        # Pick a single short-circuit edge for the pre path based on deny_response.
        if deny_response == "drop":
            pre_actions.discard("override")
            pre_actions.discard("deny")
            pre_actions.add("drop")
            pre_deny_rcode = None
        else:
            pre_actions.discard("drop")
            pre_actions.discard("override")
            pre_actions.add("deny")

        has_ip_rules = _has_nonempty_list(
            entry_config.get("blocked_ips")
        ) or _has_nonempty_list(entry_config.get("blocked_ips_files"))
        if not has_ip_rules:
            return replace(
                info,
                post_priority=None,
                post_actions=set(),
                pre_actions=pre_actions,
                pre_deny_rcode=pre_deny_rcode,
                post_deny_rcode=post_deny_rcode,
            )

        # Post path: mirror the deny_response policy, preferring a single deny edge
        # over an 'override (wire reply)' implementation detail.
        if deny_response == "drop":
            post_actions.discard("override")
            post_actions.discard("deny")
            post_actions.add("drop")
            post_deny_rcode = None
        else:
            post_actions.discard("drop")
            post_actions.discard("override")
            post_actions.add("deny")

        return replace(
            info,
            pre_actions=pre_actions,
            post_actions=post_actions,
            pre_deny_rcode=pre_deny_rcode,
            post_deny_rcode=post_deny_rcode,
        )

    if info.cls_path == "foghorn.plugins.resolve.rate_limit.RateLimit":
        deny_response = str(entry_config.get("deny_response", "nxdomain")).lower()
        deny_label = _deny_response_to_rcode_label(deny_response)

        pre_actions = set(info.pre_actions)
        # Prefer a single deny edge with the effective RCODE label.
        pre_actions.discard("override")
        pre_actions.discard("drop")
        pre_actions.add("deny")

        return replace(
            info,
            pre_actions=pre_actions,
            post_priority=None,
            post_actions=set(),
            pre_deny_rcode=deny_label,
            post_deny_rcode=None,
        )

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

        # If the config doesn't specify priorities, the runtime defaults still
        # apply (BasePlugin pre/post_priority default to 100). Only enable phases
        # that exist on the plugin class.
        if src and src.has_pre_resolve and pre_prio is None:
            pre_prio = 100
        if src and src.has_post_resolve and post_prio is None:
            post_prio = 100

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

        # Plugin-specific diagram metadata.
        if info.cls_path == "foghorn.plugins.resolve.upstream_router.UpstreamRouter":
            info = replace(
                info,
                routed_upstream_lines=_extract_upstream_router_route_lines(entry_cfg),
            )

        info = _constrain_plugin_info_for_config(info, entry_config=entry_cfg)

        out.append(info)

    return out


def _node_id(prefix: str, name: str, idx: int) -> str:
    """Brief: Build a diagram-safe node identifier.

    Inputs:
      - prefix: Namespace prefix (e.g. 'pre', 'post', 'setup').
      - name: Human plugin name used for readability.
      - idx: Plugin index, included to ensure uniqueness.

    Outputs:
      - str: Node id (alphanumerics/underscores only).

    Notes:
      - This id format is compatible with Graphviz dot identifiers.
    """

    safe = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    safe = re.sub(r"_+", "_", safe).strip("_")
    if not safe:
        safe = "plugin"
    return f"{prefix}_{idx}_{safe}"


_ESCAPE_DOT_REPLACEMENTS = {
    "\\": "\\\\",
    '"': '\\"',
    "\n": "\\n",
}


def _escape_dot_label(text: str) -> str:
    """Brief: Escape a string for use inside a GraphViz dot double-quoted label.

    Inputs:
      - text: Label text.

    Outputs:
      - str: Escaped label text.

    Notes:
      - We use dot's normal string labels ("...") rather than HTML labels.
      - Newlines are represented as "\\n".
      - Comma-separated segments are split onto separate lines to keep nodes narrow.
    """

    out = str(text)

    # Keep label blocks readable by splitting delimiter-separated segments onto new lines.
    # Handle both delimited+space and bare delimiter.
    out = out.replace(", ", "\n")
    out = out.replace(",", "\n")
    out = out.replace("; ", "\n")
    out = out.replace(";", "\n")

    for orig, repl in _ESCAPE_DOT_REPLACEMENTS.items():
        out = out.replace(orig, repl)
    return out


def extract_listener_lines(cfg: dict[str, Any]) -> list[str]:
    """Brief: Extract human-friendly listener lines from config."""

    server_cfg = cfg.get("server")
    if not isinstance(server_cfg, dict):
        return []
    listen_cfg = server_cfg.get("listen")
    if not isinstance(listen_cfg, dict):
        return []

    found: dict[str, str] = {}

    dns_section = listen_cfg.get("dns")
    if not isinstance(dns_section, dict):
        dns_section = {}

    default_host = str(dns_section.get("host", "127.0.0.1"))
    try:
        default_port = int(dns_section.get("port", 5335) or 5335)
    except Exception:
        default_port = 5335

    defaults = {"udp": default_port, "tcp": default_port, "dot": 853, "doh": 1443}
    enabled_defaults = {"udp": True, "tcp": False, "dot": False, "doh": False}

    for name in ("udp", "tcp", "dot", "doh"):
        section = listen_cfg.get(name)
        if isinstance(section, dict):
            # Presence of a listener block implies enabled=true unless explicitly disabled.
            enabled = bool(section.get("enabled", True))
            host = str(section.get("host", default_host))
            try:
                port = int(section.get("port", defaults[name]) or defaults[name])
            except Exception:
                port = defaults[name]
        else:
            enabled = enabled_defaults[name]
            host = default_host
            port = defaults[name]

        if not enabled:
            continue
        found[name] = f"{name}: {host}:{port}"

    out: list[str] = []
    for k in ("udp", "tcp", "dot", "doh"):
        if k in found:
            out.append(found[k])
    return out


def extract_upstream_lines(cfg: dict[str, Any], *, resolver_mode: str) -> list[str]:
    """Brief: Extract human-friendly upstream endpoint lines from config.

    Inputs:
      - cfg: Parsed config mapping.
      - resolver_mode: Resolver mode string.

    Outputs:
      - list[str]: Upstream summary lines for the diagram. Backup upstream
        endpoints are included with a ``" (backup)"`` suffix.
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

    backup_cfg = upstream_cfg.get("backup") or {}
    backup_endpoints: list[Any] = []
    if isinstance(backup_cfg, dict):
        raw_backup_endpoints = backup_cfg.get("endpoints") or []
        if isinstance(raw_backup_endpoints, list):
            backup_endpoints = raw_backup_endpoints

    lines: list[str] = []

    strategy = str(upstream_cfg.get("strategy", "failover") or "failover")
    try:
        max_concurrent = int(upstream_cfg.get("max_concurrent", 1) or 1)
    except Exception:
        max_concurrent = 1
    lines.append(f"strategy={strategy}, max_concurrent={max_concurrent}")

    def _append_endpoint_lines(
        endpoint_list: list[Any], *, is_backup: bool = False
    ) -> None:
        """Brief: Append upstream endpoint lines to the diagram payload."""
        suffix = " (backup)" if is_backup else ""
        for ep in endpoint_list:
            if not isinstance(ep, dict):
                continue
            transport = str(ep.get("transport", "udp") or "udp")
            url = ep.get("url")
            if isinstance(url, str) and url.strip():
                lines.append(f"{transport}: {url.strip()}{suffix}")
                continue

            host = ep.get("host")
            if not isinstance(host, str) or not host.strip():
                continue
            host = host.strip()
            port = ep.get("port")
            if port is None:
                lines.append(f"{transport}: {host}{suffix}")
            else:
                try:
                    p = int(port)
                except Exception:
                    lines.append(f"{transport}: {host}{suffix}")
                else:
                    lines.append(f"{transport}: {host}:{p}{suffix}")

    _append_endpoint_lines(endpoints, is_backup=False)
    _append_endpoint_lines(backup_endpoints, is_backup=True)

    return lines


def render_dot(
    plugins: list[PluginInfo],
    *,
    config_path: str,
    resolver_mode: str,
    listener_lines: list[str],
    upstream_lines: list[str],
    direction: str = _DEFAULT_DIRECTION,
    theme: str = _DEFAULT_THEME,
    font_size_px: int = _DEFAULT_FONT_SIZE_PX,
    node_spacing: float = _DEFAULT_NODE_SPACING,
    rank_spacing: float = _DEFAULT_RANK_SPACING,
    include_init: bool = True,
) -> str:
    """Brief: Render the full GraphViz dot diagram.

    Inputs:
      - plugins: Normalized plugins.
      - config_path: Path to config file (for a header comment).
      - resolver_mode: forward|recursive|master (none).
      - listener_lines: Extracted listener lines.
      - upstream_lines: Extracted upstream endpoint lines.
      - direction: TB or LR.
      - theme: "light" or "dark".
      - font_size_px: Graph font size.
      - node_spacing: nodesep.
      - rank_spacing: ranksep.
      - include_init: When True, include global node/edge attributes.

    Outputs:
      - str: GraphViz dot text.
    """

    pre_chain = [p for p in plugins if p.pre_priority is not None]
    pre_chain.sort(key=lambda p: (int(p.pre_priority or 0), p.idx))

    post_chain = [p for p in plugins if p.post_priority is not None]
    post_chain.sort(key=lambda p: (int(p.post_priority or 0), p.idx))

    has_drop = any(("drop" in p.pre_actions) for p in pre_chain) or any(
        ("drop" in p.post_actions) for p in post_chain
    )

    direction = str(direction or _DEFAULT_DIRECTION).strip().upper()
    if direction not in {"TB", "LR"}:
        direction = _DEFAULT_DIRECTION

    theme = str(theme or _DEFAULT_THEME).strip().lower()
    if theme not in {"light", "dark"}:
        theme = _DEFAULT_THEME

    font_size_px = int(font_size_px or _DEFAULT_FONT_SIZE_PX)
    node_spacing = float(node_spacing or _DEFAULT_NODE_SPACING)
    rank_spacing = float(rank_spacing or _DEFAULT_RANK_SPACING)

    rankdir = "TB" if direction == "TB" else "LR"

    mode = str(resolver_mode or "forward").lower()
    if mode == "none":
        mode = "master"

    # Build endpoint groups.
    meta_bits = [str(x).strip() for x in upstream_lines if x and ":" not in str(x)]
    endpoints = [str(x).strip() for x in upstream_lines if x and ":" in str(x)]

    # Track protocols separately for security detection
    endpoint_protocols: set[str] = set()
    for raw_s in endpoints:
        raw_s = raw_s.strip()
        proto, _, _rest = raw_s.partition(":")
        proto = proto.strip().lower()
        if proto:
            endpoint_protocols.add(proto)

    seen: set[str] = set()
    items_insecure: list[str] = []
    items_secure: list[str] = []
    protos: set[str] = set()

    for raw_s in endpoints:
        raw_s = raw_s.strip()
        if not raw_s or raw_s in seen:
            continue
        seen.add(raw_s)

        proto, _, rest = raw_s.partition(":")
        proto = proto.strip().lower()
        rest = rest.strip()
        if not proto or not rest:
            continue

        protos.add(proto)
        item = f"{proto}: {rest}"
        if proto in {"udp", "tcp"}:
            items_insecure.append(item)
        elif proto in {"dot", "doh"}:
            items_secure.append(item)
        else:
            items_insecure.append(item)

    # Use tracked protocols for security detection
    has_insecure = bool(endpoint_protocols & {"udp", "tcp"}) or bool(items_insecure)
    has_secure = bool(endpoint_protocols & {"dot", "doh"}) or bool(items_secure)

    lines: list[str] = []
    lines.append(f"// Generated from: {config_path}")
    lines.append("digraph config_diagram {")
    lines.append(f"  rankdir={rankdir};")
    lines.append(f"  nodesep={node_spacing};")
    lines.append(f"  ranksep={rank_spacing};")
    lines.append(f"  fontsize={font_size_px};")

    if include_init:
        if theme == "dark":
            lines.append(
                f'  graph [bgcolor="#0b1020", fontcolor="#e5e7eb", fontname="{_DEFAULT_FONT_FAMILY}", colorscheme="{_DEFAULT_COLORSCHEME}"];'
            )
            lines.append(
                f'  node [shape=box, style="rounded,filled", fillcolor="#111827", fontcolor="#e5e7eb", color="{_DARK_OUTLINE}", fontname="{_DEFAULT_FONT_FAMILY}"];'
            )
            lines.append(
                f'  edge [color="#e5e7eb", fontcolor="#e5e7eb", fontname="{_DEFAULT_FONT_FAMILY}"];'
            )
        else:
            lines.append(
                f'  graph [fontname="{_DEFAULT_FONT_FAMILY}", colorscheme="{_DEFAULT_COLORSCHEME}"];'
            )
            lines.append(
                f'  node [shape=box, style="rounded,filled", fillcolor="#FFFFFF", fontname="{_DEFAULT_FONT_FAMILY}"];'
            )
            lines.append(
                f'  edge [color="#555555", fontcolor="#111827", fontname="{_DEFAULT_FONT_FAMILY}"];'
            )

    # Core nodes.
    #
    # Keep the primary request pipeline nodes aligned by using a shared dot "group".
    lines.append('  Q [shape=ellipse, label="Query", group="pipeline"];')
    lines.append('  Cache [shape=diamond, label="Cache hit?", group="pipeline"];')

    resolver_label = "Resolver mode: " + _escape_dot_label(resolver_mode)
    if include_init:
        resolver_fill = _RESOLVER_FILL_DARK if theme == "dark" else _RESOLVER_FILL_LIGHT
        lines.append(
            f'  Resolver [label="{resolver_label}", fillcolor="{resolver_fill}", group="pipeline"];'
        )
    else:
        lines.append(f'  Resolver [label="{resolver_label}", group="pipeline"];')

    if mode == "recursive":
        lines.append('  Upstream [label="Recursive resolver", group="pipeline"];')
    elif mode == "master":
        lines.append(
            '  Upstream [label="Master mode: no forwarding\\n(REFUSED)", group="pipeline"];'
        )
    else:
        lines.append('  Upstream [label="Forward to upstreams", group="pipeline"];')

    lines.append('  Resp [shape=ellipse, label="Response", group="pipeline"];')
    if has_drop:
        lines.append('  Drop [shape=ellipse, label="Drop (no reply)"];')

    def _comma_newlines(text: str) -> str:
        """Brief: Split comma-separated label segments into separate lines.

        Inputs:
          - text: Label text.

        Outputs:
          - str: Label text with commas replaced by newlines.
        """

        s = str(text or "")
        # Handle both ", " and ",".
        s = s.replace(", ", "\n")
        s = s.replace(",", "\n")
        return s

    def _cluster_outline_attrs() -> tuple[str, str]:
        """Brief: Get (color, style) attributes for cluster outlines.

        Inputs:
          - None.

        Outputs:
          - (color, style): Dot attribute values.
        """

        if theme == "dark":
            return _DARK_OUTLINE, "rounded"
        return _CLUSTER_BORDER_LIGHT, "rounded"

    # Listener nodes.
    if listener_lines:
        lines.append("  subgraph cluster_listeners {")
        lines.append('    label="Listeners";')
        if include_init:
            c, st = _cluster_outline_attrs()
            lines.append(f'    style="{st}";')
            lines.append(f'    color="{c}";')
        for raw in listener_lines:
            raw = str(raw or "").strip()
            if not raw:
                continue
            proto = raw.split(":", 1)[0].strip().lower() if ":" in raw else ""
            nid = f'Listener_{re.sub(r"[^a-zA-Z0-9_]", "_", proto) or "unknown"}'

            is_secure = proto in {"dot", "doh"}
            if is_secure:
                fill = (
                    _LISTENER_SECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_SECURE_FILL_LIGHT
                )
            else:
                fill = (
                    _LISTENER_INSECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_INSECURE_FILL_LIGHT
                )

            border = _DARK_OUTLINE if theme == "dark" else "#111827"
            # The palette choices use light fills on dark background, and dark
            # fills on light background.
            listener_font = "#111827" if theme == "dark" else "#ffffff"

            # Secure listeners are shaded blue, insecure listeners red.
            lines.append(
                f'    {nid} [label="{_escape_dot_label(_comma_newlines(raw))}", fillcolor="{fill}", fontcolor="{listener_font}", color="{border}"];'
            )
        lines.append("  }")
        for raw in listener_lines:
            raw = str(raw or "").strip()
            if not raw:
                continue
            proto = raw.split(":", 1)[0].strip().lower() if ":" in raw else ""
            nid = f'Listener_{re.sub(r"[^a-zA-Z0-9_]", "_", proto) or "unknown"}'
            lines.append(f"  {nid} -> Q;")

    # Plugin chains and upstreams.
    lines.append("  subgraph cluster_query {")
    lines.append('    label="DNS query path";')
    if include_init:
        c, st = _cluster_outline_attrs()
        lines.append(f'    style="{st}";')
        lines.append(f'    color="{c}";')

    # Box the resolver pipeline elements together.
    lines.append("    subgraph cluster_resolver {")
    lines.append('      label="Resolver";')
    if include_init:
        c, _st = _cluster_outline_attrs()
        fill = _CLUSTER_FILL_DARK if theme == "dark" else _CLUSTER_FILL_LIGHT
        lines.append('      style="rounded,filled";')
        lines.append(f'      fillcolor="{fill}";')
        lines.append(f'      color="{c}";')
    lines.append("      Cache;")
    lines.append("      Resolver;")
    lines.append("      Upstream;")
    lines.append("    }")

    has_pre_merge = any(
        (("deny" in p.pre_actions) or ("override" in p.pre_actions)) for p in pre_chain
    )
    has_post_merge = any(
        (("deny" in p.post_actions) or ("override" in p.post_actions))
        for p in post_chain
    )

    # Pre plugins.
    pre_node_ids: dict[int, str] = {}
    if pre_chain:
        lines.append("    subgraph cluster_pre {")
        lines.append('      label="Pre-Resolve Plugins";')
        if include_init:
            fill = _CLUSTER_FILL_DARK if theme == "dark" else _CLUSTER_FILL_LIGHT
            border = _CLUSTER_BORDER_DARK if theme == "dark" else _CLUSTER_BORDER_LIGHT
            lines.append('      style="rounded,filled";')
            lines.append(f'      fillcolor="{fill}";')
            lines.append(f'      color="{border}";')
        first_pre: str | None = None
        prev_pre: str | None = None
        for p in pre_chain:
            nid = _node_id("pre", p.name, p.idx)
            pre_node_ids[p.idx] = nid
            label = f"{_escape_dot_label(p.name)}\\n{_escape_dot_label(p.type_key)}\\npriority={p.pre_priority}"
            if p.sets_upstreams:
                label += "\\nroutes upstream"
            # Keep pre plugins aligned with the main pipeline.
            lines.append(f'      {nid} [label="{label}", group="pipeline"];')
            if first_pre is None:
                first_pre = nid
            if prev_pre is not None:
                lines.append(f"      {prev_pre} -> {nid};")
            prev_pre = nid

            resp_bits: list[str] = []
            if "deny" in p.pre_actions:
                rcode = getattr(p, "pre_deny_rcode", None) or "NXDOMAIN"
                resp_bits.append(r"deny\n" + rcode)
            if "override" in p.pre_actions:
                resp_bits.append(r"override\nwire reply")
            if resp_bits and has_pre_merge:
                # Avoid these side edges distorting the main vertical chain layout.
                label_text = "; ".join(resp_bits)
                # Manually escape quotes for DOT
                label_text = label_text.replace('"', '\\"')
                lines.append(
                    f'      {nid} -> PreMerge [label="{label_text}", weight=1, constraint=false];'
                )
            if "drop" in p.pre_actions:
                lines.append(f'      {nid} -> Drop [label="drop", constraint=false];')

        if has_pre_merge:
            # Place the merge node at the bottom of the pre-plugins box.
            lines.append('      PreMerge [shape=ellipse, label="Pre short-circuit"];')
            if prev_pre is not None:
                lines.append(f"      {prev_pre} -> PreMerge [style=invis, weight=10];")

        lines.append("    }")
        if first_pre is not None and prev_pre is not None:
            lines.append(f"    Q -> {first_pre};")
            lines.append(f"    {prev_pre} -> Cache;")

        if has_pre_merge:
            lines.append("    PreMerge -> Resp;")
    else:
        lines.append("    Q -> Cache;")

    lines.append('    Cache -> Resp [label="hit"];')
    lines.append('    Cache -> Resolver [label="miss"];')
    lines.append("    Resolver -> Upstream;")

    # Upstreams block (forward mode only).
    routed_plugins = [p for p in pre_chain if p.routed_upstream_lines]
    upstream_tails: list[str] = ["Upstream"]
    if upstream_lines and mode == "forward":
        lines.append("    subgraph cluster_upstreams {")
        lines.append('      label="Upstreams";')
        if include_init:
            c, _st = _cluster_outline_attrs()
            fill = _CLUSTER_FILL_DARK if theme == "dark" else _CLUSTER_FILL_LIGHT
            lines.append('      style="rounded,filled";')
            lines.append(f'      fillcolor="{fill}";')
            lines.append(f'      color="{c}";')

        def _emit_upstreams_node(
            *,
            node_id: str,
            items: list[str],
            security: str | None,
        ) -> None:
            """Brief: Emit an upstream endpoint node with optional security styling.

            Inputs:
              - node_id: Dot node id.
              - items: Endpoint label items.
              - security: "secure", "insecure", or None.

            Outputs:
              - None; appends to lines.
            """

            if security == "secure":
                title = "Upstreams (secure)"
                fill = (
                    _LISTENER_SECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_SECURE_FILL_LIGHT
                )
                font = "#111827" if theme == "dark" else "#ffffff"
                # Use blue color for secure
                fill = (
                    _LISTENER_SECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_SECURE_FILL_LIGHT
                )
                font = "#111827" if theme == "dark" else "#ffffff"
            elif security == "insecure":
                title = "Upstreams (insecure)"
                fill = (
                    _LISTENER_INSECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_INSECURE_FILL_LIGHT
                )
                font = "#111827" if theme == "dark" else "#ffffff"
            else:
                title = "Upstreams (insecure)"
                # If we couldn't detect security, default to insecure styling
                fill = (
                    _LISTENER_INSECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_INSECURE_FILL_LIGHT
                )
                font = "#111827" if theme == "dark" else "#ffffff"

            label_bits = [title] + meta_bits + items
            label = "\\n".join(
                _escape_dot_label(_comma_newlines(x)) for x in label_bits if x
            )

            attrs = [f'label="{label}"', 'group="pipeline"']
            if fill and font:
                attrs.append(f'fillcolor="{fill}"')
                attrs.append(f'fontcolor="{font}"')

            lines.append(f"      {node_id} [{', '.join(attrs)}];")

        if has_insecure and has_secure:
            _emit_upstreams_node(
                node_id="UpstreamsInsecure",
                items=items_insecure,
                security="insecure",
            )
            _emit_upstreams_node(
                node_id="UpstreamsSecure",
                items=items_secure,
                security="secure",
            )
            upstream_tails = ["UpstreamsInsecure", "UpstreamsSecure"]
        else:
            items = items_insecure if has_insecure else items_secure
            security = (
                "insecure" if has_insecure else ("secure" if has_secure else None)
            )
            security = (
                "insecure" if has_insecure else ("secure" if has_secure else None)
            )
            # If we couldn't detect from endpoint_lines (old config), default to insecure
            if not security and upstream_lines:
                security = "insecure"
            _emit_upstreams_node(node_id="Upstreams", items=items, security=security)
            upstream_tails = ["Upstreams"]

        # Emit routed upstreams as additional nodes in the upstreams cluster
        for p in routed_plugins:
            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", p.name).strip("_") or "plugin"
            rid = f"RoutedUpstream_{p.idx}_{safe_name}"

            raw_lines = list(p.routed_upstream_lines or [])

            # Analyze transported endpoints for security coloring
            routed_secure: list[str] = []
            routed_insecure: list[str] = []
            for line in raw_lines:
                if not line:
                    continue
                line = line.strip()
                # Only analyze endpoint lines (protocol: endpoint pattern), skip metadata like "route:"
                if ":" in line:
                    proto, _, _rest = line.partition(":")
                    proto = proto.strip().lower()
                    # Only classify transport-based endpoints, not metadata like "route:", "upstreams:", etc.
                    if proto in {"dot", "doh", "tcp", "udp"}:
                        if proto in {"dot", "doh"}:
                            routed_secure.append(line)
                        else:
                            routed_insecure.append(line)

            # Determine styling based on transported endpoints
            if routed_secure and routed_insecure:
                # Mixed: default to insecure styling
                r_fill = (
                    _LISTENER_INSECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_INSECURE_FILL_LIGHT
                )
                r_font = "#111827" if theme == "dark" else "#ffffff"
            elif routed_secure:
                r_fill = (
                    _LISTENER_SECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_SECURE_FILL_LIGHT
                )
                r_font = "#111827" if theme == "dark" else "#ffffff"
            elif routed_insecure:
                r_fill = (
                    _LISTENER_INSECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_INSECURE_FILL_LIGHT
                )
                r_font = "#111827" if theme == "dark" else "#ffffff"
            else:
                # No endpoints: default to insecure styling
                r_fill = (
                    _LISTENER_INSECURE_FILL_DARK
                    if theme == "dark"
                    else _LISTENER_INSECURE_FILL_LIGHT
                )
                r_font = "#111827" if theme == "dark" else "#ffffff"

            # Label: "Upstreams for\\n<plugin_name>"
            r_label = r"Upstreams for\n" + _escape_dot_label(p.name)
            payload = "\\n".join(
                _escape_dot_label(_comma_newlines(x)) for x in raw_lines if x
            )
            if payload:
                r_label += "\\n" + payload

            attrs = [
                f'label="{r_label}"',
                f'fillcolor="{r_fill}"',
                f'fontcolor="{r_font}"',
            ]
            lines.append(f"      {rid} [{', '.join(attrs)}];")
            upstream_tails.append(rid)

            # Add dashed arrow from plugin to its routed upstreams
            pre_nid = pre_node_ids.get(p.idx)
            if pre_nid:
                lines.append(
                    f"    {pre_nid} -> {rid} [style=dashed, constraint=false];"
                )

            # Upstream router plugins affect the cache by setting upstreams
            lines.append(f"    {pre_nid} -> Cache [style=solid, constraint=false];")

        for tail in upstream_tails:
            if tail.startswith("RoutedUpstream"):
                lines.append(f"    Upstream -> {tail} [style=dashed, splines=3];")
            else:
                lines.append(f"    Upstream -> {tail};")

        lines.append("    }")

        # Post plugins.
    if post_chain:
        lines.append("    subgraph cluster_post {")
        lines.append('      label="Post-Resolve Plugins";')
        if include_init:
            fill = _CLUSTER_FILL_DARK if theme == "dark" else _CLUSTER_FILL_LIGHT
            border = _CLUSTER_BORDER_DARK if theme == "dark" else _CLUSTER_BORDER_LIGHT
            lines.append('      style="rounded,filled";')
            lines.append(f'      fillcolor="{fill}";')
            lines.append(f'      color="{border}";')
        # Add post cluster drop node for post-resolve drop actions
        if any("drop" in p.post_actions for p in post_chain):
            lines.append('      PostDrop [shape=ellipse, label="Drop (no reply)"];')
        first_post: str | None = None
        prev_post: str | None = None
        for p in post_chain:
            nid = _node_id("post", p.name, p.idx)
            label = f"{_escape_dot_label(p.name)}\\n{_escape_dot_label(p.type_key)}\\npost={p.post_priority}"
            # Keep post plugins aligned with the main pipeline.
            lines.append(f'      {nid} [label="{label}", group="pipeline"];')

            if first_post is None:
                first_post = nid
            if prev_post is not None:
                lines.append(f"      {prev_post} -> {nid};")
            prev_post = nid

            resp_bits: list[str] = []
            if "deny" in p.post_actions:
                rcode = getattr(p, "post_deny_rcode", None) or "NXDOMAIN"
                resp_bits.append(r"deny\n" + rcode)
            if "override" in p.post_actions:
                resp_bits.append(r"override\nwire reply")
            if resp_bits and has_post_merge:
                # Avoid these side edges distorting the main vertical chain layout.
                label_text = "; ".join(resp_bits)
                # Manually escape quotes for DOT
                label_text = label_text.replace('"', '\\"')
                lines.append(
                    f'      {nid} -> PostMerge [label="{label_text}", weight=1, constraint=false];'
                )
            if "drop" in p.post_actions:
                lines.append(
                    f'      {nid} -> PostDrop [label="drop", constraint=false];'
                )

        if has_post_merge:
            # Place the merge node at the bottom of the post-plugins box.
            lines.append('      PostMerge [shape=ellipse, label="Post short-circuit"];')
            if prev_post is not None:
                lines.append(
                    f"      {prev_post} -> PostMerge [style=invis, weight=10];"
                )

        lines.append("    }")

        if has_post_merge:
            lines.append("    PostMerge -> Resp;")

        if first_post is not None and prev_post is not None:
            for tail in upstream_tails:
                lines.append(f"    {tail} -> {first_post};")
            lines.append(f"    {prev_post} -> Resp;")
    else:
        for tail in upstream_tails:
            lines.append(f"    {tail} -> Resp;")

    lines.append("  }")
    lines.append("}")

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


def generate_dot_text_from_config_path(
    config_path: str,
    *,
    direction: str = _DEFAULT_DIRECTION,
    theme: str = _DEFAULT_THEME,
    font_size_px: int = _DEFAULT_FONT_SIZE_PX,
    node_spacing: float = _DEFAULT_NODE_SPACING,
    rank_spacing: float = _DEFAULT_RANK_SPACING,
    include_init: bool = True,
) -> str:
    """Brief: Generate GraphViz dot diagram text for a config file.

    Inputs:
      - config_path: YAML config path.
      - direction: TB or LR.
      - theme: "light" or "dark".
      - font_size_px: Graph font size.
      - node_spacing: nodesep.
      - rank_spacing: ranksep.
      - include_init: When True, include global node/edge attrs.

    Outputs:
      - str: dot diagram text.
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

    return render_dot(
        plugins,
        config_path=str(config_path),
        resolver_mode=resolver_mode,
        listener_lines=listener_lines,
        upstream_lines=upstream_lines,
        direction=direction,
        theme=theme,
        font_size_px=font_size_px,
        node_spacing=node_spacing,
        rank_spacing=rank_spacing,
        include_init=include_init,
    )


def diagram_dark_png_path_for_config(config_path: str) -> str:
    """Brief: Compute the diagram dark-theme PNG path for a given config path.

    Inputs:
      - config_path: Path to the YAML config.

    Outputs:
      - str: Dark PNG path used by ensure_config_diagram_png().
    """

    return f"{config_path}.dot-dark.png"


def diagram_png_path_for_config(config_path: str) -> str:
    """Brief: Compute the diagram PNG path for a given config path.

    Inputs:
      - config_path: Path to the YAML config.

    Outputs:
      - str: PNG path used by ensure_config_diagram_png().
    """

    return f"{config_path}.dot.png"


def diagram_dot_path_for_config(config_path: str) -> str:
    """Brief: Compute the diagram .dot path for a given config path.

    Inputs:
      - config_path: Path to the YAML config.

    Outputs:
      - str: dot source path used by ensure_config_diagram_png().
    """

    return f"{config_path}.dot"


def diagram_dark_png_candidate_paths_for_config(config_path: str) -> list[Path]:
    """Brief: Candidate locations to find a pre-generated dark-theme diagram PNG.

    Inputs:
      - config_path: YAML config path.

    Outputs:
      - list[Path]: Candidate dark PNG paths, in priority order.

    Notes:
      - Prefer a canonical file in the config directory (diagram-dark.png).
      - Fall back to the auto-generated sibling of the config file
        (<config>.dot-dark.png).
    """

    cfg = Path(str(config_path))
    cfg_dir = cfg.parent
    return [
        cfg_dir / "diagram-dark.png",
        Path(diagram_dark_png_path_for_config(str(cfg))),
    ]


def diagram_png_candidate_paths_for_config(config_path: str) -> list[Path]:
    """Brief: Candidate locations to find a pre-generated config diagram PNG.

    Inputs:
      - config_path: YAML config path.

    Outputs:
      - list[Path]: Candidate PNG paths, in priority order.

    Notes:
      - Prefer a canonical file in the config directory (diagram.png).
      - Fall back to the auto-generated sibling of the config file
        (<config>.dot.png).
    """

    cfg = Path(str(config_path))
    cfg_dir = cfg.parent
    return [cfg_dir / "diagram.png", Path(diagram_png_path_for_config(str(cfg)))]


def diagram_dot_candidate_paths_for_config(config_path: str) -> list[Path]:
    """Brief: Candidate locations to find a pre-generated config diagram dot source.

    Inputs:
      - config_path: YAML config path.

    Outputs:
      - list[Path]: Candidate dot source paths, in priority order.

    Notes:
      - Prefer a canonical file in the config directory (diagram.dot).
      - Fall back to the auto-generated sibling of the config file
        (<config>.dot).
    """

    cfg = Path(str(config_path))
    cfg_dir = cfg.parent
    return [cfg_dir / "diagram.dot", Path(diagram_dot_path_for_config(str(cfg)))]


def find_first_existing_path(paths: list[Path]) -> Path | None:
    """Brief: Return the first existing file path from a candidate list.

    Inputs:
      - paths: Candidate filesystem paths.

    Outputs:
      - Path | None: The first candidate that exists as a regular file.
    """

    for p in paths:
        try:
            if p.is_file():
                return p
        except Exception:
            continue
    return None


def stale_diagram_warning(*, config_path: str, diagram_path: str) -> str | None:
    """Brief: Build a warning when a diagram file is older than its config file.

    Inputs:
      - config_path: YAML config path.
      - diagram_path: Diagram artifact path (PNG or .dot).

    Outputs:
      - str | None: Warning text when stale, otherwise None.

    Example:
      - stale_diagram_warning(config_path='config.yaml', diagram_path='diagram.png')
    """

    try:
        cfg_mtime = float(os.stat(str(config_path)).st_mtime)
        dia_mtime = float(os.stat(str(diagram_path)).st_mtime)
    except Exception:
        return None

    if cfg_mtime <= dia_mtime:
        return None

    # Keep this short; it is commonly displayed directly in the web UI.
    return "Warning: diagram is older than config; it may be stale."


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


def _find_dot_cmd() -> str | None:
    """Brief: Locate the GraphViz dot binary.

    Inputs:
      - None.

    Outputs:
      - str | None: Path to dot, else None.
    """

    return shutil.which("dot")


def _render_png_with_dot(*, dot_text: str, output_png_path: str) -> tuple[bool, str]:
    """Brief: Render dot text to PNG using dot.

    Inputs:
      - dot_text: GraphViz dot text.
      - output_png_path: Destination path.

    Outputs:
      - (ok, detail)
    """

    dot_cmd = _find_dot_cmd()
    if not dot_cmd:
        return False, "dot not found"

    out_path = Path(output_png_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="foghorn-dot-") as td:
        in_path = Path(td) / "diagram.dot"
        in_path.write_text(dot_text, encoding="utf-8")

        cmd = [dot_cmd, "-Tpng", "-o", str(out_path), str(in_path)]
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as exc:
            return False, f"failed to run dot: {exc}"

        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            return False, f"dot failed: {err}" if err else "dot failed"

    return True, "ok"


def _render_png_with_dot_atomic(
    *, dot_text: str, output_png_path: str
) -> tuple[bool, str]:
    """Brief: Render via dot and atomically replace the destination file.

    Inputs:
      - dot_text: GraphViz dot text.
      - output_png_path: Final destination PNG path.

    Outputs:
      - (ok, detail)
    """

    tmp_path = f"{output_png_path}.new"

    ok, detail = _render_png_with_dot(dot_text=dot_text, output_png_path=tmp_path)
    if not ok:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass
        return False, detail

    try:
        os.replace(tmp_path, output_png_path)
    except Exception as exc:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass
        return False, f"failed to replace png: {exc}"

    return True, "ok"


def ensure_config_diagram_png(
    *,
    config_path: str,
    output_png_path: str | None = None,
    output_png_dark_path: str | None = None,
    output_dot_path: str | None = None,
    output_dot_dark_path: str | None = None,
    direction: str = _DEFAULT_DIRECTION,
    font_size_px: int = _DEFAULT_FONT_SIZE_PX,
    node_spacing: float = _DEFAULT_NODE_SPACING,
    rank_spacing: float = _DEFAULT_RANK_SPACING,
    include_init: bool = True,
) -> tuple[bool, str, str | None]:
    """Brief: Ensure a PNG config diagram exists and is up-to-date.

    Inputs:
      - config_path: YAML config path.
      - output_png_path: Optional explicit output path for PNG.
      - output_png_dark_path: Optional explicit output path for dark-theme PNG.
      - output_dot_path: Optional explicit output path for dot source.
      - output_dot_dark_path: Optional explicit output path for dark-theme dot source.
      - direction: GraphViz rankdir (TB or LR).
      - font_size_px: Font size in pixels.
      - node_spacing: GraphViz nodesep.
      - rank_spacing: GraphViz ranksep.
      - include_init: When True, include global dot attributes.

    Outputs:
      - (ok, detail, png_path)

    Behaviour:
      - If the PNG is missing or older than the config file, regenerate it.
      - If dot is unavailable, returns ok=False with a helpful detail.
    """

    cfg_path = str(config_path)
    if not cfg_path:
        return False, "config_path is empty", None

    cfg_dir = Path(cfg_path).resolve().parent

    if output_png_path is None:
        output_png_path = str(cfg_dir / "diagram.png")

    if output_png_dark_path is None:
        try:
            p = Path(str(output_png_path))
            output_png_dark_path = str(p.with_name(p.stem + "-dark" + p.suffix))
        except Exception:
            output_png_dark_path = str(cfg_dir / "diagram-dark.png")

    if output_dot_path is None:
        output_dot_path = str(cfg_dir / "diagram.dot")

    if output_dot_dark_path is None:
        try:
            p = Path(str(output_dot_path))
            output_dot_dark_path = str(p.with_name(p.stem + "-dark" + p.suffix))
        except Exception:
            output_dot_dark_path = str(cfg_dir / "diagram-dark.dot")

    if not os.path.isfile(cfg_path):
        return False, f"config not found: {cfg_path}", None

    # Consider the diagram stale not just when the config changes, but also
    # when the generator implementation or schema changes.
    stale_inputs: list[str] = [cfg_path]

    try:
        impl_path = str(Path(__file__).resolve())
        if os.path.isfile(impl_path):
            stale_inputs.append(impl_path)
    except Exception:
        pass

    try:
        schema_path = str(get_default_schema_path())
        if os.path.isfile(schema_path):
            stale_inputs.append(schema_path)
    except Exception:
        pass

    stale_light = any(_is_stale(p, output_png_path) for p in stale_inputs)
    stale_dark = any(_is_stale(p, str(output_png_dark_path)) for p in stale_inputs)

    if not stale_light and not stale_dark:
        return True, "up-to-date", output_png_path

    dot_text_light: str | None = None
    dot_text_dark: str | None = None

    if stale_light:
        try:
            dot_text_light = generate_dot_text_from_config_path(
                cfg_path,
                direction=direction,
                theme="light",
                font_size_px=font_size_px,
                node_spacing=node_spacing,
                rank_spacing=rank_spacing,
                include_init=include_init,
            )
        except Exception as exc:
            return False, f"failed to generate dot text: {exc}", None

        # Best-effort: also write the .dot next to the PNG for debugging.
        try:
            Path(output_dot_path).write_text(dot_text_light, encoding="utf-8")
        except Exception:
            pass

        ok_light, detail_light = _render_png_with_dot_atomic(
            dot_text=dot_text_light, output_png_path=output_png_path
        )
        if not ok_light:
            return False, detail_light, None

    if stale_dark:
        try:
            dot_text_dark = generate_dot_text_from_config_path(
                cfg_path,
                direction=direction,
                theme="dark",
                font_size_px=font_size_px,
                node_spacing=node_spacing,
                rank_spacing=rank_spacing,
                include_init=include_init,
            )
        except Exception as exc:
            return False, f"failed to generate dot text: {exc}", None

        # Best-effort: also write the .dot next to the PNG for debugging.
        try:
            Path(str(output_dot_dark_path)).write_text(dot_text_dark, encoding="utf-8")
        except Exception:
            pass

        ok_dark, detail_dark = _render_png_with_dot_atomic(
            dot_text=dot_text_dark, output_png_path=str(output_png_dark_path)
        )
        if not ok_dark:
            # If the light theme rendered successfully, treat this as best-effort.
            if not stale_light:
                return False, detail_dark, None
            return True, f"rendered light; dark failed: {detail_dark}", output_png_path

    return True, "rendered with dot", output_png_path
