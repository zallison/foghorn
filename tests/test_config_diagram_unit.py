"""Brief: Unit tests for foghorn.utils.config_diagram helpers.

Inputs:
  - tmp_path: pytest tmp_path fixture.
  - monkeypatch: pytest monkeypatch fixture.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

import foghorn.utils.config_diagram as cm


def test_safe_int_handles_none_valid_and_invalid() -> None:
    """Brief: _safe_int returns int when possible and None on failures.

    Inputs:
      - value: None, int-like string, and a non-int-like object.

    Outputs:
      - None; asserts correct conversions.
    """

    assert cm._safe_int(None) is None
    assert cm._safe_int("25") == 25
    assert cm._safe_int("bad") is None


def test_get_dict_descends_and_handles_non_mapping() -> None:
    """Brief: _get_dict returns nested dicts and {} for missing/invalid paths.

    Inputs:
      - Nested dict structure.
      - Non-dict intermediate and missing keys.

    Outputs:
      - None; asserts returned dicts.
    """

    assert cm._get_dict({"a": {"b": 1}}, "a") == {"b": 1}
    assert cm._get_dict({"a": 1}, "a") == {}
    assert cm._get_dict({"a": {"b": 2}}, "a", "b") == {}


def test_alias_helpers_normalize_and_default_alias() -> None:
    """Brief: Alias normalization matches runtime expectations.

    Inputs:
      - CamelCase class names, Plugin suffix, and hyphenated aliases.

    Outputs:
      - None; asserts conversions.
    """

    assert cm._camel_to_snake("MdnsBridge") == "mdns_bridge"
    assert cm._default_alias_for_class("DockerHostsPlugin") == "docker_hosts"
    assert cm._normalize_alias("  Foo-Bar  ") == "foo_bar"
    assert cm._normalize_alias("") == ""


def test_module_to_file_prefers_py_and_falls_back_to_init() -> None:
    """Brief: _module_to_file resolves .py modules and package __init__.py.

    Inputs:
      - A module path that maps to an existing .py file.
      - A module path that maps to a package directory.

    Outputs:
      - None; asserts returned Paths.
    """

    py = cm._module_to_file("foghorn.plugins.resolve.filter")
    assert py is not None
    assert py.name == "filter.py"

    pkg_init = cm._module_to_file("foghorn.plugins.resolve.zone_records")
    assert pkg_init is not None
    assert pkg_init.name == "__init__.py"

    assert cm._module_to_file("") is None


def test_scan_actions_filters_to_core_supported_actions() -> None:
    """Brief: _scan_actions_in_text extracts allow/deny/drop/override only.

    Inputs:
      - Text containing PluginDecision calls with supported and unsupported actions.

    Outputs:
      - None; asserts only allowed actions returned.
    """

    text = """
    return PluginDecision('deny')
    return PluginDecision(action='drop')
    return PluginDecision('override')
    return PluginDecision('not_supported')
    """
    assert cm._scan_actions_in_text(text) == {"deny", "drop", "override"}


def test_extract_class_text_requires_baseplugin() -> None:
    """Brief: _extract_class_text only returns classes inheriting from BasePlugin.

    Inputs:
      - Source text containing classes with and without BasePlugin in bases.

    Outputs:
      - None; asserts extraction behavior.
    """

    src = (
        "class NotAPlugin(object):\n    pass\n\n"
        "class IsAPlugin(BasePlugin):\n    def pre_resolve(self):\n        pass\n"
    )
    assert cm._extract_class_text(src, "NotAPlugin") == ""
    assert "class IsAPlugin" in cm._extract_class_text(src, "IsAPlugin")


def test_build_plugin_source_from_module_extracts_phases_actions_and_upstreams(
    tmp_path: Path,
) -> None:
    """Brief: _build_plugin_source_from_module derives metadata from source text.

    Inputs:
      - Temporary python file containing a BasePlugin subclass.

    Outputs:
      - None; asserts has_setup/actions/sets_upstreams.
    """

    p = tmp_path / "example_plugin.py"
    p.write_text(
        """
class Example(BasePlugin):
    def setup(self):
        pass

    def pre_resolve(self, qname, qtype, req, ctx):
        ctx.upstream_candidates = ['1.1.1.1']
        return PluginDecision('drop')

    def post_resolve(self, qname, qtype, req, resp, ctx):
        return PluginDecision(action='override')
""".lstrip(),
        encoding="utf-8",
    )

    src = cm._build_plugin_source_from_module(
        alias="example",
        module="foghorn.plugins.resolve.example_plugin",
        class_name="Example",
        file_path=p,
    )
    assert src is not None
    assert src.has_setup is True
    # Note: actions are scanned at the class level and then attributed based on
    # whether pre/post methods exist.
    assert "drop" in src.pre_actions
    assert "override" in src.pre_actions
    assert src.post_actions == src.pre_actions
    assert src.sets_upstreams is True


def test_build_plugin_source_from_module_returns_none_on_read_or_parse_failure(
    tmp_path: Path,
) -> None:
    """Brief: _build_plugin_source_from_module returns None on failures.

    Inputs:
      - Missing file path.
      - File that doesn't contain the requested plugin class.

    Outputs:
      - None; asserts None returned.
    """

    missing = tmp_path / "missing.py"
    assert (
        cm._build_plugin_source_from_module(
            alias="x", module="m", class_name="C", file_path=missing
        )
        is None
    )

    p = tmp_path / "no_class.py"
    p.write_text("class Other(BasePlugin):\n    pass\n", encoding="utf-8")
    assert (
        cm._build_plugin_source_from_module(
            alias="x", module="m", class_name="C", file_path=p
        )
        is None
    )


def test_build_plugin_source_index_from_schema_happy_path_and_filtering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: _build_plugin_source_index_from_schema uses schema registry and filters.

    Inputs:
      - Monkeypatched schema file with resolve and non-resolve entries.
      - Monkeypatched _module_to_file/_build_plugin_source_from_module.

    Outputs:
      - None; asserts alias mapping built only for resolve plugins.
    """

    schema_path = tmp_path / "schema.json"
    schema_path.write_text(
        '{"$defs": {"PluginConfigs": {'
        '"A": {"module": "foghorn.plugins.resolve.x.Foo", "aliases": ["foo", "foo"]},'
        '"B": {"module": "foghorn.plugins.other.y.Bar"}'
        "}}}",
        encoding="utf-8",
    )

    monkeypatch.setattr(cm, "get_default_schema_path", lambda: schema_path)

    def fake_module_to_file(_mod: str) -> Path:
        return tmp_path / "fake.py"

    def fake_build_plugin_source_from_module(
        *, alias: str, module: str, class_name: str, file_path: Path
    ):
        return cm.PluginSource(
            alias=alias,
            module=module,
            class_name=class_name,
            file_path=file_path,
            has_setup=False,
            pre_actions=set(),
            post_actions=set(),
            sets_upstreams=False,
        )

    monkeypatch.setattr(cm, "_module_to_file", fake_module_to_file)
    monkeypatch.setattr(
        cm, "_build_plugin_source_from_module", fake_build_plugin_source_from_module
    )

    idx = cm._build_plugin_source_index_from_schema()

    # From class Foo => default alias 'foo'. Duplicates should be ignored.
    assert "foo" in idx
    assert idx["foo"].class_name == "Foo"
    # Non-resolve plugins are filtered out.
    assert "bar" not in idx


def test_get_plugin_source_index_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _get_plugin_source_index caches the schema-derived mapping.

    Inputs:
      - Monkeypatched _build_plugin_source_index_from_schema.

    Outputs:
      - None; asserts builder called once.
    """

    calls = {"n": 0}

    def fake_build() -> dict[str, cm.PluginSource]:
        calls["n"] += 1
        return {
            "x": cm.PluginSource(
                alias="x",
                module="m",
                class_name="C",
                file_path=Path("x.py"),
            )
        }

    monkeypatch.setattr(cm, "_build_plugin_source_index_from_schema", fake_build)
    cm._PLUGIN_SOURCE_INDEX = None

    assert cm._get_plugin_source_index()["x"].class_name == "C"
    assert cm._get_plugin_source_index()["x"].class_name == "C"
    assert calls["n"] == 1


def test_lookup_plugin_source_handles_dotted_and_alias_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _lookup_plugin_source derives aliases from dotted module/class keys.

    Inputs:
      - Index containing a 'filter' alias.

    Outputs:
      - None; asserts lookup results.
    """

    src = cm.PluginSource(
        alias="filter", module="m", class_name="Filter", file_path=Path("x.py")
    )
    monkeypatch.setattr(cm, "_get_plugin_source_index", lambda: {"filter": src})

    assert cm._lookup_plugin_source("filter") is src
    assert cm._lookup_plugin_source("foghorn.plugins.resolve.filter.Filter") is src
    assert cm._lookup_plugin_source("") is None


def test_derive_display_name_prefers_id_then_name_then_type_module() -> None:
    """Brief: _derive_display_name chooses a display label from config entry.

    Inputs:
      - Dicts with various combinations of keys.

    Outputs:
      - None; asserts selected values.
    """

    assert cm._derive_display_name({"id": "x", "name": "y"}) == "x"
    assert cm._derive_display_name({"name": "y"}) == "y"
    assert cm._derive_display_name({"type": "t"}) == "t"
    assert cm._derive_display_name({"module": "m"}) == "m"
    assert cm._derive_display_name({}) == "plugin"


def test_extract_priorities_precedence_and_fallbacks() -> None:
    """Brief: _extract_priorities respects hook-specific, legacy, then generic priorities.

    Inputs:
      - Entry with hook priority present.
      - Entry with only legacy and generic priorities.

    Outputs:
      - None; asserts resulting (setup, pre, post) priorities.
    """

    entry_hooks = {
        "setup": {"priority": "1"},
        "hooks": {"pre_resolve": {"priority": "5"}},
        "priority": 50,
        "pre_priority": 20,
        "post_priority": 30,
    }
    setup_p, pre_p, post_p = cm._extract_priorities(entry_hooks)
    assert setup_p == 1
    assert pre_p == 5
    # post falls back: hook missing => legacy post_priority
    assert post_p == 30

    entry_legacy = {"priority": "7", "pre_priority": "9"}
    setup_p2, pre_p2, post_p2 = cm._extract_priorities(entry_legacy)
    assert pre_p2 == 9
    assert post_p2 == 7
    assert setup_p2 == 7


def test_constrain_filter_plugin_removes_drop_when_not_drop_and_disables_post_when_no_ip_rules() -> (
    None
):
    """Brief: _constrain_plugin_info_for_config adjusts Filter based on config.

    Inputs:
      - Filter PluginInfo with drop actions and post enabled.
      - Config without blocked_ips/blocked_ips_files.

    Outputs:
      - None; asserts drop removed and post phase disabled.
    """

    info = cm.PluginInfo(
        idx=0,
        name="Filter",
        type_key="filter",
        cls_path="foghorn.plugins.resolve.filter.Filter",
        setup_priority=None,
        pre_priority=10,
        post_priority=20,
        pre_actions={"drop", "deny"},
        post_actions={"drop", "override"},
        sets_upstreams=False,
    )

    out = cm._constrain_plugin_info_for_config(
        info, entry_config={"deny_response": "nxdomain"}
    )
    assert out.post_priority is None
    assert out.post_actions == set()
    assert "drop" not in out.pre_actions


def test_constrain_filter_plugin_keeps_post_when_ip_rules_present_and_drop_policy() -> (
    None
):
    """Brief: Filter post phase is retained when IP rules present.

    Inputs:
      - Filter PluginInfo with drop actions.
      - Config with deny_response=drop and blocked_ips populated.

    Outputs:
      - None; asserts post remains enabled and drop preserved.
    """

    info = cm.PluginInfo(
        idx=0,
        name="Filter",
        type_key="filter",
        cls_path="foghorn.plugins.resolve.filter.Filter",
        setup_priority=None,
        pre_priority=10,
        post_priority=20,
        pre_actions={"drop"},
        post_actions={"drop"},
        sets_upstreams=False,
    )

    out = cm._constrain_plugin_info_for_config(
        info,
        entry_config={"deny_response": "drop", "blocked_ips": ["1.2.3.4"]},
    )
    assert out.post_priority == 20
    assert "drop" in out.pre_actions
    assert "drop" in out.post_actions


def test_normalize_plugins_uses_source_metadata_and_setup_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: normalize_plugins populates PluginInfo using PluginSource and config priorities.

    Inputs:
      - Config dict with a single plugin entry.
      - Monkeypatched _lookup_plugin_source.

    Outputs:
      - None; asserts PluginInfo fields.
    """

    src = cm.PluginSource(
        alias="x",
        module="foghorn.plugins.resolve.x",
        class_name="X",
        file_path=Path("x.py"),
        has_setup=True,
        pre_actions={"deny"},
        post_actions={"override"},
        sets_upstreams=True,
    )
    monkeypatch.setattr(cm, "_lookup_plugin_source", lambda _k: src)

    cfg = {"plugins": [{"module": "x", "priority": 12, "config": None}]}
    plugins = cm.normalize_plugins(cfg)
    assert len(plugins) == 1
    p = plugins[0]
    assert p.type_key == "x"
    assert p.cls_path == "foghorn.plugins.resolve.x.X"
    assert p.pre_priority == 12
    assert p.post_priority == 12
    # setup_prio default derives from pre_priority when a setup plugin.
    assert p.setup_priority == 12
    assert p.sets_upstreams is True

    assert cm.normalize_plugins({"plugins": {}}) == []


def test_node_id_sanitizes_and_falls_back_to_plugin() -> None:
    """Brief: _node_id produces safe node identifiers.

    Inputs:
      - Names containing invalid characters.
      - Empty/fully-sanitized names.

    Outputs:
      - None; asserts formatting.
    """

    assert cm._node_id("pre", "Hello World", 1).startswith("pre_1_Hello_World")
    assert cm._node_id("pre", "!!!", 2) == "pre_2_plugin"


def test_extract_listener_lines_implies_enabled_for_present_listener_blocks() -> None:
    """Brief: extract_listener_lines treats present listener blocks as enabled by default.

    Inputs:
      - server.listen.dns with host/port defaults.
      - server.listen.tcp/dot/doh present without explicit enabled values.
      - server.listen.dot section using invalid port.

    Outputs:
      - None; asserts ordered listener lines include udp/tcp/dot/doh.
    """

    cfg = {
        "server": {
            "listen": {
                "dns": {"host": "127.0.0.1", "port": "bad"},
                "tcp": {},
                "dot": {"host": "0.0.0.0", "port": "bad"},
                "doh": {},
            }
        }
    }

    lines = cm.extract_listener_lines(cfg)
    assert lines[0].startswith("udp: 127.0.0.1:5335")
    assert lines[1].startswith("tcp: 127.0.0.1:5335")
    assert "dot: 0.0.0.0:853" in lines
    assert "doh: 127.0.0.1:1443" in lines


def test_extract_listener_lines_respects_explicit_enabled_false() -> None:
    """Brief: extract_listener_lines keeps explicit enabled=false listeners disabled.

    Inputs:
      - server.listen.dns defaults.
      - server.listen.tcp/dot/doh with enabled=false.

    Outputs:
      - None; asserts only udp remains enabled.
    """

    cfg = {
        "server": {
            "listen": {
                "dns": {"host": "127.0.0.1", "port": 5335},
                "tcp": {"enabled": False},
                "dot": {"enabled": False},
                "doh": {"enabled": False},
            }
        }
    }

    lines = cm.extract_listener_lines(cfg)
    assert lines == ["udp: 127.0.0.1:5335"]


def test_extract_upstream_lines_forward_only_and_endpoint_formats() -> None:
    """Brief: extract_upstream_lines returns endpoints only in forward mode.

    Inputs:
      - forward mode config with url and host/port endpoints.
      - non-forward mode.

    Outputs:
      - None; asserts rendered lines.
    """

    cfg = {
        "upstreams": {
            "strategy": "failover",
            "max_concurrent": "2",
            "endpoints": [
                {"transport": "udp", "host": "1.1.1.1", "port": 53},
                {"transport": "tcp", "url": " tls://example.com "},
                {"transport": "udp", "host": "9.9.9.9", "port": "bad"},
                {"transport": "udp", "host": "8.8.8.8"},
            ],
        }
    }

    lines = cm.extract_upstream_lines(cfg, resolver_mode="forward")
    assert lines[0] == "strategy=failover, max_concurrent=2"
    assert "udp: 1.1.1.1:53" in lines
    assert "tcp: tls://example.com" in lines
    assert "udp: 9.9.9.9" in lines
    assert "udp: 8.8.8.8" in lines

    assert cm.extract_upstream_lines(cfg, resolver_mode="recursive") == []


def test_extract_upstream_lines_includes_backup_endpoints() -> None:
    """Brief: extract_upstream_lines includes backup upstream endpoints.

    Inputs:
      - forward mode config with primary and backup endpoints.

    Outputs:
      - None; asserts backup endpoints are rendered with a backup suffix.
    """

    cfg = {
        "upstreams": {
            "strategy": "failover",
            "max_concurrent": 1,
            "endpoints": [{"transport": "udp", "host": "1.1.1.1", "port": 53}],
            "backup": {
                "endpoints": [
                    {"transport": "tcp", "host": "8.8.8.8", "port": 53},
                    {"transport": "doh", "url": "https://backup.example/dns-query"},
                ]
            },
        }
    }

    lines = cm.extract_upstream_lines(cfg, resolver_mode="forward")
    assert "udp: 1.1.1.1:53" in lines
    assert "tcp: 8.8.8.8:53 (backup)" in lines
    assert "doh: https://backup.example/dns-query (backup)" in lines


def test_render_dot_includes_expected_branches() -> None:
    """Brief: render_dot includes merge/drop/pre/post branches.

    Inputs:
      - Plugins with deny/override/drop phases.
      - forward resolver mode with listeners/upstreams.

    Outputs:
      - None; asserts key nodes and edges exist.
    """

    # Setup plugins are intentionally not shown in this diagram, but they should
    # also not break rendering.
    setup = cm.PluginInfo(
        idx=0,
        name="Setupper",
        type_key="x",
        cls_path="m.C",
        setup_priority=1,
        pre_priority=None,
        post_priority=None,
    )

    pre = cm.PluginInfo(
        idx=1,
        name="Pre",
        type_key="y",
        cls_path="m.C",
        setup_priority=None,
        pre_priority=10,
        post_priority=None,
        pre_actions={"deny", "override", "drop"},
        sets_upstreams=True,
    )

    post = cm.PluginInfo(
        idx=2,
        name="Post",
        type_key="z",
        cls_path="m.C",
        setup_priority=None,
        pre_priority=None,
        post_priority=10,
        post_actions={"deny"},
    )

    out = cm.render_dot(
        [setup, pre, post],
        config_path="cfg.yaml",
        resolver_mode="forward",
        listener_lines=["udp: 0.0.0.0:53"],
        upstream_lines=["strategy=failover, max_concurrent=1", "udp: 1.1.1.1:53"],
        direction="bad",
        include_init=False,
    )

    assert "digraph config_diagram" in out
    assert "rankdir=TB" in out
    assert "Drop (no reply)" in out
    assert "PreMerge" in out
    assert "PostMerge" in out
    assert "cluster_pre" in out
    assert "cluster_post" in out
    assert "routes upstream" in out
    assert "priority=10" in out
    assert "pre=10" not in out

    # Listener and upstream details should show up as separate nodes.
    assert "Listener_udp" in out
    assert "Listener_udp -> Q" in out
    assert "cluster_upstreams" in out
    assert "strategy=failover\\nmax_concurrent=1" in out
    assert "udp: 1.1.1.1:53" in out


def test_render_dot_renders_routed_upstreams_block_like_endpoints() -> None:
    """Brief: Routed upstreams are rendered as upstream endpoints in a dedicated block.

    Inputs:
      - A pre plugin that routes upstreams.
      - routed_upstream_lines representing upstream_router routes.

    Outputs:
      - None; asserts block name and endpoint-like lines are emitted.
    """

    p = cm.PluginInfo(
        idx=0,
        name="router",
        type_key="upstream_router",
        cls_path="foghorn.plugins.resolve.upstream_router.UpstreamRouter",
        pre_priority=100,
        routed_upstream_lines=[
            "route: domain=internal.example",
            "udp: 10.0.0.2:53",
            "udp: 10.0.0.3:53",
        ],
        sets_upstreams=True,
    )

    out = cm.render_dot(
        [p],
        config_path="cfg.yaml",
        resolver_mode="forward",
        listener_lines=[],
        upstream_lines=["strategy=failover, max_concurrent=1", "udp: 1.1.1.1:53"],
        include_init=False,
    )

    # Routed upstreams are rendered as additional nodes within the upstreams
    # cluster, linked from the routing plugin via a dashed edge.
    assert "cluster_upstreams" in out
    assert "RoutedUpstream_0_router" in out
    assert "Upstreams for\\nrouter" in out
    assert "route: domain=internal.example" in out
    assert "udp: 10.0.0.2:53" in out
    assert "pre_0_router -> RoutedUpstream_0_router" in out
    assert "style=dashed" in out


def test_render_dot_renders_two_upstream_boxes_when_transports_mixed() -> None:
    """Brief: Mixed secure/insecure upstreams are rendered as two separate boxes.

    Inputs:
      - forward resolver mode.
      - multiple upstream endpoint lines with mixed transports.

    Outputs:
      - None; asserts a secure and insecure upstream node are emitted.
    """

    out = cm.render_dot(
        [],
        config_path="cfg.yaml",
        resolver_mode="forward",
        listener_lines=[],
        upstream_lines=[
            "strategy=failover, max_concurrent=1",
            "udp: 1.1.1.1:53",
            "tcp: 9.9.9.9:53",
            "doh: https://dns.example/dns-query",
        ],
        include_init=False,
    )

    assert "cluster_upstreams" in out
    assert "UpstreamsInsecure" in out
    assert "UpstreamsSecure" in out
    assert "Upstream -> UpstreamsInsecure" in out
    assert "Upstream -> UpstreamsSecure" in out

    # Endpoints should still be present in the diagram output.
    assert "udp: 1.1.1.1:53" in out
    assert "tcp: 9.9.9.9:53" in out
    assert "doh: https://dns.example/dns-query" in out


def test_load_config_returns_empty_for_non_mapping_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: load_config returns {} when YAML root is not a mapping.

    Inputs:
      - YAML file containing a list.

    Outputs:
      - None; asserts validate_config not called and {} returned.
    """

    p = tmp_path / "cfg.yaml"
    p.write_text("- 1\n- 2\n", encoding="utf-8")

    monkeypatch.setattr(
        cm,
        "validate_config",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("called")),
    )
    assert cm.load_config(str(p)) == {}


def test_is_stale_handles_missing_and_mtime_comparison(tmp_path: Path) -> None:
    """Brief: _is_stale returns True when output missing or older than input.

    Inputs:
      - Temporary files with controlled mtimes.

    Outputs:
      - None; asserts staleness behaviour.
    """

    inp = tmp_path / "in"
    out = tmp_path / "out"
    inp.write_text("x", encoding="utf-8")

    assert cm._is_stale(str(inp), str(out)) is True

    out.write_text("y", encoding="utf-8")
    assert cm._is_stale(str(inp), str(out)) is False

    # Bump input mtime to be newer (avoid filesystem timestamp resolution issues).
    import os
    import time

    t = time.time()
    os.utime(out, (t, t))
    os.utime(inp, (t + 10, t + 10))
    assert cm._is_stale(str(inp), str(out)) is True


def test_diagram_candidate_paths_prefer_config_dir_over_sibling(tmp_path: Path) -> None:
    """Brief: diagram_*_candidate_paths prefer config/diagram.* over <cfg>.dot.*.

    Inputs:
      - tmp_path with cfg.yaml and multiple diagram candidates.

    Outputs:
      - None; asserts lookup order and helper selection.
    """

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("plugins: []\n", encoding="utf-8")

    cfg_dir_png = tmp_path / "diagram.png"
    cfg_dir_png.write_bytes(b"PNG")
    sibling_png = tmp_path / "cfg.yaml.dot.png"
    sibling_png.write_bytes(b"PNG2")

    png_candidates = cm.diagram_png_candidate_paths_for_config(str(cfg))
    assert png_candidates[0] == cfg_dir_png
    assert png_candidates[1] == sibling_png
    assert cm.find_first_existing_path(png_candidates) == cfg_dir_png

    cfg_dir_dot = tmp_path / "diagram.dot"
    cfg_dir_dot.write_text("digraph config_diagram {}\n", encoding="utf-8")
    sibling_dot = tmp_path / "cfg.yaml.dot"
    sibling_dot.write_text("digraph other {}\n", encoding="utf-8")

    dot_candidates = cm.diagram_dot_candidate_paths_for_config(str(cfg))
    assert dot_candidates[0] == cfg_dir_dot
    assert dot_candidates[1] == sibling_dot
    assert cm.find_first_existing_path(dot_candidates) == cfg_dir_dot


def test_stale_diagram_warning_when_config_newer(tmp_path: Path) -> None:
    """Brief: stale_diagram_warning is set when config mtime is newer than diagram.

    Inputs:
      - tmp_path config and diagram files with controlled mtimes.

    Outputs:
      - None; asserts warning returned when stale.
    """

    cfg = tmp_path / "cfg.yaml"
    dia = tmp_path / "diagram.png"
    cfg.write_text("x: 1\n", encoding="utf-8")
    dia.write_bytes(b"PNG")

    import os
    import time

    t = time.time()
    os.utime(dia, (t, t))
    os.utime(cfg, (t + 10, t + 10))

    warn = cm.stale_diagram_warning(config_path=str(cfg), diagram_path=str(dia))
    assert warn is not None
    assert "stale" in warn.lower()

    # If the diagram is newer (or equal), no warning.
    os.utime(dia, (t + 20, t + 20))
    warn2 = cm.stale_diagram_warning(config_path=str(cfg), diagram_path=str(dia))
    assert warn2 is None


def test_render_png_with_dot_failure_messages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Brief: _render_png_with_dot returns helpful detail on failures.

    Inputs:
      - dot present.
      - subprocess.run returns non-zero and then raises.

    Outputs:
      - None; asserts error detail formatting.
    """

    monkeypatch.setattr(cm.shutil, "which", lambda _n: "/usr/bin/dot")

    def fake_run_bad(*_a, **_k):  # type: ignore[no-untyped-def]
        return types.SimpleNamespace(returncode=1, stderr="bad", stdout="")

    monkeypatch.setattr(cm.subprocess, "run", fake_run_bad)
    ok, detail = cm._render_png_with_dot(
        dot_text="digraph config_diagram {}\n", output_png_path=str(tmp_path / "o.png")
    )
    assert ok is False
    assert "dot failed" in detail

    def fake_run_raises(*_a, **_k):  # type: ignore[no-untyped-def]
        raise OSError("boom")

    monkeypatch.setattr(cm.subprocess, "run", fake_run_raises)
    ok2, detail2 = cm._render_png_with_dot(
        dot_text="digraph config_diagram {}\n", output_png_path=str(tmp_path / "o2.png")
    )
    assert ok2 is False
    assert "failed to run dot" in detail2


def test_ensure_config_diagram_png_edge_cases_when_dot_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png handles empty/missing configs and missing dot.

    Inputs:
      - Empty config_path.
      - Missing config file.
      - Config file with dot missing.

    Outputs:
      - None; asserts expected (ok, detail, path).
    """

    ok0, detail0, path0 = cm.ensure_config_diagram_png(config_path="")
    assert ok0 is False
    assert path0 is None
    assert "empty" in detail0

    ok1, detail1, path1 = cm.ensure_config_diagram_png(
        config_path=str(tmp_path / "nope.yaml")
    )
    assert ok1 is False
    assert path1 is None
    assert "not found" in detail1

    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text("plugins: []\n", encoding="utf-8")

    monkeypatch.setattr(
        cm,
        "generate_dot_text_from_config_path",
        lambda _p, **_k: "digraph config_diagram {}\n",
    )
    monkeypatch.setattr(cm.shutil, "which", lambda _n: None)

    # Force .dot write failure (best-effort) by making output path a directory.
    dot_dir = tmp_path / "as_dir"
    dot_dir.mkdir()

    ok2, detail2, path2 = cm.ensure_config_diagram_png(
        config_path=str(cfg_path),
        output_dot_path=str(dot_dir),
    )
    assert ok2 is False
    assert path2 is None
    assert "dot" in detail2.lower()


def test_ensure_config_diagram_png_reports_generate_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png returns ok=False when dot text generation fails.

    Inputs:
      - Config file exists.
      - generate_dot_text_from_config_path raises.

    Outputs:
      - None; asserts error message surfaced.
    """

    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text("plugins: []\n", encoding="utf-8")

    monkeypatch.setattr(
        cm,
        "generate_dot_text_from_config_path",
        lambda _p, **_k: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    ok, detail, png_path = cm.ensure_config_diagram_png(config_path=str(cfg_path))
    assert ok is False
    assert png_path is None
    assert "failed to generate dot text" in detail


def test_module_to_file_returns_none_when_unresolvable() -> None:
    """Brief: _module_to_file returns None for non-existent modules.

    Inputs:
      - Module path that does not exist in this source tree.

    Outputs:
      - None; asserts None returned.
    """

    assert cm._module_to_file("foghorn.plugins.resolve._definitely_missing_123") is None


def test_extract_method_block_empty_when_missing() -> None:
    """Brief: _extract_method_block returns '' when the method doesn't exist.

    Inputs:
      - Class text without the requested method.
      - Class text with the requested method.

    Outputs:
      - None; asserts extracted block behaviour.
    """

    class_text = "class X(BasePlugin):\n    def a(self):\n        return 1\n"
    assert cm._extract_method_block(class_text, "missing") == ""

    class_text2 = (
        "class X(BasePlugin):\n"
        "    def pre_resolve(self):\n"
        "        return PluginDecision('deny')\n"
        "\n"
        "    def post_resolve(self):\n"
        "        return None\n"
    )
    assert "def pre_resolve" in cm._extract_method_block(class_text2, "pre_resolve")


def test_scan_sets_upstreams_in_text_true_and_false() -> None:
    """Brief: _scan_sets_upstreams_in_text detects ctx upstream override fields.

    Inputs:
      - Text without upstream references.
      - Text with upstream references.

    Outputs:
      - None; asserts detection.
    """

    assert cm._scan_sets_upstreams_in_text("return None") is False
    assert cm._scan_sets_upstreams_in_text("ctx.upstream_candidates = []") is True


def test_constrain_plugin_info_for_config_non_filter_is_noop() -> None:
    """Brief: _constrain_plugin_info_for_config leaves non-Filter plugins unchanged.

    Inputs:
      - PluginInfo with a non-Filter cls_path.

    Outputs:
      - None; asserts the info is unchanged.
    """

    info = cm.PluginInfo(
        idx=0,
        name="X",
        type_key="x",
        cls_path="other.Mod",
        pre_priority=10,
        post_priority=20,
        pre_actions={"deny"},
        post_actions={"override"},
    )
    assert cm._constrain_plugin_info_for_config(info, entry_config={}) == info


def test_normalize_plugins_skips_invalid_entries_and_handles_missing_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: normalize_plugins ignores invalid plugin entries and works without PluginSource.

    Inputs:
      - plugins list containing non-dicts, missing module/type, and unknown type.

    Outputs:
      - None; asserts only the valid unknown-type entry is included.
    """

    monkeypatch.setattr(cm, "_lookup_plugin_source", lambda _k: None)

    cfg = {
        "plugins": [
            "not-a-dict",
            {},
            {"module": "unknown", "priority": 1},
        ]
    }

    plugins = cm.normalize_plugins(cfg)
    assert len(plugins) == 1
    p = plugins[0]
    assert p.cls_path == "unknown"
    assert p.pre_actions == set()
    assert p.post_actions == set()


def test_load_config_calls_validate_config_for_mapping_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: load_config validates mapping roots with validate_config().

    Inputs:
      - YAML file containing a mapping.

    Outputs:
      - None; asserts validate_config invoked.
    """

    p = tmp_path / "cfg.yaml"
    p.write_text("plugins: []\n", encoding="utf-8")

    called: dict[str, object] = {}

    def fake_validate(obj, *, config_path=None, unknown_keys=None):  # type: ignore[no-untyped-def]
        called["obj"] = obj
        called["config_path"] = config_path
        called["unknown_keys"] = unknown_keys

    monkeypatch.setattr(cm, "validate_config", fake_validate)

    out = cm.load_config(str(p))
    assert out == {"plugins": []}
    assert called["config_path"] == str(p)
    assert called["unknown_keys"] == "ignore"


def test_render_dot_recursive_and_master_modes_include_init_and_no_drop() -> None:
    """Brief: render_dot handles recursive/master modes and init blocks.

    Inputs:
      - Empty plugin list.
      - recursive and none/master resolver modes.

    Outputs:
      - None; asserts mode-specific labels and init handling.
    """

    rec = cm.render_dot(
        [],
        config_path="cfg.yaml",
        resolver_mode="recursive",
        listener_lines=[],
        upstream_lines=[],
        direction="LR",
        include_init=True,
    )
    assert "digraph config_diagram" in rec
    assert "rankdir=LR" in rec
    assert "Recursive resolver" in rec
    assert "node [shape=box" in rec
    assert "Drop (no reply)" not in rec

    mas = cm.render_dot(
        [],
        config_path="cfg.yaml",
        resolver_mode="none",
        listener_lines=[],
        upstream_lines=[],
        include_init=True,
    )
    assert "Master mode: no forwarding" in mas
    assert "(REFUSED)" in mas


def test_generate_dot_text_from_config_path_wires_through_components(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: generate_dot_text_from_config_path passes derived values into render_dot.

    Inputs:
      - Monkeypatched load_config/normalize/extract/render to capture arguments.

    Outputs:
      - None; asserts resolver_mode/listener_lines/upstream_lines flow through.
    """

    monkeypatch.setattr(
        cm, "load_config", lambda _p: {"server": {"resolver": {"mode": "forward"}}}
    )
    monkeypatch.setattr(cm, "normalize_plugins", lambda _cfg: [])
    monkeypatch.setattr(cm, "extract_listener_lines", lambda _cfg: ["udp: 0.0.0.0:53"])
    monkeypatch.setattr(
        cm,
        "extract_upstream_lines",
        lambda _cfg, resolver_mode=None: ["strategy=failover, max_concurrent=1"],
    )

    captured: dict[str, object] = {}

    def fake_render_dot(plugins, *, config_path, resolver_mode, listener_lines, upstream_lines, **_k):  # type: ignore[no-untyped-def]
        captured["plugins"] = plugins
        captured["config_path"] = config_path
        captured["resolver_mode"] = resolver_mode
        captured["listener_lines"] = listener_lines
        captured["upstream_lines"] = upstream_lines
        return "ok"

    monkeypatch.setattr(cm, "render_dot", fake_render_dot)

    out = cm.generate_dot_text_from_config_path("cfg.yaml", include_init=False)
    assert out == "ok"
    assert captured["resolver_mode"] == "forward"
    assert captured["listener_lines"] == ["udp: 0.0.0.0:53"]
    assert captured["upstream_lines"] == ["strategy=failover, max_concurrent=1"]


def test_extract_listener_lines_returns_empty_on_non_mapping_shapes() -> None:
    """Brief: extract_listener_lines defensively returns [] on invalid config shapes.

    Inputs:
      - cfg['server'] not a dict.
      - cfg['server']['listen'] not a dict.

    Outputs:
      - None; asserts empty list.
    """

    assert cm.extract_listener_lines({"server": []}) == []
    assert cm.extract_listener_lines({"server": {"listen": []}}) == []


def test_extract_upstream_lines_returns_empty_on_non_forward_or_bad_shapes() -> None:
    """Brief: extract_upstream_lines returns [] outside forward mode or invalid shapes.

    Inputs:
      - resolver_mode not forward.
      - cfg['upstreams'] not a dict.
      - cfg['upstreams']['endpoints'] not a list.

    Outputs:
      - None; asserts empty list.
    """

    assert cm.extract_upstream_lines({"upstreams": {}}, resolver_mode="none") == []
    assert cm.extract_upstream_lines({"upstreams": 1}, resolver_mode="forward") == []
    assert (
        cm.extract_upstream_lines(
            {"upstreams": {"endpoints": {"a": 1}}}, resolver_mode="forward"
        )
        == []
    )


def test_is_stale_returns_true_when_input_missing(tmp_path: Path) -> None:
    """Brief: _is_stale returns True if input_path stat fails.

    Inputs:
      - Missing input file and present output file.

    Outputs:
      - None; asserts staleness True.
    """

    out = tmp_path / "out"
    out.write_text("x", encoding="utf-8")
    assert cm._is_stale(str(tmp_path / "missing"), str(out)) is True


def test_get_dict_returns_empty_for_non_mapping_root() -> None:
    """Brief: _get_dict returns {} when root is not a mapping.

    Inputs:
      - Non-dict root value.

    Outputs:
      - None; asserts empty dict.
    """

    assert cm._get_dict([], "a") == {}


def test_extract_priorities_accepts_scalar_hook_values() -> None:
    """Brief: _extract_priorities supports scalar hook values.

    Inputs:
      - hooks.setup, hooks.pre_resolve, hooks.post_resolve as scalar values.

    Outputs:
      - None; asserts parsed setup/pre/post priorities.
    """

    setup_p, pre_p, post_p = cm._extract_priorities(
        {"hooks": {"setup": "41", "pre_resolve": "42", "post_resolve": "43"}}
    )
    assert setup_p == 41
    assert pre_p == 42
    assert post_p == 43


def test_build_plugin_source_index_from_schema_handles_malformed_top_levels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: _build_plugin_source_index_from_schema returns {} for malformed schema shapes.

    Inputs:
      - Schema payloads missing/invalid $defs.PluginConfigs structure.

    Outputs:
      - None; asserts empty index for each malformed payload.
    """

    schema_path = tmp_path / "schema.json"
    monkeypatch.setattr(cm, "get_default_schema_path", lambda: schema_path)

    for payload in (
        "{}",
        '{"$defs": []}',
        '{"$defs": {"PluginConfigs": []}}',
    ):
        schema_path.write_text(payload, encoding="utf-8")
        assert cm._build_plugin_source_index_from_schema() == {}


def test_build_plugin_source_index_from_schema_exercises_skip_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: _build_plugin_source_index_from_schema filters invalid plugin entries.

    Inputs:
      - Schema with non-dict entries, invalid modules, non-resolve modules,
        missing files, aliases edge-cases, and source-builder None results.

    Outputs:
      - None; asserts only valid aliases are indexed.
    """

    schema_path = tmp_path / "schema.json"
    schema_path.write_text(
        json.dumps(
            {
                "$defs": {
                    "PluginConfigs": {
                        "not_dict": [],
                        "bad_module_type": {"module": 123},
                        "blank_module": {"module": "   "},
                        "non_resolve": {"module": "other.plugins.x.Plugin"},
                        "no_class_name": {"module": "foghorn.plugins.resolve."},
                        "missing_file": {
                            "module": "foghorn.plugins.resolve.nofile.NoFile"
                        },
                        "none_source": {
                            "module": "foghorn.plugins.resolve.none_source.NoneSource",
                            "aliases": ["none-source"],
                        },
                        "good": {
                            "module": "foghorn.plugins.resolve.good.GoodPlugin",
                            "aliases": ["", "good-plugin", "good_plugin"],
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(cm, "get_default_schema_path", lambda: schema_path)

    def fake_module_to_file(module: str) -> Path | None:
        if module.endswith("nofile"):
            return None
        return tmp_path / "fake.py"

    def fake_builder(
        *, alias: str, module: str, class_name: str, file_path: Path
    ) -> cm.PluginSource | None:
        if alias == "none_source":
            return None
        return cm.PluginSource(
            alias=alias,
            module=module,
            class_name=class_name,
            file_path=file_path,
        )

    monkeypatch.setattr(cm, "_module_to_file", fake_module_to_file)
    monkeypatch.setattr(cm, "_build_plugin_source_from_module", fake_builder)

    idx = cm._build_plugin_source_index_from_schema()
    assert "good" in idx
    assert "good_plugin" in idx
    assert "none_source" not in idx
    assert "missing_file" not in idx


def test_extract_upstream_router_route_lines_covers_edge_cases() -> None:
    """Brief: _extract_upstream_router_route_lines handles route/upstream edge-cases.

    Inputs:
      - Routes containing non-dicts, empty matchers, per-route/shared/legacy upstreams,
        template hosts, URL transport inference, and invalid ports.

    Outputs:
      - None; asserts expected route and endpoint lines.
    """

    cfg = {
        "routes": [
            "skip",
            {},
            {"domain": " ", "suffix": " "},
            {
                "domain": "example.com",
                "upstreams": [
                    "bad-entry",
                    {"url": "https://dns.example/query"},
                    {"url": "tls://dot.example"},
                    {"url": "tcp://tcp.example"},
                    {"url": "ftp://fallback.example"},
                    {"host": "${UPSTREAM_HOST}", "transport": "tcp", "port": "853"},
                    {"host": "${UPSTREAM_HOST}", "transport": "udp", "port": "bad"},
                    {"host": "9.9.9.9", "port": None},
                    {"host": "8.8.8.8", "port": "bad"},
                    {"host": "1.1.1.1", "transport": "dot", "port": "53"},
                    {"host": "   "},
                ],
            },
            {
                "suffix": "internal.example",
                "upstream": {"transport": "udp", "host": "10.0.0.1", "port": 5300},
            },
            {"domain": "shared.example", "upstreams": []},
        ],
        "upstreams": [{"url": "https://shared.example/dns-query"}],
    }

    lines = cm._extract_upstream_router_route_lines(cfg)
    assert "route: domain=example.com" in lines
    assert "doh: https://dns.example/query" in lines
    assert "dot: tls://dot.example" in lines
    assert "tcp: tcp://tcp.example" in lines
    assert "udp: ftp://fallback.example" in lines
    assert "tcp: {host}:853" in lines
    assert "udp: {host}:bad" in lines
    assert "udp: 9.9.9.9" in lines
    assert "udp: 8.8.8.8" in lines
    assert "dot: 1.1.1.1:53" in lines
    assert "route: suffix=internal.example" in lines
    assert "udp: 10.0.0.1:5300" in lines
    assert "route: domain=shared.example (shared upstreams)" in lines
    assert "doh: https://shared.example/dns-query" in lines

    none_lines = cm._extract_upstream_router_route_lines(
        {"routes": [{"domain": "none.example"}], "upstreams": {}}
    )
    assert "upstreams: (none)" in none_lines


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("nxdomain", "NXDOMAIN"),
        ("refused", "REFUSED"),
        ("servfail", "SERVFAIL"),
        ("noerror_empty", "NOERROR (empty)"),
        ("nodata", "NOERROR (empty)"),
        ("ip", "IP"),
        ("drop", None),
        ("unknown", None),
    ],
)
def test_deny_response_to_rcode_label_modes(mode: str, expected: str | None) -> None:
    """Brief: _deny_response_to_rcode_label maps known modes and falls back to None.

    Inputs:
      - deny_response mode strings.

    Outputs:
      - None; asserts mapped labels.
    """

    assert cm._deny_response_to_rcode_label(mode) == expected


def test_constrain_plugin_info_for_config_access_control_ip_path() -> None:
    """Brief: _constrain_plugin_info_for_config applies IP-mode deny labels.

    Inputs:
      - AccessControl PluginInfo with pre/post actions including drop/override.
      - Config with deny_response=ip and post-phase IP rule sources.

    Outputs:
      - None; asserts deny labels and normalized pre/post actions.
    """

    info = cm.PluginInfo(
        idx=0,
        name="access",
        type_key="access_control",
        cls_path="foghorn.plugins.resolve.access_control.AccessControl",
        pre_priority=10,
        post_priority=20,
        pre_actions={"drop", "override"},
        post_actions={"drop", "override"},
    )

    out = cm._constrain_plugin_info_for_config(
        info,
        entry_config={"deny_response": "ip", "blocked_ips_files": ["ips.txt"]},
    )
    assert out.pre_deny_rcode == "IP"
    assert out.post_deny_rcode == "IP"
    assert "deny" in out.pre_actions
    assert "deny" in out.post_actions
    assert "drop" not in out.pre_actions
    assert "drop" not in out.post_actions
    assert out.post_priority == 20


def test_normalize_plugins_sets_default_hook_priorities_and_router_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: normalize_plugins sets runtime default priorities and routed metadata.

    Inputs:
      - UpstreamRouter source with pre_resolve but no explicit pre_priority.
      - Setup-only source with no explicit setup priority.

    Outputs:
      - None; asserts default priorities and routed_upstream_lines population.
    """

    router_src = cm.PluginSource(
        alias="upstream_router",
        module="foghorn.plugins.resolve.upstream_router",
        class_name="UpstreamRouter",
        file_path=Path("router.py"),
        has_setup=False,
        has_pre_resolve=True,
        has_post_resolve=False,
        pre_actions={"allow"},
        post_actions=set(),
        sets_upstreams=True,
    )
    setup_src = cm.PluginSource(
        alias="setup_only",
        module="foghorn.plugins.resolve.setup_only",
        class_name="SetupOnly",
        file_path=Path("setup.py"),
        has_setup=True,
        has_pre_resolve=False,
        has_post_resolve=False,
    )

    def fake_lookup(type_key: str) -> cm.PluginSource | None:
        if type_key == "upstream_router":
            return router_src
        if type_key == "setup_only":
            return setup_src
        return None

    monkeypatch.setattr(cm, "_lookup_plugin_source", fake_lookup)

    plugins = cm.normalize_plugins(
        {
            "plugins": [
                {
                    "type": "upstream_router",
                    "config": {
                        "routes": [
                            {
                                "domain": "internal.example",
                                "upstreams": [{"host": "10.0.0.2", "port": 53}],
                            }
                        ]
                    },
                },
                {"type": "setup_only", "config": {}},
            ]
        }
    )

    router = plugins[0]
    setup = plugins[1]
    assert router.pre_priority == 100
    assert router.post_priority is None
    assert "route: domain=internal.example" in router.routed_upstream_lines
    assert setup.setup_priority == 100
    assert setup.pre_priority is None
    assert setup.post_priority is None


def test_extract_listener_lines_defaults_when_sections_missing() -> None:
    """Brief: extract_listener_lines uses default enabled/ports when sections are absent.

    Inputs:
      - listen.dns provided, tcp/dot/doh sections omitted.

    Outputs:
      - None; asserts only udp default listener remains.
    """

    cfg = {"server": {"listen": {"dns": {"host": "0.0.0.0", "port": 5300}}}}
    assert cm.extract_listener_lines(cfg) == ["udp: 0.0.0.0:5300"]


def test_extract_upstream_lines_handles_backup_shape_and_invalid_endpoints() -> None:
    """Brief: extract_upstream_lines ignores invalid endpoint entries safely.

    Inputs:
      - endpoints list with non-dict and invalid host records.
      - backup section with non-dict shape.

    Outputs:
      - None; asserts strategy line plus valid endpoint lines only.
    """

    lines = cm.extract_upstream_lines(
        {
            "upstreams": {
                "endpoints": [
                    "bad",
                    {"host": None},
                    {"host": "  "},
                    {"host": "1.1.1.1"},
                ],
                "backup": [],
            }
        },
        resolver_mode="forward",
    )
    assert lines[0] == "strategy=failover, max_concurrent=1"
    assert "udp: 1.1.1.1" in lines


def test_render_dot_dark_theme_covers_listener_and_unknown_upstream_paths() -> None:
    """Brief: render_dot handles dark theme, odd listener labels, and unknown endpoints.

    Inputs:
      - dark theme with include_init.
      - listener lines with empty and non-protocol values.
      - upstream lines that cannot derive secure/insecure protocol.

    Outputs:
      - None; asserts fallback styling and node rendering.
    """

    out = cm.render_dot(
        [],
        config_path="cfg.yaml",
        resolver_mode="forward",
        listener_lines=["", "custom_listener", "dot: 0.0.0.0:853"],
        upstream_lines=["strategy=failover, max_concurrent=1", ":"],
        theme="dark",
        include_init=True,
    )

    assert 'graph [bgcolor="#0b1020"' in out
    assert "Listener_unknown" in out
    assert "Listener_dot" in out
    assert "Upstreams (insecure)" in out
    assert "UpstreamsSecure" not in out


def test_render_dot_routed_upstream_security_variants() -> None:
    """Brief: render_dot applies routed-upstream coloring for mixed/secure/empty routes.

    Inputs:
      - Three routed pre plugins with mixed, secure-only, and metadata-only route lines.

    Outputs:
      - None; asserts routed nodes and dashed upstream links are emitted.
    """

    mixed = cm.PluginInfo(
        idx=0,
        name="mixed",
        type_key="upstream_router",
        cls_path="foghorn.plugins.resolve.upstream_router.UpstreamRouter",
        pre_priority=1,
        routed_upstream_lines=["dot: tls://secure", "udp: 10.0.0.1:53"],
    )
    secure = cm.PluginInfo(
        idx=1,
        name="secure",
        type_key="upstream_router",
        cls_path="foghorn.plugins.resolve.upstream_router.UpstreamRouter",
        pre_priority=2,
        routed_upstream_lines=["doh: https://secure.example/dns-query"],
    )
    none = cm.PluginInfo(
        idx=2,
        name="none",
        type_key="upstream_router",
        cls_path="foghorn.plugins.resolve.upstream_router.UpstreamRouter",
        pre_priority=3,
        routed_upstream_lines=["route: domain=internal.example"],
    )

    out = cm.render_dot(
        [mixed, secure, none],
        config_path="cfg.yaml",
        resolver_mode="forward",
        listener_lines=[],
        upstream_lines=["udp: 1.1.1.1:53"],
        include_init=True,
    )

    assert "RoutedUpstream_0_mixed" in out
    assert "RoutedUpstream_1_secure" in out
    assert "RoutedUpstream_2_none" in out
    assert "Upstream -> RoutedUpstream_0_mixed [style=dashed, splines=4];" in out
    assert "pre_0_mixed -> RoutedUpstream_0_mixed [style=dashed" in out
    assert "pre_1_secure -> Cache [style=solid, constraint=false];" in out


def test_generate_dot_text_from_config_path_handles_non_mapping_server_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: generate_dot_text_from_config_path defaults resolver_mode when shapes are invalid.

    Inputs:
      - load_config returning non-mapping server/resolver structures.

    Outputs:
      - None; asserts resolver_mode forwarded to render_dot as forward.
    """

    monkeypatch.setattr(cm, "load_config", lambda _p: {"server": []})
    monkeypatch.setattr(cm, "normalize_plugins", lambda _cfg: [])
    monkeypatch.setattr(cm, "extract_listener_lines", lambda _cfg: [])
    monkeypatch.setattr(
        cm, "extract_upstream_lines", lambda _cfg, resolver_mode=None: []
    )

    captured: dict[str, object] = {}

    def fake_render_dot(plugins, **kwargs):  # type: ignore[no-untyped-def]
        captured["plugins"] = plugins
        captured["resolver_mode"] = kwargs["resolver_mode"]
        return "ok"

    monkeypatch.setattr(cm, "render_dot", fake_render_dot)
    out = cm.generate_dot_text_from_config_path("cfg.yaml")
    assert out == "ok"
    assert captured["resolver_mode"] == "forward"


def test_diagram_dark_helpers_and_candidate_path_order(tmp_path: Path) -> None:
    """Brief: Dark helper path builders and candidate ordering are stable.

    Inputs:
      - Config path in a temp directory.

    Outputs:
      - None; asserts helper outputs and candidate order.
    """

    cfg = tmp_path / "config.yaml"
    cfg.write_text("plugins: []\n", encoding="utf-8")
    assert cm.diagram_dark_png_path_for_config(str(cfg)).endswith(".dot-dark.png")
    assert cm.diagram_png_path_for_config(str(cfg)).endswith(".dot.png")
    assert cm.diagram_dot_path_for_config(str(cfg)).endswith(".dot")

    cands = cm.diagram_dark_png_candidate_paths_for_config(str(cfg))
    assert cands[0] == tmp_path / "diagram-dark.png"
    assert cands[1] == tmp_path / "config.yaml.dot-dark.png"


def test_find_first_existing_path_ignores_exceptions(tmp_path: Path) -> None:
    """Brief: find_first_existing_path skips entries whose is_file() raises.

    Inputs:
      - First candidate with failing is_file().
      - Second candidate existing file path.

    Outputs:
      - None; asserts second candidate is returned.
    """

    class _BadPath:
        def is_file(self) -> bool:
            raise OSError("boom")

    good = tmp_path / "good.png"
    good.write_bytes(b"x")
    result = cm.find_first_existing_path([_BadPath(), good])  # type: ignore[list-item]
    assert result == good


def test_stale_diagram_warning_returns_none_when_stats_fail() -> None:
    """Brief: stale_diagram_warning returns None when stat calls fail.

    Inputs:
      - Non-existent config/diagram paths.

    Outputs:
      - None; asserts None returned.
    """

    assert (
        cm.stale_diagram_warning(
            config_path="missing-config.yaml", diagram_path="missing-diagram.png"
        )
        is None
    )


def test_is_stale_returns_true_when_output_stat_raises_non_file_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _is_stale returns True when output stat raises non-FileNotFound errors.

    Inputs:
      - Monkeypatched os.stat that raises PermissionError for output path.

    Outputs:
      - None; asserts True returned.
    """

    def fake_stat(path: str):  # type: ignore[no-untyped-def]
        if path == "out.png":
            raise PermissionError("denied")
        raise AssertionError("input stat should not be reached")

    monkeypatch.setattr(cm.os, "stat", fake_stat)
    assert cm._is_stale("in.yaml", "out.png") is True


def test_render_png_with_dot_atomic_cleans_temp_file_on_render_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: _render_png_with_dot_atomic removes temp files when render fails.

    Inputs:
      - Monkeypatched _render_png_with_dot that creates a temp file then fails.

    Outputs:
      - None; asserts failure detail and temp cleanup.
    """

    out_png = tmp_path / "diagram.png"
    tmp_png = Path(f"{out_png}.new")

    def fake_render(*, dot_text: str, output_png_path: str):  # type: ignore[no-untyped-def]
        Path(output_png_path).write_bytes(b"tmp")
        return False, "render failed"

    monkeypatch.setattr(cm, "_render_png_with_dot", fake_render)
    ok, detail = cm._render_png_with_dot_atomic(
        dot_text="digraph config_diagram {}\n", output_png_path=str(out_png)
    )
    assert ok is False
    assert "render failed" in detail
    assert not tmp_png.exists()


def test_render_png_with_dot_atomic_cleans_temp_file_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: _render_png_with_dot_atomic removes temp file when atomic replace fails.

    Inputs:
      - Monkeypatched _render_png_with_dot success and os.replace failure.

    Outputs:
      - None; asserts failure detail and temp cleanup.
    """

    out_png = tmp_path / "diagram.png"
    tmp_png = Path(f"{out_png}.new")

    def fake_render(*, dot_text: str, output_png_path: str):  # type: ignore[no-untyped-def]
        Path(output_png_path).write_bytes(b"tmp")
        return True, "ok"

    monkeypatch.setattr(cm, "_render_png_with_dot", fake_render)
    monkeypatch.setattr(cm.os, "replace", lambda *_a, **_k: (_ for _ in ()).throw(OSError("replace failed")))  # type: ignore[arg-type]
    ok, detail = cm._render_png_with_dot_atomic(
        dot_text="digraph config_diagram {}\n", output_png_path=str(out_png)
    )
    assert ok is False
    assert "failed to replace png" in detail
    assert not tmp_png.exists()


def test_ensure_config_diagram_png_dark_failure_after_light_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png reports partial success when dark render fails.

    Inputs:
      - stale_light=True and stale_dark=True.
      - light render succeeds and dark render fails.

    Outputs:
      - None; asserts rendered-light partial success detail.
    """

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("plugins: []\n", encoding="utf-8")

    monkeypatch.setattr(cm, "_is_stale", lambda _in, _out: True)
    monkeypatch.setattr(
        cm,
        "generate_dot_text_from_config_path",
        lambda _p, **k: f"digraph {k.get('theme', 'light')} {{}}\n",
    )
    monkeypatch.setattr(cm, "_dot_text_matches_existing_file", lambda **_k: False)

    calls = {"n": 0}

    def fake_render(*, dot_text: str, output_png_path: str):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            Path(output_png_path).write_bytes(b"PNG")
            return True, "ok"
        return False, "dark failed"

    monkeypatch.setattr(cm, "_render_png_with_dot_atomic", fake_render)

    ok, detail, png_path = cm.ensure_config_diagram_png(config_path=str(cfg))
    assert ok is True
    assert "rendered light; dark failed: dark failed" == detail
    assert png_path == str(tmp_path / "diagram.png")


def test_ensure_config_diagram_png_dark_only_failure_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png returns error when only dark render is stale and fails.

    Inputs:
      - stale_light=False and stale_dark=True.
      - dark render fails.

    Outputs:
      - None; asserts error result with no png path.
    """

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("plugins: []\n", encoding="utf-8")

    def fake_stale(_input: str, output: str) -> bool:
        return str(output).endswith("diagram-dark.png")

    monkeypatch.setattr(cm, "_is_stale", fake_stale)
    monkeypatch.setattr(
        cm,
        "generate_dot_text_from_config_path",
        lambda _p, **k: f"digraph {k.get('theme', 'dark')} {{}}\n",
    )
    monkeypatch.setattr(cm, "_dot_text_matches_existing_file", lambda **_k: False)
    monkeypatch.setattr(
        cm, "_render_png_with_dot_atomic", lambda **_k: (False, "dark failed")
    )

    ok, detail, png_path = cm.ensure_config_diagram_png(config_path=str(cfg))
    assert ok is False
    assert detail == "dark failed"
    assert png_path is None


def test_build_plugin_source_index_from_schema_returns_empty_on_invalid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: _build_plugin_source_index_from_schema handles unreadable/invalid schema.

    Inputs:
      - Schema file containing invalid JSON.

    Outputs:
      - None; asserts empty index.
    """

    schema_path = tmp_path / "schema.json"
    schema_path.write_text("{invalid", encoding="utf-8")
    monkeypatch.setattr(cm, "get_default_schema_path", lambda: schema_path)
    assert cm._build_plugin_source_index_from_schema() == {}


def test_build_plugin_source_index_from_schema_defaults_aliases_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: _build_plugin_source_index_from_schema treats missing aliases as [].

    Inputs:
      - Resolve plugin entry without an aliases key.

    Outputs:
      - None; asserts class-derived default alias is indexed.
    """

    schema_path = tmp_path / "schema.json"
    schema_path.write_text(
        json.dumps(
            {
                "$defs": {
                    "PluginConfigs": {
                        "One": {"module": "foghorn.plugins.resolve.simple.SimplePlugin"}
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cm, "get_default_schema_path", lambda: schema_path)
    monkeypatch.setattr(cm, "_module_to_file", lambda _m: tmp_path / "x.py")
    monkeypatch.setattr(
        cm,
        "_build_plugin_source_from_module",
        lambda *, alias, module, class_name, file_path: cm.PluginSource(
            alias=alias,
            module=module,
            class_name=class_name,
            file_path=file_path,
        ),
    )
    idx = cm._build_plugin_source_index_from_schema()
    assert "simple" in idx


def test_extract_priorities_supports_dict_setup_and_post_hooks() -> None:
    """Brief: _extract_priorities reads dict-style setup/post hook priorities.

    Inputs:
      - hooks.setup and hooks.post_resolve mappings with priority keys.

    Outputs:
      - None; asserts setup/post values are parsed.
    """

    setup_p, pre_p, post_p = cm._extract_priorities(
        {
            "hooks": {
                "setup": {"priority": "8"},
                "pre_resolve": 7,
                "post_resolve": {"priority": "9"},
            }
        }
    )
    assert setup_p == 8
    assert pre_p == 7
    assert post_p == 9


def test_extract_upstream_router_route_lines_returns_empty_when_routes_not_list() -> (
    None
):
    """Brief: _extract_upstream_router_route_lines returns [] if routes is not a list.

    Inputs:
      - Config with routes as a non-list object.

    Outputs:
      - None; asserts empty list.
    """

    assert cm._extract_upstream_router_route_lines({"routes": {"domain": "x"}}) == []


def test_normalize_plugins_handles_truthy_non_list_and_post_default_priority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: normalize_plugins handles non-list plugins and post default priority.

    Inputs:
      - Truthy non-list plugins container.
      - PluginSource with has_post_resolve=True and no configured post priority.

    Outputs:
      - None; asserts [] for invalid plugins shape and post_priority=100 default.
    """

    assert cm.normalize_plugins({"plugins": {"bad": True}}) == []

    src = cm.PluginSource(
        alias="post_only",
        module="foghorn.plugins.resolve.post_only",
        class_name="PostOnly",
        file_path=Path("x.py"),
        has_post_resolve=True,
    )
    monkeypatch.setattr(cm, "_lookup_plugin_source", lambda _k: src)
    out = cm.normalize_plugins({"plugins": [{"type": "post_only"}]})
    assert out[0].post_priority == 100


def test_extract_listener_lines_handles_non_mapping_dns_section() -> None:
    """Brief: extract_listener_lines falls back to defaults when dns section is invalid.

    Inputs:
      - listen.dns as a non-dict value.

    Outputs:
      - None; asserts default udp listener.
    """

    cfg = {"server": {"listen": {"dns": "bad"}}}
    assert cm.extract_listener_lines(cfg) == ["udp: 127.0.0.1:5335"]


def test_extract_upstream_lines_handles_bad_backup_shapes_and_max_concurrent() -> None:
    """Brief: extract_upstream_lines handles invalid backup endpoint shapes and max_concurrent.

    Inputs:
      - max_concurrent with invalid value.
      - backup as non-dict and backup.endpoints as non-list.

    Outputs:
      - None; asserts fallback max_concurrent and stable output.
    """

    lines_a = cm.extract_upstream_lines(
        {
            "upstreams": {
                "max_concurrent": "bad",
                "endpoints": [{"host": "1.1.1.1"}],
                "backup": "bad",
            }
        },
        resolver_mode="forward",
    )
    assert lines_a[0] == "strategy=failover, max_concurrent=1"

    lines_b = cm.extract_upstream_lines(
        {
            "upstreams": {
                "endpoints": [{"host": "1.1.1.1"}],
                "backup": {"endpoints": "bad"},
            }
        },
        resolver_mode="forward",
    )
    assert "udp: 1.1.1.1" in lines_b


def test_generate_dot_text_from_config_path_handles_truthy_invalid_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: generate_dot_text_from_config_path handles truthy non-dict server config.

    Inputs:
      - load_config returning server as a non-dict truthy value.

    Outputs:
      - None; asserts function still returns render_dot output.
    """

    monkeypatch.setattr(cm, "load_config", lambda _p: {"server": [1]})
    monkeypatch.setattr(cm, "normalize_plugins", lambda _cfg: [])
    monkeypatch.setattr(cm, "extract_listener_lines", lambda _cfg: [])
    monkeypatch.setattr(
        cm, "extract_upstream_lines", lambda _cfg, resolver_mode=None: []
    )
    monkeypatch.setattr(cm, "render_dot", lambda *_a, **_k: "ok")
    assert cm.generate_dot_text_from_config_path("cfg.yaml") == "ok"


def test_generate_dot_text_from_config_path_handles_truthy_invalid_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: generate_dot_text_from_config_path handles truthy non-dict resolver config.

    Inputs:
      - load_config returning resolver as a non-dict truthy value.

    Outputs:
      - None; asserts resolver_mode falls back to forward.
    """

    captured: dict[str, object] = {}
    monkeypatch.setattr(cm, "load_config", lambda _p: {"server": {"resolver": [1]}})
    monkeypatch.setattr(cm, "normalize_plugins", lambda _cfg: [])
    monkeypatch.setattr(cm, "extract_listener_lines", lambda _cfg: [])
    monkeypatch.setattr(
        cm, "extract_upstream_lines", lambda _cfg, resolver_mode=None: []
    )

    def fake_render_dot(*_a, **kwargs):  # type: ignore[no-untyped-def]
        captured["resolver_mode"] = kwargs["resolver_mode"]
        return "ok"

    monkeypatch.setattr(cm, "render_dot", fake_render_dot)
    assert cm.generate_dot_text_from_config_path("cfg.yaml") == "ok"
    assert captured["resolver_mode"] == "forward"


def test_render_dot_covers_post_cluster_and_endpoint_dedupe_paths() -> None:
    """Brief: render_dot covers post-chain edges and endpoint dedupe/unknown transport paths.

    Inputs:
      - Routed pre plugins with empty/no-colon lines.
      - Two post plugins with deny/override/drop actions.
      - Duplicate unknown upstream protocol endpoints.

    Outputs:
      - None; asserts expected post and routed edges are rendered.
    """

    pre = cm.PluginInfo(
        idx=0,
        name="router",
        type_key="upstream_router",
        cls_path="foghorn.plugins.resolve.upstream_router.UpstreamRouter",
        pre_priority=1,
        routed_upstream_lines=["", "no_colon_line", "udp: 10.0.0.2:53"],
    )
    pre_empty = cm.PluginInfo(
        idx=1,
        name="empty",
        type_key="upstream_router",
        cls_path="foghorn.plugins.resolve.upstream_router.UpstreamRouter",
        pre_priority=2,
        routed_upstream_lines=[""],
    )
    post_a = cm.PluginInfo(
        idx=2,
        name="post-a",
        type_key="post_a",
        cls_path="m.PostA",
        post_priority=10,
        post_actions={"deny", "override", "drop"},
    )
    post_b = cm.PluginInfo(
        idx=3,
        name="post-b",
        type_key="post_b",
        cls_path="m.PostB",
        post_priority=20,
        post_actions=set(),
    )

    out = cm.render_dot(
        [pre, pre_empty, post_a, post_b],
        config_path="cfg.yaml",
        resolver_mode="forward",
        listener_lines=[],
        upstream_lines=["meta=1", "weird: endpoint", "weird: endpoint"],
        theme="not-a-theme",
        include_init=True,
    )

    assert "PostDrop [shape=ellipse" in out
    assert "post_2_post_a -> post_3_post_b" in out
    assert "override\\nwire reply" in out
    assert '-> PostDrop [label="drop"' in out
    assert "RoutedUpstream_1_empty" in out


def test_render_png_with_dot_atomic_handles_unlink_failure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: _render_png_with_dot_atomic tolerates unlink failures in cleanup paths.

    Inputs:
      - Failing render and failing replace cases where os.unlink raises.

    Outputs:
      - None; asserts function still returns expected failure tuples.
    """

    out_png = tmp_path / "diagram.png"

    monkeypatch.setattr(cm, "_render_png_with_dot", lambda **_k: (False, "bad render"))
    monkeypatch.setattr(cm.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(
        cm.os,
        "unlink",
        lambda _p: (_ for _ in ()).throw(OSError("unlink failed")),
    )
    ok1, detail1 = cm._render_png_with_dot_atomic(
        dot_text="digraph config_diagram {}\n", output_png_path=str(out_png)
    )
    assert ok1 is False
    assert detail1 == "bad render"

    monkeypatch.setattr(cm, "_render_png_with_dot", lambda **_k: (True, "ok"))
    monkeypatch.setattr(
        cm.os,
        "replace",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("replace failed")),
    )
    ok2, detail2 = cm._render_png_with_dot_atomic(
        dot_text="digraph config_diagram {}\n", output_png_path=str(out_png)
    )
    assert ok2 is False
    assert "failed to replace png" in detail2


def test_ensure_config_diagram_png_light_only_render_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png returns rendered result when only light output is stale.

    Inputs:
      - stale_light=True and stale_dark=False.

    Outputs:
      - None; asserts rendered-with-dot success.
    """

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("plugins: []\n", encoding="utf-8")

    def fake_stale(_input: str, output: str) -> bool:
        return str(output).endswith("diagram.png")

    monkeypatch.setattr(cm, "_is_stale", fake_stale)
    monkeypatch.setattr(
        cm, "generate_dot_text_from_config_path", lambda *_a, **_k: "digraph light {}\n"
    )
    monkeypatch.setattr(cm, "_dot_text_matches_existing_file", lambda **_k: False)
    monkeypatch.setattr(cm, "_render_png_with_dot_atomic", lambda **_k: (True, "ok"))

    ok, detail, png = cm.ensure_config_diagram_png(config_path=str(cfg))
    assert ok is True
    assert detail == "rendered with dot"
    assert png == str(tmp_path / "diagram.png")


def test_ensure_config_diagram_png_explicit_paths_and_fallback_exceptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png handles explicit outputs and fallback exception paths.

    Inputs:
      - Explicit output paths.
      - Path.with_name failure, impl_path isfile exception, and schema-path exception.

    Outputs:
      - None; asserts function still returns up-to-date success.
    """

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("plugins: []\n", encoding="utf-8")
    explicit_png = tmp_path / "x.png"
    explicit_dot = tmp_path / "x.dot"

    monkeypatch.setattr(
        cm.Path,
        "with_name",
        lambda self, _n: (_ for _ in ()).throw(ValueError("bad with_name")),
    )
    monkeypatch.setattr(
        cm,
        "get_default_schema_path",
        lambda: (_ for _ in ()).throw(RuntimeError("schema boom")),
    )

    impl_path = str(Path(cm.__file__).resolve())

    def fake_isfile(path: str) -> bool:
        if path == str(cfg):
            return True
        if path == impl_path:
            raise OSError("impl stat failed")
        return False

    monkeypatch.setattr(cm.os.path, "isfile", fake_isfile)
    monkeypatch.setattr(cm, "_is_stale", lambda _in, _out: False)

    ok, detail, out = cm.ensure_config_diagram_png(
        config_path=str(cfg),
        output_png_path=str(explicit_png),
        output_dot_path=str(explicit_dot),
    )
    assert ok is True
    assert detail == "up-to-date"
    assert out == str(explicit_png)


def test_ensure_config_diagram_png_dark_generation_and_dot_write_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png handles dark-generation and dark-dot-write failures.

    Inputs:
      - Scenario A: stale_dark=True with dark dot generation exception.
      - Scenario B: stale_dark=True with dark dot write exception.

    Outputs:
      - None; asserts expected return values in both scenarios.
    """

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("plugins: []\n", encoding="utf-8")

    # A: dark generation exception path.
    monkeypatch.setattr(
        cm, "_is_stale", lambda _in, out: str(out).endswith("diagram-dark.png")
    )

    def gen_raises(_p: str, **kwargs):  # type: ignore[no-untyped-def]
        if kwargs.get("theme") == "dark":
            raise RuntimeError("dark generation boom")
        return "digraph light {}\n"

    monkeypatch.setattr(cm, "generate_dot_text_from_config_path", gen_raises)
    ok_a, detail_a, out_a = cm.ensure_config_diagram_png(config_path=str(cfg))
    assert ok_a is False
    assert "failed to generate dot text: dark generation boom" == detail_a
    assert out_a is None

    # B: dark dot write failure should be best-effort (render still succeeds).
    dark_dot_dir = tmp_path / "dark-dot-dir"
    dark_dot_dir.mkdir()
    monkeypatch.setattr(
        cm, "_is_stale", lambda _in, out: str(out).endswith("diagram-dark.png")
    )
    monkeypatch.setattr(
        cm, "generate_dot_text_from_config_path", lambda *_a, **_k: "digraph dark {}\n"
    )
    monkeypatch.setattr(cm, "_dot_text_matches_existing_file", lambda **_k: False)
    monkeypatch.setattr(cm, "_render_png_with_dot_atomic", lambda **_k: (True, "ok"))

    ok_b, detail_b, out_b = cm.ensure_config_diagram_png(
        config_path=str(cfg),
        output_dot_dark_path=str(dark_dot_dir),
    )
    assert ok_b is True
    assert detail_b == "rendered with dot"
    assert out_b == str(tmp_path / "diagram.png")


def test_render_dot_post_chain_without_merge_still_wires_response() -> None:
    """Brief: render_dot handles post-chain flows without PostMerge edges.

    Inputs:
      - Post plugin that only emits drop (no deny/override merge actions).

    Outputs:
      - None; asserts PostDrop edge exists and direct response wiring remains.
    """

    post = cm.PluginInfo(
        idx=0,
        name="post-drop-only",
        type_key="post",
        cls_path="m.Post",
        post_priority=10,
        post_actions={"drop"},
    )
    out = cm.render_dot(
        [post],
        config_path="cfg.yaml",
        resolver_mode="forward",
        listener_lines=[],
        upstream_lines=["udp: 1.1.1.1:53"],
        include_init=True,
    )
    assert "PostMerge" not in out
    assert 'PostDrop [shape=ellipse, label="Drop (no reply)"]' in out
    assert "Upstreams -> post_0_post_drop_only" in out
    assert "post_0_post_drop_only -> Resp" in out


def test_render_png_with_dot_atomic_replace_failure_without_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: _render_png_with_dot_atomic handles replace failures when temp file vanishes.

    Inputs:
      - Successful dot render.
      - os.replace failure and os.path.exists reporting temp file absent.

    Outputs:
      - None; asserts function returns replace failure detail.
    """

    out_png = tmp_path / "diagram.png"
    monkeypatch.setattr(cm, "_render_png_with_dot", lambda **_k: (True, "ok"))
    monkeypatch.setattr(
        cm.os,
        "replace",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("replace failed")),
    )
    monkeypatch.setattr(cm.os.path, "exists", lambda _p: False)
    ok, detail = cm._render_png_with_dot_atomic(
        dot_text="digraph config_diagram {}\n", output_png_path=str(out_png)
    )
    assert ok is False
    assert "failed to replace png" in detail


def test_ensure_config_diagram_png_with_explicit_dark_paths_and_nonexistent_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png handles explicit dark paths and non-existent stale inputs.

    Inputs:
      - Explicit output_png_dark_path/output_dot_dark_path.
      - os.path.isfile false for impl/schema files.

    Outputs:
      - None; asserts up-to-date return without rendering.
    """

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("plugins: []\n", encoding="utf-8")
    out_png = tmp_path / "diagram.png"
    out_png_dark = tmp_path / "diagram-dark.png"
    out_dot = tmp_path / "diagram.dot"
    out_dot_dark = tmp_path / "diagram-dark.dot"

    schema_path = tmp_path / "schema-does-not-exist.json"
    monkeypatch.setattr(cm, "get_default_schema_path", lambda: schema_path)

    def fake_isfile(path: str) -> bool:
        return path == str(cfg)

    monkeypatch.setattr(cm.os.path, "isfile", fake_isfile)
    monkeypatch.setattr(cm, "_is_stale", lambda _in, _out: False)

    ok, detail, out = cm.ensure_config_diagram_png(
        config_path=str(cfg),
        output_png_path=str(out_png),
        output_png_dark_path=str(out_png_dark),
        output_dot_path=str(out_dot),
        output_dot_dark_path=str(out_dot_dark),
    )
    assert ok is True
    assert detail == "up-to-date"
    assert out == str(out_png)
