"""Brief: Unit tests for foghorn.utils.config_diagram helpers.

Inputs:
  - tmp_path: pytest tmp_path fixture.
  - monkeypatch: pytest monkeypatch fixture.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

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
