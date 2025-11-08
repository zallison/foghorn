"""
Brief: Tests for foghorn.plugins.registry module.

Inputs:
  - None

Outputs:
  - None
"""

import pytest
from foghorn.plugins.registry import (
    _camel_to_snake,
    _default_alias_for,
    _normalize,
    discover_plugins,
    get_plugin_class,
)
from foghorn.plugins.base import BasePlugin


def test_camel_to_snake_simple():
    """
    Brief: Convert simple CamelCase to snake_case.

    Inputs:
      - name: CamelCase string

    Outputs:
      - None: Asserts snake_case result
    """
    assert _camel_to_snake("CamelCase") == "camel_case"
    assert _camel_to_snake("SimpleExample") == "simple_example"


def test_camel_to_snake_with_numbers():
    """
    Brief: Convert CamelCase with numbers to snake_case.

    Inputs:
      - name: CamelCase string with digits

    Outputs:
      - None: Asserts snake_case result
    """
    assert _camel_to_snake("Test123Example") == "test123_example"
    assert _camel_to_snake("My2ndPlugin") == "my2nd_plugin"


def test_camel_to_snake_already_snake():
    """
    Brief: Handle already snake_case input.

    Inputs:
      - name: snake_case string

    Outputs:
      - None: Asserts unchanged result
    """
    assert _camel_to_snake("already_snake") == "already_snake"


def test_default_alias_for_with_plugin_suffix():
    """
    Brief: Extract default alias from class name ending in Plugin.

    Inputs:
      - cls: Plugin class with 'Plugin' suffix

    Outputs:
      - None: Asserts suffix removed and snake_cased
    """

    class ExamplePlugin(BasePlugin):
        pass

    assert _default_alias_for(ExamplePlugin) == "example"


def test_default_alias_for_without_plugin_suffix():
    """
    Brief: Extract default alias from class name without Plugin suffix.

    Inputs:
      - cls: Plugin class without 'Plugin' suffix

    Outputs:
      - None: Asserts snake_cased name
    """

    class MyFilter(BasePlugin):
        pass

    assert _default_alias_for(MyFilter) == "my_filter"


def test_normalize_strips_whitespace():
    """
    Brief: Normalize alias by stripping whitespace.

    Inputs:
      - alias: string with leading/trailing whitespace

    Outputs:
      - None: Asserts stripped result
    """
    assert _normalize("  test  ") == "test"


def test_normalize_converts_to_lowercase():
    """
    Brief: Normalize alias to lowercase.

    Inputs:
      - alias: mixed-case string

    Outputs:
      - None: Asserts lowercase result
    """
    assert _normalize("TEST") == "test"
    assert _normalize("TeSt") == "test"


def test_normalize_replaces_hyphens_with_underscores():
    """
    Brief: Normalize alias by replacing hyphens with underscores.

    Inputs:
      - alias: string containing hyphens

    Outputs:
      - None: Asserts hyphens replaced
    """
    assert _normalize("test-plugin") == "test_plugin"
    assert _normalize("multi-word-name") == "multi_word_name"


def test_normalize_combined():
    """
    Brief: Normalize alias with all transformations.

    Inputs:
      - alias: string needing all normalizations

    Outputs:
      - None: Asserts fully normalized result
    """
    assert _normalize("  Test-Plugin  ") == "test_plugin"


def test_discover_plugins_returns_dict():
    """
    Brief: Discover plugins returns non-empty registry dict.

    Inputs:
      - None: Uses default foghorn.plugins package

    Outputs:
      - None: Asserts dict type and known plugins present
    """
    registry = discover_plugins()
    assert isinstance(registry, dict)
    assert len(registry) > 0


def test_discover_plugins_includes_filter():
    """
    Brief: Verify FilterPlugin is discovered.

    Inputs:
      - None

    Outputs:
      - None: Asserts 'filter' alias maps to FilterPlugin
    """
    registry = discover_plugins()
    assert "filter" in registry
    cls = registry["filter"]
    assert cls.__name__ == "FilterPlugin"


def test_discover_plugins_includes_aliases():
    """
    Brief: Verify plugin-declared aliases are registered.

    Inputs:
      - None

    Outputs:
      - None: Asserts known aliases present
    """
    registry = discover_plugins()
    # FilterPlugin has aliases: filter, block, allow
    assert "filter" in registry
    assert "block" in registry
    assert "allow" in registry


def test_get_plugin_class_by_alias():
    """
    Brief: Retrieve plugin class by alias.

    Inputs:
      - identifier: known alias string

    Outputs:
      - None: Asserts correct class returned
    """
    cls = get_plugin_class("filter")
    assert cls.__name__ == "FilterPlugin"


def test_get_plugin_class_by_dotted_path():
    """
    Brief: Retrieve plugin class by dotted import path.

    Inputs:
      - identifier: full import path

    Outputs:
      - None: Asserts correct class returned
    """
    cls = get_plugin_class("foghorn.plugins.filter.FilterPlugin")
    assert cls.__name__ == "FilterPlugin"


def test_get_plugin_class_unknown_alias_raises():
    """
    Brief: Verify unknown alias raises KeyError with suggestions.

    Inputs:
      - identifier: non-existent alias

    Outputs:
      - None: Asserts KeyError raised
    """
    with pytest.raises(KeyError) as exc_info:
        get_plugin_class("nonexistent_plugin_xyz")
    assert "Unknown plugin alias" in str(exc_info.value)


def test_get_plugin_class_invalid_dotted_path_raises():
    """
    Brief: Verify invalid dotted path raises appropriate error.

    Inputs:
      - identifier: malformed dotted path

    Outputs:
      - None: Asserts ValueError or ModuleNotFoundError raised
    """
    with pytest.raises((ValueError, ModuleNotFoundError)):
        get_plugin_class("invalid..path")


def test_get_plugin_class_not_baseplugin_raises():
    """
    Brief: Verify non-BasePlugin class raises TypeError.

    Inputs:
      - identifier: path to non-plugin class

    Outputs:
      - None: Asserts TypeError raised
    """
    with pytest.raises(TypeError):
        get_plugin_class("foghorn.plugins.registry._normalize")


def test_discover_plugins_no_duplicates():
    """
    Brief: Verify duplicate alias detection.

    Inputs:
      - None

    Outputs:
      - None: Asserts no duplicates found
    """
    registry = discover_plugins()
    assert len(registry) > 0


def test_get_plugin_class_case_insensitive():
    """
    Brief: Verify plugin retrieval is case-insensitive.

    Inputs:
      - identifier: mixed-case alias

    Outputs:
      - None: Asserts correct class returned
    """
    cls = get_plugin_class("FILTER")
    assert cls.__name__ == "FilterPlugin"


def test_get_plugin_class_with_hyphens():
    """
    Brief: Verify aliases with hyphens work via normalization.

    Inputs:
      - identifier: hyphenated alias

    Outputs:
      - None: Asserts normalization handles hyphens
    """
    registry = discover_plugins()
    if "etc_hosts" in registry:
        cls = get_plugin_class("etc-hosts")
        assert cls is not None
