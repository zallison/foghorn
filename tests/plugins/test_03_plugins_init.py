import importlib
import types

import pytest

import foghorn.plugins.resolve as plugins


def test_all_contains_known_modules():
    """
    Inputs: None
    Outputs: Asserts that known plugin modules are present in foghorn.plugins.__all__

    Brief: Verifies that dynamic __all__ includes importable plugin modules.
    """
    assert "base" in plugins.__all__
    assert "access_control" in plugins.__all__


def test_getattr_imports_module():
    """
    Inputs: None
    Outputs: Asserts that foghorn.plugins.__getattr__(name) returns the imported module.

    Brief: Ensures lazy attribute access imports and returns the target submodule.

    Example:
        mod = getattr(plugins, "base")
        assert isinstance(mod, types.ModuleType)
    """
    mod = getattr(plugins, "base")
    assert isinstance(mod, types.ModuleType)
    assert mod is importlib.import_module("foghorn.plugins.resolve.base")


def test_getattr_missing_attribute_raises_attributeerror():
    """
    Inputs: None
    Outputs: Asserts that accessing a missing attribute raises AttributeError with expected text.

    Brief: Confirms missing modules produce AttributeError per the API contract.
    """
    name = "does_not_exist"
    try:
        getattr(plugins, name)
    except AttributeError as e:
        assert f"module '{plugins.__name__}' has no attribute '{name}'" in str(e)
    else:
        raise AssertionError("Expected AttributeError to be raised")


def test_getattr_re_raises_non_matching_module_not_found(monkeypatch):
    """
    Inputs: pytest monkeypatch fixture
    Outputs: Asserts that ModuleNotFoundError is re-raised when it does not refer to the requested module.

    Brief: If importlib.import_module raises ModuleNotFoundError for a nested dependency (e.name != fullname),
    __getattr__ should not convert it to AttributeError.

    Example:
        monkeypatch importlib.import_module to raise ModuleNotFoundError with e.name != fullname;
        getattr(plugins, "base") should propagate ModuleNotFoundError.
    """
    target_name = "base"
    fullname = f"{plugins.__name__}.{target_name}"

    # Ensure attribute and module are not already loaded so __getattr__ path is exercised
    if hasattr(plugins, target_name):
        try:
            delattr(plugins, target_name)
        except Exception:  # pragma: no cover
            pass  # pragma: no cover
    import sys

    sys.modules.pop(fullname, None)

    original_import_module = importlib.import_module

    def fake_import(name):
        if name == fullname:
            err = ModuleNotFoundError("No module named 'some.inner.dependency'")
            err.name = "some.inner.dependency"
            raise err
        return original_import_module(name)

    monkeypatch.setattr(importlib, "import_module", fake_import)

    with pytest.raises(ModuleNotFoundError):
        getattr(plugins, target_name)
