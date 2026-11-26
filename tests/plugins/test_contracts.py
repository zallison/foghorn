"""Executable contract tests for BasePlugin and BaseStatsStore implementations.

Runs the shared contract checks from ``contract_tests.py`` against:

  - a minimal no-op ``BasePlugin`` subclass (full contract, including the
    pre/post-resolve hook return types),
  - every plugin class discovered by the registry (structural checks only;
    hook-based checks require per-plugin setup and belong in each plugin's
    own test module),
  - ``SqliteStatsStore``, the canonical query-log backend (full contract).
"""

from __future__ import annotations

from typing import Any, Dict, List, Type

import pytest
from contract_tests import (
    ResolvePluginContract,
    StatsStoreContract,
    run_contract_checks,
)
from pydantic import BaseModel

from foghorn.plugins.querylog.sqlite import SqliteStatsStore
from foghorn.plugins.resolve.base import BasePlugin
from foghorn.plugins.resolve.registry import discover_plugins


class _NoOpPlugin(BasePlugin):
    """Minimal concrete plugin used to exercise the full resolve contract."""


def _discovered_plugin_classes() -> List[Type[BasePlugin]]:
    """Return de-duplicated registered plugin classes in stable order."""
    registry: Dict[str, Type[BasePlugin]] = discover_plugins()
    seen: Dict[str, Type[BasePlugin]] = {}
    for cls in registry.values():
        # De-duplicate by class (one class may be registered under several
        # aliases) while keeping a stable, sorted order for parametrize ids.
        seen.setdefault(cls.__name__, cls)
    return [seen[name] for name in sorted(seen)]


_PLUGIN_CLASSES = _discovered_plugin_classes()


def test_registry_discovery_nonempty() -> None:
    """Ensure at least one plugin class is available for the contracts."""
    assert _PLUGIN_CLASSES, "plugin discovery returned no classes"


def test_noop_plugin_contract() -> None:
    """The base-class defaults must satisfy the full resolve contract."""
    plugin = _NoOpPlugin(name="contract-noop")
    run_contract_checks(ResolvePluginContract(plugin))


def _minimal_plugin_kwargs(plugin_cls: Type[BasePlugin]) -> Dict[str, Any]:
    """Brief: Build bare kwargs so plugins with required config can construct.

    Inputs:
      - plugin_cls: Registered BasePlugin subclass under test.

    Outputs:
      - Dict of keyword args covering required Pydantic config fields with
        simple placeholder values (empty string/list/dict, 0, False, or a
        one-label domain-like string for ``str`` fields). Returns {} when the
        plugin has no config model or no required fields.
    """

    get_model = getattr(plugin_cls, "get_config_model", None)
    if not callable(get_model):
        return {}
    try:
        model = get_model()
    except Exception:
        return {}
    if not isinstance(model, type) or not issubclass(model, BaseModel):
        return {}

    kwargs: Dict[str, Any] = {}
    for name, field in model.model_fields.items():
        if not field.is_required():
            continue
        ann = field.annotation
        if ann is str:
            # Prefer a one-label placeholder so domain-like validators pass.
            kwargs[name] = "contract.test"
        elif ann is int or ann is float:
            kwargs[name] = 0
        elif ann is bool:
            kwargs[name] = False
        elif ann is list or getattr(ann, "__origin__", None) is list:
            kwargs[name] = []
        elif ann is dict or getattr(ann, "__origin__", None) is dict:
            kwargs[name] = {}
        else:
            kwargs[name] = "contract.test"
    return kwargs


@pytest.mark.parametrize("plugin_cls", _PLUGIN_CLASSES, ids=lambda cls: cls.__name__)
def test_registered_plugins_structural_contract(
    plugin_cls: Type[BasePlugin],
) -> None:
    """Every registered plugin must satisfy the structural contract.

    Hook-based checks are intentionally excluded here: they assume setup()
    has already run, which is covered per-plugin in each plugin's own tests.
    """
    plugin = plugin_cls(**_minimal_plugin_kwargs(plugin_cls))
    contract = ResolvePluginContract(plugin)
    contract.test_basic_interface()
    contract.test_priority_bounds()
    contract.test_targets_returns_bool()
    contract.test_name_is_set()


@pytest.fixture()
def sqlite_store() -> SqliteStatsStore:
    """Provide a throwaway in-memory SQLite stats store for the full contract."""
    store = SqliteStatsStore(":memory:")
    yield store
    store.close()


def test_sqlite_store_contract(sqlite_store: SqliteStatsStore) -> None:
    """The canonical backend must satisfy the full stats-store contract."""
    run_contract_checks(StatsStoreContract(sqlite_store))
