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

from typing import Dict, List, Type

import pytest
from contract_tests import (
    ResolvePluginContract,
    StatsStoreContract,
    run_contract_checks,
)

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


@pytest.mark.parametrize("plugin_cls", _PLUGIN_CLASSES, ids=lambda cls: cls.__name__)
def test_registered_plugins_structural_contract(
    plugin_cls: Type[BasePlugin],
) -> None:
    """Every registered plugin must satisfy the structural contract.

    Hook-based checks are intentionally excluded here: they assume setup()
    has already run, which is covered per-plugin in each plugin's own tests.
    """
    plugin = plugin_cls()
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
