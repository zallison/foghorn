"""Brief: Unit tests for the `none` cache plugin (NullCache implementation).

Inputs:
  - None

Outputs:
  - None
"""

import pytest

from foghorn.cache_plugins.none import NullCache
from foghorn.cache_plugins.registry import load_cache_plugin


def test_null_cache_always_misses_and_noops() -> None:
    """Brief: NullCache never returns values and ignores set/purge.

    Inputs:
      - None

    Outputs:
      - None
    """

    c = NullCache()
    assert c.get(("example.com", 1)) is None
    assert c.get_with_meta(("example.com", 1)) == (None, None, None)

    # No-op methods should not raise.
    c.set(("example.com", 1), 60, b"wire")
    assert c.purge() == 0


@pytest.mark.parametrize("ident", ["none", "disabled", "no_cache"])
def test_registry_loads_null_cache_aliases(ident: str) -> None:
    """Brief: load_cache_plugin resolves NullCache via supported aliases.

    Inputs:
      - ident: Alias string.

    Outputs:
      - None; asserts returned instance type.
    """

    inst = load_cache_plugin(ident)
    assert isinstance(inst, NullCache)


def test_registry_loads_null_cache_from_mapping() -> None:
    """Brief: load_cache_plugin supports mapping form for NullCache.

    Inputs:
      - None

    Outputs:
      - None; asserts returned instance type.
    """

    inst = load_cache_plugin({"module": "none", "config": {"ignored": True}})
    assert isinstance(inst, NullCache)
