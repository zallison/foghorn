"""
Brief: Regression tests for bounded plugin-order cache behavior in server helpers.

Inputs:
  - None.

Outputs:
  - None.
"""

import foghorn.servers.server as srv


class _Plugin:
    def __init__(self, *, pre_priority: int, post_priority: int):
        self.pre_priority = int(pre_priority)
        self.post_priority = int(post_priority)


def _clear_plugin_order_cache() -> None:
    """Brief: Clear plugin-order cache between tests.

    Inputs:
      - None.

    Outputs:
      - None.
    """

    with srv._PLUGIN_ORDER_LOCK:
        srv._PLUGIN_ORDER_CACHE.clear()


def test_plugin_order_cache_prunes_old_snapshot_generations():
    """Brief: Keep only a bounded number of snapshot-generation ordering entries.

    Inputs:
      - None.

    Outputs:
      - None; asserts old generation entries are evicted.
    """

    _clear_plugin_order_cache()
    plugins = [
        _Plugin(pre_priority=20, post_priority=5),
        _Plugin(pre_priority=10, post_priority=15),
    ]
    max_keep = int(srv._PLUGIN_ORDER_CACHE_MAX_SNAP_GENERATIONS)
    total_generations = max_keep + 24

    for generation in range(total_generations):
        pre_plugins, post_plugins = srv._get_ordered_plugins(
            plugins=plugins,
            token_kind="snap",
            token=generation,
        )
        assert pre_plugins[0] is plugins[1]
        assert post_plugins[0] is plugins[0]

    with srv._PLUGIN_ORDER_LOCK:
        snap_tokens = sorted(
            token for (kind, token) in srv._PLUGIN_ORDER_CACHE.keys() if kind == "snap"
        )

    assert len(snap_tokens) == max_keep
    assert snap_tokens[0] == total_generations - max_keep
    assert snap_tokens[-1] == total_generations - 1

    _clear_plugin_order_cache()


def test_plugin_order_cache_prunes_old_state_tokens():
    """Brief: Keep only a bounded number of state-token ordering entries.

    Inputs:
      - None.

    Outputs:
      - None; asserts older state tokens are evicted.
    """

    _clear_plugin_order_cache()
    plugins = [_Plugin(pre_priority=1, post_priority=2)]
    max_keep = int(srv._PLUGIN_ORDER_CACHE_MAX_STATE_KEYS)
    total_tokens = max_keep + 11

    for token in range(total_tokens):
        srv._get_ordered_plugins(
            plugins=plugins,
            token_kind="state",
            token=token,
        )

    with srv._PLUGIN_ORDER_LOCK:
        state_tokens = sorted(
            token for (kind, token) in srv._PLUGIN_ORDER_CACHE.keys() if kind == "state"
        )

    assert len(state_tokens) == max_keep
    assert state_tokens[0] == total_tokens - max_keep
    assert state_tokens[-1] == total_tokens - 1

    _clear_plugin_order_cache()
