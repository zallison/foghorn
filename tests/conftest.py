"""
Brief: Global pytest configuration enforcing per-test 10s timeout.

Inputs:
  - None

Outputs:
  - None
"""

import os
import signal
import sys
import importlib
import types

import pytest

# Ensure 'src' is on sys.path so 'foghorn' package is importable in tests
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
SRC_DIR = os.path.join(ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Compatibility shims for example plugins that were moved under
# src/foghorn/plugins/resolve/examples without their own base.py or legacy
# module names.
try:
    # Provide foghorn.plugins.resolve.examples.base so relative imports like
    # `from .base import BasePlugin` continue to work.
    from foghorn.plugins.resolve import base as _resolve_base

    _examples_base = types.ModuleType("foghorn.plugins.resolve.examples.base")
    for _name in ("BasePlugin", "PluginContext", "PluginDecision", "plugin_aliases"):
        setattr(_examples_base, _name, getattr(_resolve_base, _name))
    sys.modules["foghorn.plugins.resolve.examples.base"] = _examples_base

    # Alias old module paths to their new locations under the examples package.
    _examples_mod = importlib.import_module(
        "foghorn.plugins.resolve.examples.examples"
    )
    _dns_prefetch_mod = importlib.import_module(
        "foghorn.plugins.resolve.examples.dns_prefetch"
    )
    _greylist_mod = importlib.import_module(
        "foghorn.plugins.resolve.examples.greylist"
    )
    _ndf_mod = importlib.import_module(
        "foghorn.plugins.resolve.examples.new_domain_filter"
    )

    sys.modules.setdefault(
        "foghorn.plugins.resolve.examples",
        importlib.import_module("foghorn.plugins.resolve.examples"),
    )
    sys.modules.setdefault("foghorn.plugins.resolve.examples.examples", _examples_mod)
    sys.modules.setdefault("foghorn.plugins.resolve.dns_prefetch", _dns_prefetch_mod)
    sys.modules.setdefault("foghorn.plugins.resolve.greylist", _greylist_mod)
    sys.modules.setdefault("foghorn.plugins.resolve.new_domain_filter", _ndf_mod)

    # Expose Examples symbols on the examples package for legacy imports like
    # `from foghorn.plugins.resolve.examples import Examples`.
    _examples_pkg = sys.modules["foghorn.plugins.resolve.examples"]
    for _name in (
        "Examples",
        "ExamplesConfig",
        "_count_subdomains",
        "_length_without_dots",
    ):
        if hasattr(_examples_mod, _name):
            setattr(_examples_pkg, _name, getattr(_examples_mod, _name))
except Exception:  # pragma: no cover
    # Best-effort; if this fails, test failures will surface the issue.
    pass


def _alarm_handler(signum, frame):
    """
    Brief: Signal handler that raises TimeoutError when alarm triggers.

    Inputs:
      - signum: signal number (int)
      - frame: current frame (ignored)

    Outputs:
      - None: Raises TimeoutError to fail the test
    """
    raise TimeoutError("Test exceeded 10 seconds")


# Install handler if supported on this platform
if hasattr(signal, "SIGALRM"):
    signal.signal(signal.SIGALRM, _alarm_handler)


@pytest.fixture(autouse=True)
def clear_dns_cache_between_tests():
    """
    Brief: Clear DNSUDPHandler cache between tests to avoid cross-test interference.

    Inputs:
      - None

    Outputs:
      - None
    """
    try:
        from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache
        from foghorn.plugins.resolve import base as plugin_base

        plugin_base.DNS_CACHE = InMemoryTTLCache()
    except Exception:  # pragma: no cover
        pass  # pragma: no cover
    yield


@pytest.fixture(autouse=True)
def enforce_test_timeout():
    """
    Brief: Enforce a hard 10-second timeout for each test.

    Inputs:
      - None

    Outputs:
      - None: Cancels alarm after test
    """
    if hasattr(signal, "SIGALRM"):
        signal.alarm(10)
        try:
            yield
        finally:
            signal.alarm(0)
    else:
        # Fallback: no-op on platforms without SIGALRM
        yield
