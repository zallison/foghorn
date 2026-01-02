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

import pytest

# Ensure 'src' is on sys.path so 'foghorn' package is importable in tests
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
SRC_DIR = os.path.join(ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


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
        from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCachePlugin
        from foghorn.plugins.resolve import base as plugin_base

        plugin_base.DNS_CACHE = InMemoryTTLCachePlugin()
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
